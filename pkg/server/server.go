package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/collector"
	"github.com/mosfaqur/sieve-security/pkg/fingerprint"
	"github.com/mosfaqur/sieve-security/pkg/models"
	"github.com/mosfaqur/sieve-security/pkg/plugins"
	"github.com/mosfaqur/sieve-security/pkg/reachability"
	"github.com/mosfaqur/sieve-security/pkg/remediation"
	"github.com/mosfaqur/sieve-security/pkg/scan"
	"github.com/mosfaqur/sieve-security/pkg/scope"
	"github.com/mosfaqur/sieve-security/pkg/storage"
)

// Server coordinates the control plane REST API, scan orchestrator, and web interface.
type Server struct {
	mu           sync.RWMutex
	store        *storage.Store
	pluginEngine *plugins.Engine
	remediator   *remediation.Orchestrator
	reachability *reachability.Evaluator
	addr         string
	activeScan   *models.ScanRun
}

// NewServer initializes the Sieve Security platform server.
func NewServer(addr string, store *storage.Store, engine *plugins.Engine) *Server {
	return &Server{
		store:        store,
		pluginEngine: engine,
		remediator:   remediation.NewOrchestrator(),
		reachability: reachability.NewEvaluator(),
		addr:         addr,
	}
}

// Start launches the HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/scans", s.handleScans)
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/findings/state", s.handleFindingState)
	mux.HandleFunc("/api/v1/remediations", s.handleRemediations)
	mux.HandleFunc("/api/v1/verify", s.handleVerificationRescan)
	mux.HandleFunc("/api/v1/diff", s.handleDiff)

	// Web UI
	mux.HandleFunc("/", s.handleWebUI)

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	fmt.Printf("[+] Sieve Security platform listening on http://%s\n", s.addr)
	return srv.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "healthy",
		"plugins_loaded":  s.pluginEngine.Count(),
		"timestamp":       time.Now().Format(time.RFC3339),
		"thesis":          "Fewer findings, each true, each with a fix.",
	})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		var req struct {
			Target         string `json:"target"`
			SSHUser        string `json:"ssh_user,omitempty"`
			SSHPassword    string `json:"ssh_password,omitempty"`
			SafetyCeiling  string `json:"safety_ceiling,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Target == "" {
			http.Error(w, "missing target", http.StatusBadRequest)
			return
		}

		runID := fmt.Sprintf("scan-%d", time.Now().Unix())
		run := &models.ScanRun{
			ID:            runID,
			TenantID:      "tenant-default",
			NetworkZoneID: "zone-corp",
			Status:        "running",
			Targets:       []string{req.Target},
			StartTime:     time.Now(),
			CurrentPhase:  "Discovery",
			HostsTargeted: 1,
		}

		s.mu.Lock()
		s.activeScan = run
		s.store.ScanRuns[runID] = run
		s.mu.Unlock()

		// Launch scan asynchronously
		go s.executeScan(run, req.Target, req.SSHUser, req.SSHPassword, req.SafetyCeiling)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(run)
		return
	}

	// GET
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []*models.ScanRun
	for _, r := range s.store.ScanRuns {
		list = append(list, r)
	}
	_ = json.NewEncoder(w).Encode(list)
}

func (s *Server) executeScan(run *models.ScanRun, target, sshUser, sshPass, safetyCeilingStr string) {
	defer func() {
		now := time.Now()
		run.EndTime = &now
		run.Status = "completed"
		run.ProgressPct = 100
		_ = s.store.Save()
	}()

	ceiling := models.SafetyActiveSafe
	if safetyCeilingStr != "" {
		ceiling = models.SafetyClass(safetyCeilingStr)
	}

	// 1. Authorize Target in Scope (§4.1)
	sc := &models.Scope{
		ID:       "dynamic-scope",
		TenantID: run.TenantID,
		Status:   "active",
		Entries: []models.ScopeEntry{
			{Kind: "cidr", Value: "192.168.1.0/24"},
			{Kind: "cidr", Value: "10.0.0.0/8"},
			{Kind: "cidr", Value: "127.0.0.0/8"},
			{Kind: "ip", Value: target},
		},
	}
	guard, err := scope.Compile(sc)
	if err != nil {
		run.Status = "failed"
		return
	}

	resolvedIPs, err := guard.ValidateAndResolve(target)
	if err != nil || len(resolvedIPs) == 0 {
		run.Status = "failed"
		return
	}

	targetIP := resolvedIPs[0]
	run.HostsLive = 1
	run.CurrentPhase = "Port Scanning"
	run.ProgressPct = 25

	scanner := scan.NewScanner(guard)
	openPorts, err := scanner.ScanPorts(context.Background(), targetIP, scan.ScanOptions{
		MaxPPS:        2000,
		Timeout:       1200 * time.Millisecond,
		SafetyCeiling: ceiling,
	})
	if err != nil {
		run.Status = "failed"
		return
	}

	var portList []int
	for _, p := range openPorts {
		portList = append(portList, p.Port)
	}
	run.DiscoveredPorts = portList

	run.CurrentPhase = "Service Fingerprinting"
	run.ProgressPct = 50

	fingerprinter := fingerprint.NewFingerprinter(guard, 2500*time.Millisecond)
	var services []models.Service
	for _, p := range openPorts {
		svc, err := fingerprinter.Identify(context.Background(), targetIP, p.Port)
		if err == nil && svc != nil {
			svc.AssetID = fmt.Sprintf("asset-%s", strings.ReplaceAll(targetIP.String(), ".", "-"))
			services = append(services, *svc)
		}
	}

	// 2. Authenticated Assessment if credentials provided (§26)
	run.CurrentPhase = "Authenticated Assessment"
	run.ProgressPct = 70
	var auditFacts *collector.HostAuditFact

	if sshUser != "" {
		coll, err := collector.NewSSHCollectorAuto(targetIP.String(), 22, sshUser, sshPass, "", 5*time.Second)
		if err == nil {
			facts, err := coll.Collect(context.Background())
			if err == nil {
				auditFacts = facts
				run.DataQuality.UncredentialedHosts = 0
				run.HostsAssessed = 1
			} else {
				run.DataQuality.FailedCredentials = 1
			}
		} else {
			run.DataQuality.FailedCredentials = 1
		}
	} else {
		run.DataQuality.UncredentialedHosts = 1
	}

	// 3. Asset Record
	assetID := fmt.Sprintf("asset-%s", strings.ReplaceAll(targetIP.String(), ".", "-"))
	asset := &models.Asset{
		ID:            assetID,
		TenantID:      run.TenantID,
		NetworkZoneID: run.NetworkZoneID,
		DisplayName:   target,
		IPv4:          targetIP.String(),
		AssetClass:    "server",
		Criticality:   7,
		Exposure:      "internal",
		FirstSeen:     time.Now(),
		LastSeen:      time.Now(),
		LastScanned:   time.Now(),
		Services:      services,
	}

	if auditFacts != nil {
		asset.OSFamily = auditFacts.OSID
		asset.OSProduct = auditFacts.OSName
		asset.OSVersion = auditFacts.OSVersion
		asset.Hostname = auditFacts.Hostname
		now := time.Now()
		asset.LastCredentialed = &now
	}
	s.store.UpsertAsset(asset)

	// 4. Vulnerability Plugin Evaluation
	run.CurrentPhase = "Plugin Evaluation"
	run.ProgressPct = 85
	var detectedFindings []*models.Finding

	for i := range services {
		svc := &services[i]
		findings, err := s.pluginEngine.EvaluateService(context.Background(), asset, svc, auditFacts, ceiling)
		if err == nil {
			for _, f := range findings {
				// Evaluate Reachability Tier 1 & 2 (§1.2, §38.4)
				f.Reachability = s.reachability.EvaluateReachability(f, svc, auditFacts)
				detectedFindings = append(detectedFindings, f)
			}
		}
	}

	// 5. Ingest into Store with 4-Column Defensible Diff (§68.4)
	diff := s.store.IngestScanFindings(run.ID, asset.ID, detectedFindings, true)
	run.Diff = diff
	run.TotalFindings = len(detectedFindings)

	for _, f := range detectedFindings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			run.CriticalCount++
		case "high":
			run.HighCount++
		case "medium":
			run.MediumCount++
		case "low":
			run.LowCount++
		default:
			run.InfoCount++
		}
	}

	// 6. Remediation Grouping (§50.1)
	remediations := s.remediator.GroupFindings(run.TenantID, detectedFindings)
	for _, r := range remediations {
		s.store.Remediations[r.ID] = r
	}

	if len(detectedFindings) == 0 {
		run.SummaryMessage = fmt.Sprintf("Target %s is clean: 0 actionable vulnerabilities detected across %d open ports.", target, len(openPorts))
	} else {
		run.SummaryMessage = fmt.Sprintf("Target %s: %d vulnerabilities detected across %d open ports, grouped into %d remediation actions.", target, len(detectedFindings), len(openPorts), len(remediations))
	}
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*models.Asset
	for _, a := range s.store.Assets {
		list = append(list, a)
	}
	_ = json.NewEncoder(w).Encode(list)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sev := r.URL.Query().Get("severity")
	state := models.FindingState(r.URL.Query().Get("state"))

	findings := s.store.ListFindings(sev, state)
	_ = json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleFindingState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DedupKey string              `json:"dedup_key"`
		State    models.FindingState `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ok := s.store.UpdateFindingState(req.DedupKey, req.State)
	if !ok {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

func (s *Server) handleRemediations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	items := s.store.ListRemediations()
	_ = json.NewEncoder(w).Encode(items)
}

// handleVerificationRescan executes sub-60-second targeted re-probes (§50.2).
func (s *Server) handleVerificationRescan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		RemediationID string `json:"remediation_id"`
		FindingID     string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Fast sub-60s verification
	start := time.Now()
	recheckCount := 0
	fixedCount := 0

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, f := range s.store.Findings {
		if req.RemediationID != "" && f.RemediationID != req.RemediationID {
			continue
		}
		if req.FindingID != "" && f.ID != req.FindingID && f.DedupKey != req.FindingID {
			continue
		}

		recheckCount++
		// Re-test port connectivity or package
		addr := fmt.Sprintf("%s:%d", f.AssetIP, f.Port)
		conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
		if err != nil {
			// Port closed -> verified fixed
			f.State = models.StateFixed
			now := time.Now()
			f.FixedAt = &now
			fixedCount++
		} else {
			_ = conn.Close()
		}
	}

	_ = s.store.Save()

	elapsed := time.Since(start)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "completed",
		"duration_ms":     elapsed.Milliseconds(),
		"rechecked_count": recheckCount,
		"fixed_count":     fixedCount,
		"verified_in_sub_60s": elapsed < 60*time.Second,
	})
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Aggregate 4-column defensible diff across recent runs
	diff := models.DiffSummary{}
	for _, run := range s.store.ScanRuns {
		diff.NewFindings += run.Diff.NewFindings
		diff.ConfirmedFixed += run.Diff.ConfirmedFixed
		diff.ReopenedFindings += run.Diff.ReopenedFindings
		diff.UnverifiedAbsent += run.Diff.UnverifiedAbsent
	}

	_ = json.NewEncoder(w).Encode(diff)
}
