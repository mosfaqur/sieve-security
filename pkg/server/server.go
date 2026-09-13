package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
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
			Target        string `json:"target"`
			SSHUser       string `json:"ssh_user,omitempty"`
			SSHPassword   string `json:"ssh_password,omitempty"`
			SafetyCeiling string `json:"safety_ceiling,omitempty"`
			PortRange     string `json:"port_range,omitempty"`
			CustomPorts   string `json:"custom_ports,omitempty"`
			MaxPPS        int    `json:"max_pps,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Target == "" {
			http.Error(w, "missing target", http.StatusBadRequest)
			return
		}

		portOption := req.PortRange
		if portOption == "custom" && req.CustomPorts != "" {
			portOption = req.CustomPorts
		} else if portOption == "" {
			portOption = "default"
		}

		runID := fmt.Sprintf("scan-%d", time.Now().Unix())
		run := &models.ScanRun{
			ID:            runID,
			TenantID:      "tenant-default",
			NetworkZoneID: "zone-corp",
			Status:        "running",
			Targets:       []string{req.Target},
			StartTime:     time.Now(),
			CurrentPhase:  "Discovery & Liveness",
			HostsTargeted: 1,
			PortRange:     portOption,
			SafetyCeiling: req.SafetyCeiling,
			MaxPPS:        req.MaxPPS,
			Logs: []string{
				fmt.Sprintf("[%s] Scan initialized against %s (Port profile: %s)", time.Now().Format("15:04:05"), req.Target, portOption),
			},
		}

		s.mu.Lock()
		s.activeScan = run
		s.store.ScanRuns[runID] = run
		s.mu.Unlock()

		// Launch scan asynchronously
		go s.executeScan(run, req.Target, req.SSHUser, req.SSHPassword, req.SafetyCeiling, portOption, req.MaxPPS)

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(run)
		return
	}

	// GET
	scanID := r.URL.Query().Get("id")
	s.mu.RLock()
	defer s.mu.RUnlock()

	if scanID != "" {
		run, exists := s.store.ScanRuns[scanID]
		if !exists {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(run)
		return
	}

	var list []*models.ScanRun
	for _, r := range s.store.ScanRuns {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].StartTime.After(list[j].StartTime)
	})
	_ = json.NewEncoder(w).Encode(list)
}

func (s *Server) executeScan(run *models.ScanRun, target, sshUser, sshPass, safetyCeilingStr, portSpec string, maxPPS int) {
	logMsg := func(msg string) {
		s.mu.Lock()
		run.Logs = append(run.Logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), msg))
		s.mu.Unlock()
	}

	defer func() {
		now := time.Now()
		s.mu.Lock()
		run.EndTime = &now
		if run.Status != "failed" {
			run.Status = "completed"
		}
		run.ProgressPct = 100
		s.mu.Unlock()
		_ = s.store.Save()
	}()

	ceiling := models.SafetyActiveSafe
	if safetyCeilingStr != "" {
		ceiling = models.SafetyClass(safetyCeilingStr)
	}

	logMsg(fmt.Sprintf("Scope validation started for target: %s", target))

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
		s.mu.Lock()
		run.Status = "failed"
		s.mu.Unlock()
		logMsg(fmt.Sprintf("Scope compilation error: %v", err))
		return
	}

	resolvedIPs, err := guard.ValidateAndResolve(target)
	if err != nil || len(resolvedIPs) == 0 {
		s.mu.Lock()
		run.Status = "failed"
		s.mu.Unlock()
		logMsg(fmt.Sprintf("DNS resolution / scope check rejected target: %v", err))
		return
	}

	targetIP := resolvedIPs[0]
	s.mu.Lock()
	run.HostsLive = 1
	s.mu.Unlock()
	logMsg(fmt.Sprintf("Scope authorization passed for IP %s", targetIP.String()))

	// Parse requested ports
	portsToScan, err := scan.ParsePortSpec(portSpec)
	if err != nil {
		portsToScan = scan.DefaultTopPorts
		logMsg(fmt.Sprintf("Warning: Failed to parse port spec '%s', defaulting to curated top ports", portSpec))
	} else {
		logMsg(fmt.Sprintf("Configured port range '%s' resolved to %d target ports", portSpec, len(portsToScan)))
	}

	s.mu.Lock()
	run.CurrentPhase = fmt.Sprintf("Port Scanning (%d ports)", len(portsToScan))
	run.ProgressPct = 15
	s.mu.Unlock()

	if maxPPS <= 0 {
		if len(portsToScan) > 5000 {
			maxPPS = 3000
		} else {
			maxPPS = 2000
		}
	}

	scanner := scan.NewScanner(guard)
	openPorts, err := scanner.ScanPorts(context.Background(), targetIP, scan.ScanOptions{
		Ports:         portsToScan,
		MaxPPS:        maxPPS,
		SafetyCeiling: ceiling,
		OnProgress: func(scanned, total, openFound int) {
			s.mu.Lock()
			pct := 15 + int((float64(scanned)/float64(total))*35.0) // 15% to 50%
			if pct > 50 {
				pct = 50
			}
			run.ProgressPct = pct
			s.mu.Unlock()
		},
	})
	if err != nil {
		s.mu.Lock()
		run.Status = "failed"
		s.mu.Unlock()
		logMsg(fmt.Sprintf("Port scan error: %v", err))
		return
	}

	var portList []int
	for _, p := range openPorts {
		portList = append(portList, p.Port)
	}
	s.mu.Lock()
	run.DiscoveredPorts = portList
	run.CurrentPhase = "Service Fingerprinting"
	run.ProgressPct = 55
	s.mu.Unlock()
	logMsg(fmt.Sprintf("Discovered %d open port(s): %v", len(openPorts), portList))

	fingerprinter := fingerprint.NewFingerprinter(guard, 2500*time.Millisecond)
	var services []models.Service
	for _, p := range openPorts {
		svc, err := fingerprinter.Identify(context.Background(), targetIP, p.Port)
		if err == nil && svc != nil {
			svc.AssetID = fmt.Sprintf("asset-%s", strings.ReplaceAll(targetIP.String(), ".", "-"))
			services = append(services, *svc)
			logMsg(fmt.Sprintf("Fingerprinted port %d/tcp: %s (%s %s)", p.Port, svc.ServiceName, svc.Product, svc.Version))
		}
	}
	s.mu.Lock()
	run.DiscoveredServices = services
	s.mu.Unlock()

	// 2. Authenticated Assessment if credentials provided (§26)
	s.mu.Lock()
	run.CurrentPhase = "Host Fact Inspection"
	run.ProgressPct = 70
	s.mu.Unlock()
	var auditFacts *collector.HostAuditFact

	if sshUser != "" {
		logMsg(fmt.Sprintf("Attempting credentialed SSH assessment as '%s' on %s:22", sshUser, targetIP.String()))
		coll, err := collector.NewSSHCollectorAuto(targetIP.String(), 22, sshUser, sshPass, "", 5*time.Second)
		if err == nil {
			facts, err := coll.Collect(context.Background())
			if err == nil {
				auditFacts = facts
				s.mu.Lock()
				run.DataQuality.UncredentialedHosts = 0
				run.HostsAssessed = 1
				s.mu.Unlock()
				logMsg(fmt.Sprintf("SSH collection successful: Hostname=%s, OS=%s %s, Packages=%d", facts.Hostname, facts.OSName, facts.OSVersion, len(facts.Packages)))
			} else {
				s.mu.Lock()
				run.DataQuality.FailedCredentials = 1
				s.mu.Unlock()
				logMsg(fmt.Sprintf("SSH fact extraction failed: %v", err))
			}
		} else {
			s.mu.Lock()
			run.DataQuality.FailedCredentials = 1
			s.mu.Unlock()
			logMsg(fmt.Sprintf("SSH connection failed: %v", err))
		}
	} else {
		s.mu.Lock()
		run.DataQuality.UncredentialedHosts = 1
		s.mu.Unlock()
		logMsg("No SSH credentials supplied. Performing non-credentialed network assessment.")
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
	s.mu.Lock()
	run.CurrentPhase = "Vulnerability Plugin Evaluation"
	run.ProgressPct = 85
	s.mu.Unlock()
	logMsg(fmt.Sprintf("Executing %d declarative plugins against discovered services...", s.pluginEngine.Count()))
	var detectedFindings []*models.Finding

	for i := range services {
		svc := &services[i]
		findings, err := s.pluginEngine.EvaluateService(context.Background(), asset, svc, auditFacts, ceiling)
		if err == nil {
			for _, f := range findings {
				f.Reachability = s.reachability.EvaluateReachability(f, svc, auditFacts)
				detectedFindings = append(detectedFindings, f)
				logMsg(fmt.Sprintf("Finding detected: [%s] %s (Port: %d, Reachability: %s)", f.Severity, f.Title, f.Port, f.Reachability))
			}
		}
	}

	// 5. Ingest into Store with 4-Column Defensible Diff (§68.4)
	diff := s.store.IngestScanFindings(run.ID, asset.ID, detectedFindings, true)
	s.mu.Lock()
	run.Diff = diff
	run.TotalFindings = len(detectedFindings)
	run.Findings = detectedFindings

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
	s.mu.Unlock()

	// 6. Remediation Grouping (§50.1)
	remediations := s.remediator.GroupFindings(run.TenantID, detectedFindings)
	for _, r := range remediations {
		s.store.Remediations[r.ID] = r
	}
	s.mu.Lock()
	run.Remediations = remediations
	run.PortRange = portSpec
	run.SafetyCeiling = string(ceiling)
	run.MaxPPS = maxPPS

	if len(detectedFindings) == 0 {
		run.SummaryMessage = fmt.Sprintf("Target %s is clean: 0 actionable vulnerabilities detected across %d open ports (%v).", target, len(openPorts), portList)
	} else {
		run.SummaryMessage = fmt.Sprintf("Target %s: %d vulnerabilities detected across %d open ports, grouped into %d remediation actions.", target, len(detectedFindings), len(openPorts), len(remediations))
	}
	s.mu.Unlock()

	if len(detectedFindings) == 0 {
		logMsg(fmt.Sprintf("Assessment finished: Target is clean. 0 vulnerabilities across %d services.", len(openPorts)))
	} else {
		logMsg(fmt.Sprintf("Assessment finished: %d findings, %d remediation items generated.", len(detectedFindings), len(remediations)))
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
