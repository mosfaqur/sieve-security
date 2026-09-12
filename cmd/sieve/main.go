package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/collector"
	"github.com/mosfaqur/sieve-security/pkg/fingerprint"
	"github.com/mosfaqur/sieve-security/pkg/models"
	"github.com/mosfaqur/sieve-security/pkg/plugins"
	"github.com/mosfaqur/sieve-security/pkg/reachability"
	"github.com/mosfaqur/sieve-security/pkg/remediation"
	"github.com/mosfaqur/sieve-security/pkg/scan"
	"github.com/mosfaqur/sieve-security/pkg/scope"
	"github.com/mosfaqur/sieve-security/pkg/server"
	"github.com/mosfaqur/sieve-security/pkg/storage"
)

const version = "3.1.0-alpha"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "scan":
		runScan(os.Args[2:])
	case "server":
		runServer(os.Args[2:])
	case "plugins":
		runPlugins(os.Args[2:])
	case "version":
		fmt.Printf("Sieve Security Platform v%s (Consolidated Plan v3.1)\n", version)
	default:
		fmt.Printf("Unknown command: %s\n\n", subcmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Sieve Security — Vulnerability Management Platform")
	fmt.Println("Thesis: Fewer findings, each true, each with a fix.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  sieve scan <target> [flags]        Run targeted scan against an authorized target")
	fmt.Println("  sieve server [flags]               Launch the control plane and Web UI")
	fmt.Println("  sieve plugins [flags]              List and inspect loaded vulnerability plugins")
	fmt.Println("  sieve version                      Print platform version")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  sieve scan 192.168.1.30 --ssh-user root")
	fmt.Println("  sieve server --addr :8080")
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	sshUser := fs.String("ssh-user", "", "SSH username for credentialed assessment")
	sshPass := fs.String("ssh-pass", "", "SSH password for credentialed assessment")
	safety := fs.String("safety", "active-safe", "Safety ceiling (passive, active-safe, active-noisy, intrusive, destructive)")
	pluginDir := fs.String("plugins-dir", "content/plugins", "Path to declarative YAML plugins directory")
	outJSON := fs.Bool("json", false, "Output results as JSON")
	dataFile := fs.String("data-file", "data/sieve-store.json", "Path to local JSON persistence file")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Println("Error: target IP or hostname required")
		os.Exit(1)
	}
	target := fs.Arg(0)

	fmt.Printf("[*] Initializing Sieve Security scanner (Safety: %s)...\n", *safety)

	// 1. Initialize Store
	store, err := storage.NewStore(*dataFile)
	if err != nil {
		fmt.Printf("[-] Warning: Failed to open storage file %s: %v\n", *dataFile, err)
		store, _ = storage.NewStore("")
	}

	// 2. Load Plugins
	engine := plugins.NewEngine()
	if _, err := os.Stat(*pluginDir); err == nil {
		count, err := engine.LoadFromDir(*pluginDir)
		if err != nil {
			fmt.Printf("[-] Plugin load warning: %v\n", err)
		} else {
			fmt.Printf("[+] Loaded %d declarative vulnerability plugins from %s\n", count, *pluginDir)
		}
	}

	// 3. Compile Scope Guard (§4.1)
	sc := &models.Scope{
		ID:       "cli-scope",
		TenantID: "tenant-default",
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
		fmt.Printf("[-] Failed to compile scope: %v\n", err)
		os.Exit(1)
	}

	resolvedIPs, err := guard.ValidateAndResolve(target)
	if err != nil {
		fmt.Printf("[-] Scope guard rejection: %v\n", err)
		os.Exit(1)
	}
	targetIP := resolvedIPs[0]

	// 4. Discovery & Port Scan
	fmt.Printf("[*] Probing target %s (%s)...\n", target, targetIP.String())
	scanner := scan.NewScanner(guard)
	openPorts, err := scanner.ScanPorts(context.Background(), targetIP, scan.ScanOptions{
		MaxPPS:        2000,
		Timeout:       1200 * time.Millisecond,
		SafetyCeiling: models.SafetyClass(*safety),
	})
	if err != nil {
		fmt.Printf("[-] Port scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Discovered %d open TCP ports on %s\n", len(openPorts), targetIP.String())

	// 5. Service Interrogation
	fingerprinter := fingerprint.NewFingerprinter(guard, 2500*time.Millisecond)
	var services []models.Service
	for _, p := range openPorts {
		svc, err := fingerprinter.Identify(context.Background(), targetIP, p.Port)
		if err == nil && svc != nil {
			svc.AssetID = fmt.Sprintf("asset-%s", strings.ReplaceAll(targetIP.String(), ".", "-"))
			services = append(services, *svc)
			fmt.Printf("    -> Port %-5d %-10s %-15s %s\n", svc.Port, svc.ServiceName, svc.Product, svc.Version)
		}
	}

	// 6. Authenticated Host Collection if credentials specified
	var auditFacts *collector.HostAuditFact
	if *sshUser != "" {
		fmt.Printf("[*] Initiating authenticated assessment over SSH (%s@%s:22)...\n", *sshUser, targetIP.String())
		coll, err := collector.NewSSHCollectorAuto(targetIP.String(), 22, *sshUser, *sshPass, "", 5*time.Second)
		if err != nil {
			fmt.Printf("[-] SSH configuration error: %v\n", err)
		} else {
			facts, err := coll.Collect(context.Background())
			if err != nil {
				fmt.Printf("[-] Authenticated collection failed: %v\n", err)
			} else {
				auditFacts = facts
				fmt.Printf("[+] Authenticated host assessment successful! OS: %s %s, Packages: %d, Listening Sockets: %d\n",
					facts.OSName, facts.OSVersion, len(facts.Packages), len(facts.ListeningPorts))
			}
		}
	}

	// 7. Construct Asset Entity
	assetID := fmt.Sprintf("asset-%s", strings.ReplaceAll(targetIP.String(), ".", "-"))
	asset := &models.Asset{
		ID:            assetID,
		TenantID:      "tenant-default",
		NetworkZoneID: "zone-corp",
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
	store.UpsertAsset(asset)

	// 8. Evaluate Plugins & Reachability
	reachEvaluator := reachability.NewEvaluator()
	var detectedFindings []*models.Finding

	for i := range services {
		svc := &services[i]
		findings, err := engine.EvaluateService(context.Background(), asset, svc, auditFacts, models.SafetyClass(*safety))
		if err == nil {
			for _, f := range findings {
				f.Reachability = reachEvaluator.EvaluateReachability(f, svc, auditFacts)
				detectedFindings = append(detectedFindings, f)
			}
		}
	}

	// 9. Remediation Orchestration
	orchestrator := remediation.NewOrchestrator()
	remediations := orchestrator.GroupFindings("tenant-default", detectedFindings)
	for _, r := range remediations {
		store.Remediations[r.ID] = r
	}

	// 10. Update Store & Diff
	diff := store.IngestScanFindings(fmt.Sprintf("cli-%d", time.Now().Unix()), asset.ID, detectedFindings, true)
	_ = store.Save()

	if *outJSON {
		output := map[string]any{
			"target":        target,
			"ip":            targetIP.String(),
			"services":      services,
			"findings":      detectedFindings,
			"remediations":  remediations,
			"diff_summary":  diff,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(output)
		return
	}

	// Pretty Print Summary
	fmt.Printf("\n=======================================================\n")
	fmt.Printf("Sieve Security Scan Results for %s\n", target)
	fmt.Printf("=======================================================\n")
	fmt.Printf("Findings Detected: %d | Grouped Actions: %d\n", len(detectedFindings), len(remediations))
	fmt.Printf("Defensible Diff:   +%d new, %d fixed, %d reopened, %d unverified\n\n",
		diff.NewFindings, diff.ConfirmedFixed, diff.ReopenedFindings, diff.UnverifiedAbsent)

	fmt.Println("--- ACTIONABLE REMEDIATION QUEUE (The Thesis: What to Fix) ---")
	for i, r := range remediations {
		fmt.Printf("\nAction #%d [%s]: %s\n", i+1, strings.ToUpper(r.MaxSeverity), r.Title)
		fmt.Printf("  Target Hosts:     %s\n", strings.Join(r.TargetAssetNames, ", "))
		fmt.Printf("  Findings Bound:   %d\n", r.FindingCount)
		fmt.Printf("  Estimated Effort: %s\n", r.EstimatedEffort)
		fmt.Printf("  Risk Reduced:     -%.1f pts\n", r.TotalRiskRemoved)
		fmt.Printf("  CLI Fix Command:  %s\n", r.CLIScript)
	}

	fmt.Println("\n--- DETAILED FINDINGS (With Reachability Proof Stack) ---")
	for _, f := range detectedFindings {
		fmt.Printf("\n[%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		fmt.Printf("  Port/Proto:   %d/%s\n", f.Port, f.Protocol)
		fmt.Printf("  Reachability: %s\n", f.Reachability)
		fmt.Printf("  Confidence:   %s (%s)\n", f.Confidence, f.Method)
		if len(f.CVEs) > 0 {
			fmt.Printf("  CVEs:         %s\n", strings.Join(f.CVEs, ", "))
		}
		if f.Evidence != "" {
			fmt.Printf("  Evidence:     %s\n", f.Evidence)
		}
	}
	fmt.Printf("\nScan completed successfully in %s.\n", time.Since(asset.FirstSeen).Round(time.Millisecond))
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:8080", "Server listen address")
	pluginDir := fs.String("plugins-dir", "content/plugins", "Path to declarative plugins")
	dataFile := fs.String("data-file", "data/sieve-store.json", "Persistent data store file")
	fs.Parse(args)

	store, err := storage.NewStore(*dataFile)
	if err != nil {
		fmt.Printf("[-] Warning: could not load store from %s: %v\n", *dataFile, err)
		store, _ = storage.NewStore("")
	}

	engine := plugins.NewEngine()
	if _, err := os.Stat(*pluginDir); err == nil {
		count, err := engine.LoadFromDir(*pluginDir)
		if err != nil {
			fmt.Printf("[-] Plugin loading error: %v\n", err)
		} else {
			fmt.Printf("[+] Loaded %d plugins into engine\n", count)
		}
	}

	srv := server.NewServer(*addr, store, engine)
	if err := srv.Start(); err != nil {
		fmt.Printf("[-] Server terminated: %v\n", err)
		os.Exit(1)
	}
}

func runPlugins(args []string) {
	fs := flag.NewFlagSet("plugins", flag.ExitOnError)
	dir := fs.String("dir", "content/plugins", "Plugins directory")
	fs.Parse(args)

	engine := plugins.NewEngine()
	count, err := engine.LoadFromDir(*dir)
	if err != nil {
		fmt.Printf("Error loading plugins: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d declarative vulnerability plugins in '%s':\n\n", count, *dir)
	_ = filepath.WalkDir(*dir, func(path string, d os.DirEntry, err error) error {
		if !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			fmt.Printf(" - %s\n", path)
		}
		return nil
	})
}
