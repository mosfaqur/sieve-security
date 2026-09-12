package plugins

import (
	"context"
	"testing"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

func TestPluginEngine(t *testing.T) {
	eng := NewEngine()

	// Register a test plugin
	p1 := &PluginDef{
		ID:            "openssh-cve-2024-6387",
		SchemaVersion: 2,
		Info: PluginInfo{
			Name:        "OpenSSH RegreSSHion Remote Code Execution",
			Family:      "ssh",
			Severity:    "critical",
			CVE:         []string{"CVE-2024-6387"},
			Safety:      models.SafetyActiveSafe,
			Method:      models.MethodVersionInference,
			Confidence:  models.ConfidenceProbable,
			Description: "Signal handler race condition leading to potential RCE in default OpenSSH server",
			Remediation: "Upgrade OpenSSH to 9.8p1 or newer",
		},
		Requires: PluginRequires{
			Service: []string{"ssh", "openssh"},
			Ports:   []int{22},
		},
		Matchers: []MatcherItem{
			{
				Type:    "version",
				FixedIn: "9.8",
			},
		},
		Emit: EmitDef{
			Title: "OpenSSH Signal Handler Race Condition (CVE-2024-6387)",
			Evidence: EvidenceDef{
				MaxBytes: 1024,
			},
		},
	}

	eng.RegisterPlugin(p1)

	asset := &models.Asset{
		ID:            "asset-test-1",
		TenantID:      "tenant-1",
		NetworkZoneID: "zone-corp",
		DisplayName:   "web-server-01",
		IPv4:          "192.168.1.30",
	}

	// Vulnerable service (OpenSSH 8.9p1 < 9.8)
	vulnSvc := &models.Service{
		ID:          "svc-22",
		Port:        22,
		Protocol:    "tcp",
		ServiceName: "ssh",
		Product:     "OpenSSH",
		Version:     "8.9",
		Banner:      "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
	}

	findings, err := eng.EvaluateService(context.Background(), asset, vulnSvc, nil, models.SafetyActiveSafe)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for vulnerable OpenSSH, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != "critical" {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.DedupKey == "" {
		t.Errorf("expected non-empty dedup key")
	}

	// Patched service (OpenSSH 9.8p1) -> True Negative test
	patchedSvc := &models.Service{
		ID:          "svc-22-fixed",
		Port:        22,
		Protocol:    "tcp",
		ServiceName: "ssh",
		Product:     "OpenSSH",
		Version:     "9.8",
		Banner:      "SSH-2.0-OpenSSH_9.8p1",
	}

	cleanFindings, err := eng.EvaluateService(context.Background(), asset, patchedSvc, nil, models.SafetyActiveSafe)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cleanFindings) != 0 {
		t.Errorf("expected 0 findings for patched OpenSSH (true negative gate), got %d", len(cleanFindings))
	}
}

func TestSafetyGating(t *testing.T) {
	eng := NewEngine()

	// Intrusive check
	pIntrusive := &PluginDef{
		ID: "dos-check-intrusive",
		Info: PluginInfo{
			Name:     "Intrusive Buffer Overflow Probe",
			Safety:   models.SafetyIntrusive,
			Severity: "high",
		},
		Requires: PluginRequires{
			Ports: []int{80},
		},
		Matchers: []MatcherItem{
			{Type: "banner", Pattern: "nginx"},
		},
		Emit: EmitDef{Title: "Intrusive Test"},
	}

	eng.RegisterPlugin(pIntrusive)

	asset := &models.Asset{ID: "a1", TenantID: "t1"}
	svc := &models.Service{Port: 80, Banner: "nginx/1.18.0"}

	// When ceiling is active-safe, intrusive check MUST NOT run
	findings, err := eng.EvaluateService(context.Background(), asset, svc, nil, models.SafetyActiveSafe)
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected intrusive plugin to be gated out under active-safe, got %d", len(findings))
	}

	// When ceiling is intrusive, check is permitted
	findings, err = eng.EvaluateService(context.Background(), asset, svc, nil, models.SafetyIntrusive)
	if err != nil {
		t.Fatalf("eval error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected intrusive plugin to run when ceiling allows, got %d", len(findings))
	}
}
