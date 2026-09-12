package remediation

import (
	"testing"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

func TestRemediationGrouping(t *testing.T) {
	orchestrator := NewOrchestrator()

	f1 := &models.Finding{
		ID:          "fnd-1",
		PluginID:    "openssh-regresshion-cve-2024-6387",
		Title:       "OpenSSH RCE",
		Severity:    "critical",
		RiskScore:   76.5,
		AssetID:     "asset-1",
		AssetDisplayName: "web-01",
	}

	f2 := &models.Finding{
		ID:          "fnd-2",
		PluginID:    "openssh-weak-kex",
		Title:       "OpenSSH Weak Key Exchange",
		Severity:    "medium",
		RiskScore:   35.0,
		AssetID:     "asset-1",
		AssetDisplayName: "web-01",
	}

	f3 := &models.Finding{
		ID:          "fnd-3",
		PluginID:    "nginx-version-exposure",
		Title:       "Nginx Version Disclosure",
		Severity:    "low",
		RiskScore:   15.0,
		AssetID:     "asset-2",
		AssetDisplayName: "web-02",
	}

	items := orchestrator.GroupFindings("tenant-default", []*models.Finding{f1, f2, f3})

	// f1 and f2 should group under openssh-server, f3 under nginx
	if len(items) != 2 {
		t.Fatalf("expected 2 grouped remediation items, got %d", len(items))
	}

	var sshItem, nginxItem *models.RemediationItem
	for _, item := range items {
		if item.ActionType == "package_upgrade" && item.MaxSeverity == "critical" {
			sshItem = item
		}
		if item.ActionType == "package_upgrade" && item.MaxSeverity == "low" {
			nginxItem = item
		}
	}

	if sshItem == nil {
		t.Fatalf("expected SSH remediation item to be created")
	}
	if sshItem.FindingCount != 2 {
		t.Errorf("expected SSH item to bind 2 findings, got %d", sshItem.FindingCount)
	}
	if sshItem.TotalRiskRemoved != 111.5 {
		t.Errorf("expected total risk removed to be 111.5, got %f", sshItem.TotalRiskRemoved)
	}
	if sshItem.CLIScript == "" {
		t.Errorf("expected non-empty CLI script")
	}

	if nginxItem == nil {
		t.Fatalf("expected Nginx remediation item to be created")
	}
}
