package storage

import (
	"testing"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

func TestStorageDefensibleDiff(t *testing.T) {
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	assetID := "asset-srv-1"
	f1 := &models.Finding{
		ID:        "f1",
		AssetID:   assetID,
		PluginID:  "vuln-check-1",
		Port:      80,
		Protocol:  "tcp",
		Severity:  "high",
		State:     models.StateOpen,
		EvidenceSignature: "sig-1",
	}
	f1.ComputeDedupKey()

	// 1. Initial Scan: Ingest finding
	diff1 := store.IngestScanFindings("run-1", assetID, []*models.Finding{f1}, true)
	if diff1.NewFindings != 1 {
		t.Errorf("expected 1 new finding, got %d", diff1.NewFindings)
	}

	// 2. Second Scan: Probed successfully, but vulnerability was patched -> CONFIRMED FIXED
	diff2 := store.IngestScanFindings("run-2", assetID, []*models.Finding{}, true)
	if diff2.ConfirmedFixed != 1 {
		t.Errorf("expected 1 confirmed fixed, got %d", diff2.ConfirmedFixed)
	}
	if store.Findings[f1.DedupKey].State != models.StateFixed {
		t.Errorf("expected state to be fixed, got %s", store.Findings[f1.DedupKey].State)
	}

	// 3. Third Scan: Vulnerability regressed -> REOPENED
	diff3 := store.IngestScanFindings("run-3", assetID, []*models.Finding{f1}, true)
	if diff3.ReopenedFindings != 1 {
		t.Errorf("expected 1 reopened finding, got %d", diff3.ReopenedFindings)
	}
	if store.Findings[f1.DedupKey].State != models.StateOpen {
		t.Errorf("expected state to be open, got %s", store.Findings[f1.DedupKey].State)
	}

	// 4. Fourth Scan: Target timed out / probed unsuccessfully -> UNVERIFIED ABSENT (NOT FIXED)
	diff4 := store.IngestScanFindings("run-4", assetID, []*models.Finding{}, false)
	if diff4.UnverifiedAbsent != 1 {
		t.Errorf("expected 1 unverified absent, got %d", diff4.UnverifiedAbsent)
	}
	if store.Findings[f1.DedupKey].State != models.StateUnverifiedAbsent {
		t.Errorf("expected state to be unverified_absent, got %s", store.Findings[f1.DedupKey].State)
	}
}
