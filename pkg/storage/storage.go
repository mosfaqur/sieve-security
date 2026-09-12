package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

// Store provides persistence and query capabilities for the vulnerability platform.
type Store struct {
	mu           sync.RWMutex
	dataFile     string
	NetworkZones map[string]*models.NetworkZone
	Scopes       map[string]*models.Scope
	Assets       map[string]*models.Asset
	Findings     map[string]*models.Finding
	Remediations map[string]*models.RemediationItem
	ScanRuns     map[string]*models.ScanRun
}

// NewStore initializes an in-memory store with optional JSON file backing.
func NewStore(dataFile string) (*Store, error) {
	s := &Store{
		dataFile:     dataFile,
		NetworkZones: make(map[string]*models.NetworkZone),
		Scopes:       make(map[string]*models.Scope),
		Assets:       make(map[string]*models.Asset),
		Findings:     make(map[string]*models.Finding),
		Remediations: make(map[string]*models.RemediationItem),
		ScanRuns:     make(map[string]*models.ScanRun),
	}

	if dataFile != "" {
		if err := s.loadFromFile(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("load store from %s: %w", dataFile, err)
		}
	}

	return s, nil
}

// Save persists the current state to disk if dataFile is set.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.dataFile == "" {
		return nil
	}

	dir := filepath.Dir(s.dataFile)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	payload := struct {
		NetworkZones map[string]*models.NetworkZone     `json:"network_zones"`
		Scopes       map[string]*models.Scope           `json:"scopes"`
		Assets       map[string]*models.Asset           `json:"assets"`
		Findings     map[string]*models.Finding         `json:"findings"`
		Remediations map[string]*models.RemediationItem `json:"remediations"`
		ScanRuns     map[string]*models.ScanRun         `json:"scan_runs"`
	}{
		NetworkZones: s.NetworkZones,
		Scopes:       s.Scopes,
		Assets:       s.Assets,
		Findings:     s.Findings,
		Remediations: s.Remediations,
		ScanRuns:     s.ScanRuns,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.dataFile, data, 0600)
}

func (s *Store) loadFromFile() error {
	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return err
	}

	var payload struct {
		NetworkZones map[string]*models.NetworkZone     `json:"network_zones"`
		Scopes       map[string]*models.Scope           `json:"scopes"`
		Assets       map[string]*models.Asset           `json:"assets"`
		Findings     map[string]*models.Finding         `json:"findings"`
		Remediations map[string]*models.RemediationItem `json:"remediations"`
		ScanRuns     map[string]*models.ScanRun         `json:"scan_runs"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	if payload.NetworkZones != nil {
		s.NetworkZones = payload.NetworkZones
	}
	if payload.Scopes != nil {
		s.Scopes = payload.Scopes
	}
	if payload.Assets != nil {
		s.Assets = payload.Assets
	}
	if payload.Findings != nil {
		s.Findings = payload.Findings
	}
	if payload.Remediations != nil {
		s.Remediations = payload.Remediations
	}
	if payload.ScanRuns != nil {
		s.ScanRuns = payload.ScanRuns
	}

	return nil
}

// UpsertAsset records or updates an asset entity.
func (s *Store) UpsertAsset(asset *models.Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.Assets[asset.ID]
	if !ok {
		s.Assets[asset.ID] = asset
		return
	}

	existing.LastSeen = time.Now()
	existing.LastScanned = asset.LastScanned
	if asset.OSProduct != "" {
		existing.OSProduct = asset.OSProduct
		existing.OSVersion = asset.OSVersion
		existing.OSFamily = asset.OSFamily
	}
	if len(asset.Services) > 0 {
		existing.Services = asset.Services
	}
	if asset.LastCredentialed != nil {
		existing.LastCredentialed = asset.LastCredentialed
	}
}

// IngestScanFindings records scan findings and computes the Defensible 4-Column Scan Diff (§68.4).
func (s *Store) IngestScanFindings(
	runID string,
	assetID string,
	newFindings []*models.Finding,
	probedSuccessfully bool,
) models.DiffSummary {
	s.mu.Lock()
	defer s.mu.Unlock()

	diff := models.DiffSummary{}
	seenDedupKeys := make(map[string]bool)

	for _, f := range newFindings {
		seenDedupKeys[f.DedupKey] = true

		existing, exists := s.Findings[f.DedupKey]
		if !exists {
			// Brand new finding
			s.Findings[f.DedupKey] = f
			diff.NewFindings++
		} else {
			// Update last detected
			existing.LastDetected = time.Now()
			existing.Evidence = f.Evidence
			existing.Reachability = f.Reachability
			existing.Confidence = f.Confidence

			// Check for regression / reopen
			if existing.State == models.StateFixed || existing.State == models.StateUnverifiedAbsent {
				existing.State = models.StateOpen
				existing.ReopenedCount++
				diff.ReopenedFindings++
			}
		}
	}

	// Check previous findings for this asset that were not seen in this scan
	for _, f := range s.Findings {
		if f.AssetID == assetID && f.State == models.StateOpen {
			if !seenDedupKeys[f.DedupKey] {
				if probedSuccessfully {
					// Confirmed fixed
					f.State = models.StateFixed
					now := time.Now()
					f.FixedAt = &now
					diff.ConfirmedFixed++
				} else {
					// Host timed out or auth failed: DO NOT claim fixed! Mark unverified absent (§6.5)
					f.State = models.StateUnverifiedAbsent
					diff.UnverifiedAbsent++
				}
			}
		}
	}

	return diff
}

// ListFindings returns all findings matching filter parameters.
func (s *Store) ListFindings(severity string, state models.FindingState) []*models.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*models.Finding
	for _, f := range s.Findings {
		if severity != "" && f.Severity != severity {
			continue
		}
		if state != "" && f.State != state {
			continue
		}
		list = append(list, f)
	}
	return list
}

// ListRemediations returns active remediation items.
func (s *Store) ListRemediations() []*models.RemediationItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*models.RemediationItem
	for _, r := range s.Remediations {
		list = append(list, r)
	}
	return list
}

// UpdateFindingState updates the state of a specific finding (e.g. Zen Triage actions).
func (s *Store) UpdateFindingState(dedupKey string, newState models.FindingState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.Findings[dedupKey]
	if !ok {
		return false
	}
	f.State = newState
	if newState == models.StateFixed {
		now := time.Now()
		f.FixedAt = &now
	}
	return true
}
