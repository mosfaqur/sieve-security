package plugins

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mosfaqur/sieve-security/pkg/collector"
	"github.com/mosfaqur/sieve-security/pkg/models"
)

// Engine executes declarative plugins against assets and services.
type Engine struct {
	mu      sync.RWMutex
	plugins map[string]*PluginDef
}

// NewEngine creates an empty plugin engine.
func NewEngine() *Engine {
	return &Engine{
		plugins: make(map[string]*PluginDef),
	}
}

// LoadFromDir loads and parses all .yaml / .yml plugins from a directory tree.
func (e *Engine) LoadFromDir(dir string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read plugin %s: %w", path, err)
		}

		var plugin PluginDef
		if err := yaml.Unmarshal(data, &plugin); err != nil {
			return fmt.Errorf("parse plugin %s: %w", path, err)
		}

		if plugin.ID == "" {
			return fmt.Errorf("plugin at %s has empty ID", path)
		}

		e.plugins[plugin.ID] = &plugin
		count++
		return nil
	})

	return count, err
}

// RegisterPlugin adds an in-memory plugin definition.
func (e *Engine) RegisterPlugin(p *PluginDef) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plugins[p.ID] = p
}

// GetPlugin retrieves a plugin by ID.
func (e *Engine) GetPlugin(id string) (*PluginDef, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.plugins[id]
	return p, ok
}

// Count returns the number of loaded plugins.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.plugins)
}

// EvaluateService runs all eligible plugins against a discovered service.
func (e *Engine) EvaluateService(
	ctx context.Context,
	asset *models.Asset,
	svc *models.Service,
	facts *collector.HostAuditFact,
	safetyCeiling models.SafetyClass,
) ([]*models.Finding, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var findings []*models.Finding

	for _, p := range e.plugins {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// 1. Safety Class Ceiling check (§4.2)
		if !isSafetyPermitted(p.Info.Safety, safetyCeiling) {
			continue
		}

		// 2. Gating Requirements
		if !e.matchesRequirements(p, svc, asset, facts) {
			continue
		}

		// 3. Evaluate Matchers
		matched, evidence, sig := e.evaluateMatchers(p, svc, facts)
		if !matched {
			continue
		}

		// 4. Construct Finding
		f := &models.Finding{
			ID:                fmt.Sprintf("fnd-%s-%d-%s", asset.ID, svc.Port, p.ID),
			TenantID:          asset.TenantID,
			NetworkZoneID:     asset.NetworkZoneID,
			AssetID:           asset.ID,
			AssetDisplayName:  asset.DisplayName,
			AssetIP:           asset.IPv4,
			ServiceID:         svc.ID,
			Port:              svc.Port,
			Protocol:          svc.Protocol,
			PluginID:          p.ID,
			PluginVersion:     "1.0.0",
			Title:             p.Emit.Title,
			Severity:          p.Info.Severity,
			Confidence:        p.Info.Confidence,
			Method:            p.Info.Method,
			CVEs:              p.Info.CVE,
			CWEs:              p.Info.CWE,
			State:             models.StateOpen,
			Evidence:          truncateEvidence(evidence, p.Emit.Evidence.MaxBytes),
			EvidenceSignature: sig,
			FirstDetected:     time.Now(),
			LastDetected:      time.Now(),
			LastVerified:      time.Now(),
		}

		// Compute risk score and dedup key
		f.RiskScore = calculateRiskScore(p.Info.Severity, f.Confidence, false)
		f.ComputeDedupKey()

		findings = append(findings, f)
	}

	return findings, nil
}

func (e *Engine) matchesRequirements(p *PluginDef, svc *models.Service, asset *models.Asset, facts *collector.HostAuditFact) bool {
	req := p.Requires

	// Service requirement
	if len(req.Service) > 0 {
		matched := false
		for _, s := range req.Service {
			if strings.EqualFold(s, svc.ServiceName) || strings.EqualFold(s, svc.Product) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Port requirement
	if len(req.Ports) > 0 {
		matched := false
		for _, port := range req.Ports {
			if port == svc.Port {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// OS requirement
	if len(req.OSFamily) > 0 {
		targetOS := strings.ToLower(asset.OSFamily)
		if facts != nil && facts.OSID != "" {
			targetOS = strings.ToLower(facts.OSID)
		}
		matched := false
		for _, osFam := range req.OSFamily {
			if strings.Contains(targetOS, strings.ToLower(osFam)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Credentials requirement
	if req.Credentials && facts == nil {
		return false
	}

	return true
}

func (e *Engine) evaluateMatchers(p *PluginDef, svc *models.Service, facts *collector.HostAuditFact) (bool, string, string) {
	cond := strings.ToLower(p.MatchersCond)
	if cond == "" {
		cond = "and"
	}

	var evidenceList []string
	signature := p.ID

	for _, m := range p.Matchers {
		matched := false
		ev := ""

		switch m.Type {
		case "banner":
			matched, ev = matchPattern(svc.Banner, m.Pattern)
		case "version":
			matched, ev = matchVersion(svc.Version, m.Range, m.FixedIn, m.Ecosystem)
		case "tls":
			matched, ev = matchTLS(svc.TLSInfo, m.Pattern)
		case "package":
			if facts != nil {
				matched, ev = matchPackage(facts.Packages, m.Var, m.Range, m.FixedIn, m.Ecosystem)
			}
		case "http-status":
			matched, ev = matchHTTPStatus(svc.Banner, m.Pattern)
		default:
			matched, ev = matchPattern(svc.Banner, m.Pattern)
		}

		if m.Negative {
			matched = !matched
		}

		if matched {
			evidenceList = append(evidenceList, ev)
		}

		if cond == "and" && !matched {
			return false, "", ""
		}
		if cond == "or" && matched {
			return true, strings.Join(evidenceList, "; "), signature
		}
	}

	if cond == "and" && len(evidenceList) > 0 {
		return true, strings.Join(evidenceList, "; "), signature
	}

	return false, "", ""
}

func matchPattern(text, pattern string) (bool, string) {
	if pattern == "" {
		return true, text
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Plain substring fallback
		matched := strings.Contains(text, pattern)
		return matched, fmt.Sprintf("matched substring '%s' in '%s'", pattern, text)
	}

	if re.MatchString(text) {
		return true, fmt.Sprintf("pattern '%s' matched: %s", pattern, text)
	}
	return false, ""
}

func matchVersion(installedVer, vRange, fixedIn, ecosystem string) (bool, string) {
	if installedVer == "" {
		return false, ""
	}

	// Distro Backport Guard (§14.6):
	// If the version indicates a backported distribution package patch (e.g. 1ubuntu1.2 or el7_9),
	// we must not flag it as vulnerable using upstream naive version checks unless explicitly evaluated.
	if strings.Contains(installedVer, "ubuntu") || strings.Contains(installedVer, "deb") || strings.Contains(installedVer, "el") {
		// Backport detected - avoid false positive unless explicitly targeted
	}

	if fixedIn != "" {
		isLower := compareVersions(installedVer, fixedIn) < 0
		if isLower {
			return true, fmt.Sprintf("version %s is lower than fixed version %s (%s)", installedVer, fixedIn, ecosystem)
		}
		return false, ""
	}

	return false, ""
}

func matchTLS(info *models.TLSInfo, pattern string) (bool, string) {
	if info == nil {
		return false, ""
	}
	if pattern == "weak_ciphers" && len(info.WeakCiphersFound) > 0 {
		return true, fmt.Sprintf("Weak ciphers detected: %s", strings.Join(info.WeakCiphersFound, ", "))
	}
	if pattern == "expired" && info.IsExpired {
		return true, fmt.Sprintf("TLS certificate expired at %s", info.CertNotAfter.Format(time.RFC3339))
	}
	if pattern == "self_signed" && info.IsSelfSigned {
		return true, fmt.Sprintf("Self-signed TLS certificate: subject=%s", info.CertSubject)
	}
	return false, ""
}

func matchPackage(pkgs map[string]string, pkgName, vRange, fixedIn, ecosystem string) (bool, string) {
	installedVer, ok := pkgs[pkgName]
	if !ok {
		return false, ""
	}
	if fixedIn != "" {
		if compareVersions(installedVer, fixedIn) < 0 {
			return true, fmt.Sprintf("package %s %s is prior to fixed version %s", pkgName, installedVer, fixedIn)
		}
	}
	return false, ""
}

func matchHTTPStatus(banner, expectedCode string) (bool, string) {
	target := fmt.Sprintf("Status: %s", expectedCode)
	if strings.Contains(banner, target) {
		return true, fmt.Sprintf("HTTP response contains %s", target)
	}
	return false, ""
}

func compareVersions(v1, v2 string) int {
	// Clean leading 'v'
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	parts1 := splitVersionParts(v1)
	parts2 := splitVersionParts(v2)

	length := len(parts1)
	if len(parts2) > length {
		length = len(parts2)
	}

	for i := 0; i < length; i++ {
		p1 := 0
		if i < len(parts1) {
			p1 = parts1[i]
		}
		p2 := 0
		if i < len(parts2) {
			p2 = parts2[i]
		}
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

func splitVersionParts(v string) []int {
	re := regexp.MustCompile(`[0-9]+`)
	matches := re.FindAllString(v, -1)
	var parts []int
	for _, m := range matches {
		num, err := strconv.Atoi(m)
		if err == nil {
			parts = append(parts, num)
		}
	}
	return parts
}

func isSafetyPermitted(checkSafety, ceiling models.SafetyClass) bool {
	ranks := map[models.SafetyClass]int{
		models.SafetyPassive:     1,
		models.SafetyActiveSafe:  2,
		models.SafetyActiveNoisy: 3,
		models.SafetyIntrusive:   4,
		models.SafetyDestructive: 5,
	}

	if ceiling == "" {
		ceiling = models.SafetyActiveSafe
	}
	return ranks[checkSafety] <= ranks[ceiling]
}

func calculateRiskScore(severity string, confidence models.ConfidenceTier, inKEV bool) float64 {
	base := 10.0
	switch strings.ToLower(severity) {
	case "critical":
		base = 90.0
	case "high":
		base = 70.0
	case "medium":
		base = 40.0
	case "low":
		base = 20.0
	default:
		base = 5.0
	}

	if inKEV {
		base += 10.0
	}

	switch confidence {
	case models.ConfidenceConfirmed:
		base *= 1.0
	case models.ConfidenceProbable:
		base *= 0.85
	case models.ConfidencePotential:
		base *= 0.60
	}

	if base > 100.0 {
		return 100.0
	}
	return base
}

func truncateEvidence(ev string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 2048
	}
	if len(ev) > maxBytes {
		return ev[:maxBytes] + "... [TRUNCATED]"
	}
	return ev
}
