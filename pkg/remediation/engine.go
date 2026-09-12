package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

// Orchestrator groups findings into actionable remediation units (§50.1).
type Orchestrator struct{}

// NewOrchestrator creates a remediation engine.
func NewOrchestrator() *Orchestrator {
	return &Orchestrator{}
}

// GroupFindings synthesizes individual findings into prioritized RemediationItems.
func (o *Orchestrator) GroupFindings(tenantID string, findings []*models.Finding) []*models.RemediationItem {
	// Group key -> slice of findings
	groups := make(map[string][]*models.Finding)

	for _, f := range findings {
		key := deriveGroupKey(f)
		groups[key] = append(groups[key], f)
	}

	var items []*models.RemediationItem

	for groupKey, groupFindings := range groups {
		if len(groupFindings) == 0 {
			continue
		}

		item := o.buildRemediationItem(tenantID, groupKey, groupFindings)
		items = append(items, item)
	}

	return items
}

func deriveGroupKey(f *models.Finding) string {
	pluginLower := strings.ToLower(f.PluginID)
	if strings.Contains(pluginLower, "openssh") || strings.Contains(pluginLower, "ssh") {
		return "pkg:openssh-server"
	}
	if strings.Contains(pluginLower, "proftpd") || strings.Contains(pluginLower, "ftp") {
		return "pkg:proftpd"
	}
	if strings.Contains(pluginLower, "nginx") {
		return "pkg:nginx"
	}
	if strings.Contains(pluginLower, "apache") {
		return "pkg:apache2"
	}
	if strings.Contains(pluginLower, "mysql") {
		return "pkg:mysql-server"
	}
	if strings.Contains(pluginLower, "tls") || strings.Contains(pluginLower, "cert") || strings.Contains(pluginLower, "cipher") {
		return "config:tls-hardening"
	}
	if strings.Contains(pluginLower, "varnish") {
		return "pkg:varnish"
	}

	return fmt.Sprintf("custom:%s", f.PluginID)
}

func (o *Orchestrator) buildRemediationItem(tenantID, groupKey string, findings []*models.Finding) *models.RemediationItem {
	first := findings[0]
	var findingIDs []string
	assetSet := make(map[string]string)
	var totalRisk float64
	maxSev := "info"

	for _, f := range findings {
		findingIDs = append(findingIDs, f.ID)
		assetSet[f.AssetID] = f.AssetDisplayName
		if assetSet[f.AssetID] == "" {
			assetSet[f.AssetID] = f.AssetIP
		}
		totalRisk += f.RiskScore
		maxSev = higherSeverity(maxSev, f.Severity)
	}

	var assetIDs []string
	var assetNames []string
	for id, name := range assetSet {
		assetIDs = append(assetIDs, id)
		assetNames = append(assetNames, name)
	}

	item := &models.RemediationItem{
		ID:               fmt.Sprintf("rem-%s-%d", strings.ReplaceAll(groupKey, ":", "-"), time.Now().Unix()),
		TenantID:         tenantID,
		TargetAssets:     assetIDs,
		TargetAssetNames: assetNames,
		FindingIDs:       findingIDs,
		FindingCount:     len(findings),
		MaxSeverity:      maxSev,
		TotalRiskRemoved: totalRisk,
		Status:           "open",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Generate multi-modal scripts based on action type
	switch {
	case strings.HasPrefix(groupKey, "pkg:"):
		pkg := strings.TrimPrefix(groupKey, "pkg:")
		item.Title = fmt.Sprintf("Upgrade %s to latest security release", pkg)
		item.Summary = fmt.Sprintf("Resolves %d vulnerabilities across %d host(s).", len(findings), len(assetIDs))
		item.ActionType = "package_upgrade"
		item.EstimatedEffort = "~15 min"
		item.CLIScript = fmt.Sprintf("sudo apt-get update && sudo apt-get install -y --only-upgrade %s && sudo systemctl restart %s", pkg, pkg)
		item.AnsibleSnippet = fmt.Sprintf("- name: Upgrade %s\n  ansible.builtin.apt:\n    name: %s\n    state: latest\n    update_cache: yes\n  notify: Restart %s", pkg, pkg, pkg)
		item.DockerfileSnippet = fmt.Sprintf("RUN apt-get update && apt-get install -y --only-upgrade %s && rm -rf /var/lib/apt/lists/*", pkg)
		item.VerificationCmd = fmt.Sprintf("dpkg-query -W -f='${Package} ${Version}\\n' %s", pkg)

	case groupKey == "config:tls-hardening":
		item.Title = "Disable deprecated TLS protocols and weak cipher suites"
		item.Summary = fmt.Sprintf("Mitigates cryptographic downgrade risks across %d host(s).", len(assetIDs))
		item.ActionType = "config_change"
		item.EstimatedEffort = "~30 min"
		item.CLIScript = "sudo sed -i 's/ssl_protocols .*/ssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf && sudo nginx -t && sudo systemctl reload nginx"
		item.AnsibleSnippet = "- name: Enforce TLS 1.2 and 1.3\n  ansible.builtin.lineinfile:\n    path: /etc/nginx/nginx.conf\n    regexp: '^\\s*ssl_protocols'\n    line: '    ssl_protocols TLSv1.2 TLSv1.3;'\n  notify: Reload nginx"
		item.VerificationCmd = "openssl s_client -connect localhost:443 -tls1_1"

	default:
		item.Title = fmt.Sprintf("Remediate %s", first.Title)
		item.Summary = fmt.Sprintf("Applies security configuration fixes for %d finding(s).", len(findings))
		item.ActionType = "config_change"
		item.EstimatedEffort = "~20 min"
		item.CLIScript = fmt.Sprintf("# Review and apply remediation for %s", first.PluginID)
		item.AnsibleSnippet = fmt.Sprintf("# Ansible task for %s", first.PluginID)
		item.VerificationCmd = "echo 'Verification probe'"
	}

	// Attach this remediation ID to each finding
	for _, f := range findings {
		f.RemediationID = item.ID
	}

	return item
}

func higherSeverity(sev1, sev2 string) string {
	ranks := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}
	if ranks[strings.ToLower(sev2)] > ranks[strings.ToLower(sev1)] {
		return strings.ToLower(sev2)
	}
	return strings.ToLower(sev1)
}
