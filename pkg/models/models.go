package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// SafetyClass specifies the blast radius control level defined in §4.2.
type SafetyClass string

const (
	SafetyPassive     SafetyClass = "passive"       // Observes only; never sends active traffic
	SafetyActiveSafe  SafetyClass = "active-safe"   // Standard active traffic; cannot alter state or crash service
	SafetyActiveNoisy SafetyClass = "active-noisy"  // May generate logs, alerts, or test events
	SafetyIntrusive   SafetyClass = "intrusive"     // Potential DoS, account lockout, or config disturbance
	SafetyDestructive SafetyClass = "destructive"   // Exploitation, brute force, reboot (off by default)
)

// ConfidenceTier identifies the defensibility tier of a detection (§1.2, §4.3).
type ConfidenceTier string

const (
	ConfidenceConfirmed ConfidenceTier = "confirmed" // Cryptographic, active probe verification, or exact package version match
	ConfidenceProbable  ConfidenceTier = "probable"  // Strong banner or protocol leak matching authoritative advisory
	ConfidencePotential ConfidenceTier = "potential" // Heuristic or inferred detection; requires review
)

// DetectionMethod identifies how a finding was identified (§1.2, §6.5).
type DetectionMethod string

const (
	MethodVersionInference DetectionMethod = "version_inference"
	MethodActiveProbe      DetectionMethod = "active_probe"
	MethodCredentialed     DetectionMethod = "credentialed"
	MethodConfigAudit      DetectionMethod = "config_audit"
	MethodAgent            DetectionMethod = "agent"
	MethodPassive          DetectionMethod = "passive"
	MethodSBOM             DetectionMethod = "sbom"
)

// ReachabilityState represents the two-tier reachability determination (§1.2, §38.4).
type ReachabilityState string

const (
	ReachabilityListeningAndLoaded ReachabilityState = "listening_and_loaded"   // Tier 1 + Tier 2: Public listener AND symbol/library loaded in process memory
	ReachabilityListeningProcess   ReachabilityState = "listening_process"      // Tier 1: Socket listener binds directly to process binary
	ReachabilityInstalledRunning   ReachabilityState = "installed_and_running"  // Process running but not bound to listening port
	ReachabilityInstalledNotRun    ReachabilityState = "installed_not_running"  // Package installed on disk, no process running
	ReachabilityNotLoaded          ReachabilityState = "not_loaded"             // Library present on disk, verified NOT mapped into memory
	ReachabilityUnknown            ReachabilityState = "unknown"
)

// FindingState represents finding lifecycle (§6.5, §44.3).
type FindingState string

const (
	StateOpen             FindingState = "open"
	StateFixed            FindingState = "fixed"
	StateRiskAccepted     FindingState = "risk_accepted"
	StateFalsePositive    FindingState = "false_positive"
	StateMitigated        FindingState = "mitigated"
	StateWontFix          FindingState = "wont_fix"
	StateUnverifiedAbsent FindingState = "unverified_absent" // Protects against false victories on timeout or auth failure
)

// NetworkZone isolates overlapping RFC1918 subnets (§6.1, §6.3).
type NetworkZone struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Scope defines the boundary of authorized testing (§4.1).
type Scope struct {
	ID                 string       `json:"id"`
	TenantID           string       `json:"tenant_id"`
	Name               string       `json:"name"`
	Entries            []ScopeEntry `json:"entries"`
	Exclusions         []ScopeEntry `json:"exclusions"`
	OwnerUserID        string       `json:"owner_user_id"`
	ApprovedBy         string       `json:"approved_by,omitempty"`
	ApprovedAt         *time.Time   `json:"approved_at,omitempty"`
	AttestationExpires *time.Time   `json:"attestation_expires,omitempty"`
	Status             string       `json:"status"` // active, pending, expired, revoked
}

// ScopeEntry specifies a target CIDR, IP range, or hostname.
type ScopeEntry struct {
	Kind  string `json:"kind"`  // cidr, ip, hostname, domain
	Value string `json:"value"` // e.g. "192.168.1.0/24", "192.168.1.30"
}

// Asset represents a discovered or credentialed target (§6.2).
type Asset struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	NetworkZoneID     string            `json:"network_zone_id"`
	DisplayName       string            `json:"display_name"`
	IPv4              string            `json:"ipv4"`
	IPv6              string            `json:"ipv6,omitempty"`
	MAC               string            `json:"mac,omitempty"`
	Hostname          string            `json:"hostname,omitempty"`
	FQDN              string            `json:"fqdn,omitempty"`
	OSFamily          string            `json:"os_family,omitempty"`
	OSProduct         string            `json:"os_product,omitempty"`
	OSVersion         string            `json:"os_version,omitempty"`
	OSConfidence      int               `json:"os_confidence"`
	AssetClass        string            `json:"asset_class"` // server, workstation, network_device, printer, etc.
	Criticality       int               `json:"criticality"` // 1..10
	Exposure          string            `json:"exposure"`    // internet, dmz, internal, isolated
	Environment       string            `json:"environment"` // prod, staging, dev
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
	LastScanned       time.Time         `json:"last_scanned"`
	LastCredentialed  *time.Time        `json:"last_credentialed,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	Services          []Service         `json:"services,omitempty"`
	Identities        []AssetIdentity   `json:"identities,omitempty"`
}

// AssetIdentity represents identity signals used for deduplication & resolution (§6.3).
type AssetIdentity struct {
	Kind       string    `json:"kind"`       // agent_uuid, cloud_instance_id, machine_guid, mac_address, ssh_host_key_fp, ip
	Value      string    `json:"value"`      // Normalized value
	Confidence string    `json:"confidence"` // authoritative, high, medium, low
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Service represents an identified network listener on an asset (§6.4).
type Service struct {
	ID            string    `json:"id"`
	AssetID       string    `json:"asset_id"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"` // tcp, udp
	State         string    `json:"state"`    // open, filtered, closed
	ServiceName   string    `json:"service_name"`
	Product       string    `json:"product,omitempty"`
	Version       string    `json:"version,omitempty"`
	ExtraInfo     string    `json:"extra_info,omitempty"`
	CPE           []string  `json:"cpe,omitempty"`
	Tunnel        string    `json:"tunnel,omitempty"` // none, tls, ssl
	TLSInfo       *TLSInfo  `json:"tls_info,omitempty"`
	Banner        string    `json:"banner,omitempty"`
	BannerHash    string    `json:"banner_hash,omitempty"`
	ProcessPID    int       `json:"process_pid,omitempty"`
	ProcessBinary string    `json:"process_binary,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// TLSInfo encapsulates detailed TLS interrogation results (§6.4, §14.5).
type TLSInfo struct {
	Version            string    `json:"version"` // TLS 1.3, TLS 1.2, etc.
	CipherSuite        string    `json:"cipher_suite"`
	SupportedVersions  []string  `json:"supported_versions,omitempty"`
	WeakCiphersFound   []string  `json:"weak_ciphers_found,omitempty"`
	CertSubject        string    `json:"cert_subject,omitempty"`
	CertIssuer         string    `json:"cert_issuer,omitempty"`
	CertSANs           []string  `json:"cert_sans,omitempty"`
	CertNotAfter       time.Time `json:"cert_not_after"`
	IsExpired          bool      `json:"is_expired"`
	IsSelfSigned       bool      `json:"is_self_signed"`
	DaysUntilExpiraton int       `json:"days_until_expiration"`
}

// Finding represents a detected vulnerability or misconfiguration (§6.5).
type Finding struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id"`
	NetworkZoneID     string            `json:"network_zone_id"`
	AssetID           string            `json:"asset_id"`
	AssetDisplayName  string            `json:"asset_display_name,omitempty"`
	AssetIP           string            `json:"asset_ip,omitempty"`
	ServiceID         string            `json:"service_id,omitempty"`
	Port              int               `json:"port,omitempty"`
	Protocol          string            `json:"protocol,omitempty"`
	PluginID          string            `json:"plugin_id"`
	PluginVersion     string            `json:"plugin_version"`
	Title             string            `json:"title"`
	Severity          string            `json:"severity"` // critical, high, medium, low, info
	CVSSv3Score       float64           `json:"cvss_v3_score,omitempty"`
	CVSSv3Vector      string            `json:"cvss_v3_vector,omitempty"`
	EPSSScore         float64           `json:"epss_score,omitempty"`
	InKEV             bool              `json:"in_kev"`
	RiskScore         float64           `json:"risk_score"`
	RiskExplanation   map[string]any    `json:"risk_explanation,omitempty"`
	Confidence        ConfidenceTier    `json:"confidence"`
	Method            DetectionMethod   `json:"method"`
	Reachability      ReachabilityState `json:"reachability"`
	CVEs              []string          `json:"cves,omitempty"`
	CWEs              []string          `json:"cwes,omitempty"`
	VendorAdvisories  []string          `json:"vendor_advisories,omitempty"`
	State             FindingState      `json:"state"`
	Evidence          string            `json:"evidence,omitempty"`
	EvidenceSignature string            `json:"evidence_signature,omitempty"`
	DedupKey          string            `json:"dedup_key"`
	RemediationID     string            `json:"remediation_id,omitempty"`
	FirstDetected     time.Time         `json:"first_detected"`
	LastDetected      time.Time         `json:"last_detected"`
	LastVerified      time.Time         `json:"last_verified"`
	FixedAt           *time.Time        `json:"fixed_at,omitempty"`
	ReopenedCount     int               `json:"reopened_count"`
}

// ComputeDedupKey generates the authoritative dedup key (§6.5):
// hash(asset_id, plugin_id, port, protocol, evidence_signature)
func (f *Finding) ComputeDedupKey() string {
	raw := fmt.Sprintf("%s:%s:%d:%s:%s", f.AssetID, f.PluginID, f.Port, strings.ToLower(f.Protocol), f.EvidenceSignature)
	h := sha256.Sum256([]byte(raw))
	f.DedupKey = hex.EncodeToString(h[:16])
	return f.DedupKey
}

// RemediationItem groups multiple related findings by actionable fix (§50.1).
type RemediationItem struct {
	ID                string               `json:"id"`
	TenantID          string               `json:"tenant_id"`
	Title             string               `json:"title"`
	Summary           string               `json:"summary"`
	ActionType        string               `json:"action_type"` // package_upgrade, config_change, service_restart, cert_renewal
	TargetAssets      []string             `json:"target_assets"`
	TargetAssetNames  []string             `json:"target_asset_names"`
	FindingIDs        []string             `json:"finding_ids"`
	FindingCount      int                  `json:"finding_count"`
	MaxSeverity       string               `json:"max_severity"`
	TotalRiskRemoved  float64              `json:"total_risk_removed"`
	EstimatedEffort   string               `json:"estimated_effort"` // e.g. "~15 min", "~2 hours"
	CLIScript         string               `json:"cli_script"`       // Copy-pasteable shell command
	AnsibleSnippet    string               `json:"ansible_snippet"`  // Ansible playbook task
	DockerfileSnippet string               `json:"dockerfile_snippet,omitempty"`
	VerificationCmd   string               `json:"verification_cmd"` // Targeted command or probe
	Status            string               `json:"status"`           // open, in_progress, verified_fixed
	CreatedAt         time.Time            `json:"created_at"`
	UpdatedAt         time.Time            `json:"updated_at"`
}

// ScanPolicy defines scanning parameters and safety bounds (§4.2, §57).
type ScanPolicy struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	SafetyCeiling     SafetyClass `json:"safety_ceiling"`
	PortRange         string      `json:"port_range"` // "top1000", "top100", "all", or comma list
	MaxPPS            int         `json:"max_pps"`    // Max packets per second rate limit
	HostTimeoutSec    int         `json:"host_timeout_sec"`
	EnablePing        bool        `json:"enable_ping"`
	EnableSYNScan     bool        `json:"enable_syn_scan"`
	EnableTLSProbe    bool        `json:"enable_tls_probe"`
	EnableReachability bool       `json:"enable_reachability"`
	FragileAvoidance  bool        `json:"fragile_avoidance"`
}

// ScanRun models a scan execution (§6.6, §58).
type ScanRun struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	NetworkZoneID  string            `json:"network_zone_id"`
	PolicyID       string            `json:"policy_id"`
	ScopeID        string            `json:"scope_id"`
	Status         string            `json:"status"` // pending, running, completed, partial, failed, cancelled
	Targets        []string          `json:"targets"`
	StartTime      time.Time         `json:"start_time"`
	EndTime        *time.Time        `json:"end_time,omitempty"`
	ProgressPct    int               `json:"progress_pct"`
	CurrentPhase   string            `json:"current_phase"`
	HostsTargeted  int               `json:"hosts_targeted"`
	HostsLive      int               `json:"hosts_live"`
	HostsAssessed  int               `json:"hosts_assessed"`
	Unreachable    int               `json:"unreachable"`
	TotalFindings  int               `json:"total_findings"`
	CriticalCount  int               `json:"critical_count"`
	HighCount      int               `json:"high_count"`
	MediumCount    int               `json:"medium_count"`
	LowCount       int               `json:"low_count"`
	InfoCount      int               `json:"info_count"`
	DataQuality    DataQualityReport `json:"data_quality"`
	Diff           DiffSummary       `json:"diff"`
}

// DataQualityReport highlights scan completeness and blind spots (§68.4).
type DataQualityReport struct {
	UncredentialedHosts int      `json:"uncredentialed_hosts"`
	FailedCredentials   int      `json:"failed_credentials"`
	FragileDevicesSeen  int      `json:"fragile_devices_seen"`
	TimedOutHosts       []string `json:"timed_out_hosts,omitempty"`
}

// DiffSummary provides the four-column defensible scan diff (§68.4).
type DiffSummary struct {
	NewFindings       int `json:"new_findings"`
	ConfirmedFixed    int `json:"confirmed_fixed"`
	ReopenedFindings  int `json:"reopened_findings"`
	UnverifiedAbsent  int `json:"unverified_absent"`
}

// IsIPv4 returns true if string is valid IPv4.
func IsIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}
