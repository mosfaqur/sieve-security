package plugins

import (
	"github.com/mosfaqur/sieve-security/pkg/models"
)

// PluginDef defines the Declarative YAML Plugin DSL schema specified in Appendix A.
type PluginDef struct {
	ID            string         `yaml:"id"`
	SchemaVersion int            `yaml:"schema_version"`
	Info          PluginInfo     `yaml:"info"`
	Requires      PluginRequires `yaml:"requires"`
	Variables     map[string]any `yaml:"variables,omitempty"`
	Collect       []CollectItem  `yaml:"collect,omitempty"`
	MatchersCond  string         `yaml:"matchers_condition,omitempty"` // and | or
	Matchers      []MatcherItem  `yaml:"matchers"`
	Extract       map[string]any `yaml:"extract,omitempty"`
	Emit          EmitDef        `yaml:"emit"`
}

// PluginInfo encapsulates finding metadata.
type PluginInfo struct {
	Name               string                 `yaml:"name"`
	Family             string                 `yaml:"family"`
	Severity           string                 `yaml:"severity"` // critical, high, medium, low, info
	CVE                []string               `yaml:"cve,omitempty"`
	CWE                []string               `yaml:"cwe,omitempty"`
	References         []string               `yaml:"references,omitempty"`
	Description        string                 `yaml:"description"`
	Remediation        string                 `yaml:"remediation"`
	Safety             models.SafetyClass     `yaml:"safety"` // passive, active-safe, active-noisy, intrusive, destructive
	Method             models.DetectionMethod `yaml:"method"`
	Confidence         models.ConfidenceTier  `yaml:"confidence"`
	Cost               string                 `yaml:"cost,omitempty"`
	TimeoutSeconds     int                    `yaml:"timeout_seconds,omitempty"`
	FalsePositiveNotes string                 `yaml:"false_positive_notes,omitempty"`
}

// PluginRequires defines execution gating.
type PluginRequires struct {
	Service     []string `yaml:"service,omitempty"`
	Ports       []int    `yaml:"ports,omitempty"`
	OSFamily    []string `yaml:"os_family,omitempty"`
	Credentials bool     `yaml:"credentials,omitempty"`
}

// CollectItem specifies a data collection operation.
type CollectItem struct {
	ID     string `yaml:"id"`
	Type   string `yaml:"type"` // http, banner, tls, package, command
	Path   string `yaml:"path,omitempty"`
	Method string `yaml:"method,omitempty"`
}

// MatcherItem specifies a condition evaluated against collected data.
type MatcherItem struct {
	Type      string `yaml:"type"` // banner, version, http-status, http-header, tls, package
	Negative  bool   `yaml:"negative,omitempty"`
	Pattern   string `yaml:"pattern,omitempty"`
	Var       string `yaml:"var,omitempty"`
	Ecosystem string `yaml:"ecosystem,omitempty"` // semver, dpkg, rpm, generic
	Range     string `yaml:"range,omitempty"`     // e.g. "< 3.0.13", ">= 2.4.0, < 2.4.52"
	FixedIn   string `yaml:"fixed_in,omitempty"`
}

// EmitDef defines the resulting finding title, evidence, and deduplication signature.
type EmitDef struct {
	Title             string      `yaml:"title"`
	Evidence          EvidenceDef `yaml:"evidence,omitempty"`
	EvidenceSignature []string    `yaml:"evidence_signature,omitempty"`
}

// EvidenceDef defines evidence capture and redaction rules.
type EvidenceDef struct {
	Include  []string `yaml:"include,omitempty"`
	Redact   []string `yaml:"redact,omitempty"`
	MaxBytes int      `yaml:"max_bytes,omitempty"`
}
