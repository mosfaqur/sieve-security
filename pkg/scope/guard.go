package scope

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

var (
	ErrOutOfScope     = errors.New("destination target is outside authorized scope")
	ErrTargetExcluded = errors.New("destination target matches an explicit exclusion")
	ErrDNSRebinding   = errors.New("DNS resolution produced out-of-scope IP address")
	ErrScopeRevoked   = errors.New("scope authorization has been revoked or expired")
)

// ScopeGuard provides compiled trie and fast IP lookup for scope validation (§4.1).
type ScopeGuard struct {
	mu           sync.RWMutex
	ScopeID      string
	TenantID     string
	Active       bool
	allowedNets  []*net.IPNet
	allowedIPs   []net.IP
	allowedHosts []string
	excludeNets  []*net.IPNet
	excludeIPs   []net.IP
	excludeHosts []string
}

// NewScopeGuard creates an empty active guard.
func NewScopeGuard(scopeID, tenantID string) *ScopeGuard {
	return &ScopeGuard{
		ScopeID:  scopeID,
		TenantID: tenantID,
		Active:   true,
	}
}

// Compile compiles a models.Scope into high-performance in-memory lookup structures.
func Compile(s *models.Scope) (*ScopeGuard, error) {
	if s.Status != "active" && s.Status != "" {
		return nil, ErrScopeRevoked
	}

	guard := NewScopeGuard(s.ID, s.TenantID)

	// Process inclusion entries
	for _, entry := range s.Entries {
		val := strings.TrimSpace(entry.Value)
		if strings.Contains(val, "/") {
			_, ipNet, err := net.ParseCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR in scope entry '%s': %w", val, err)
			}
			guard.allowedNets = append(guard.allowedNets, ipNet)
		} else if ip := net.ParseIP(val); ip != nil {
			guard.allowedIPs = append(guard.allowedIPs, ip)
		} else {
			guard.allowedHosts = append(guard.allowedHosts, strings.ToLower(val))
		}
	}

	// Process exclusion entries
	for _, entry := range s.Exclusions {
		val := strings.TrimSpace(entry.Value)
		if strings.Contains(val, "/") {
			_, ipNet, err := net.ParseCIDR(val)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR in exclusion '%s': %w", val, err)
			}
			guard.excludeNets = append(guard.excludeNets, ipNet)
		} else if ip := net.ParseIP(val); ip != nil {
			guard.excludeIPs = append(guard.excludeIPs, ip)
		} else {
			guard.excludeHosts = append(guard.excludeHosts, strings.ToLower(val))
		}
	}

	return guard, nil
}

// IsIPAllowed checks if an IP is authorized and not explicitly excluded.
func (g *ScopeGuard) IsIPAllowed(ip net.IP) (bool, string) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.Active {
		return false, "scope is deactivated"
	}

	// 1. Check exclusions first (highest priority)
	for _, exNet := range g.excludeNets {
		if exNet.Contains(ip) {
			return false, fmt.Sprintf("IP %s matches exclusion subnet %s", ip, exNet.String())
		}
	}
	for _, exIP := range g.excludeIPs {
		if exIP.Equal(ip) {
			return false, fmt.Sprintf("IP %s matches explicit exclusion IP", ip)
		}
	}

	// If no inclusions defined, allow nothing unless wildcard
	if len(g.allowedNets) == 0 && len(g.allowedIPs) == 0 && len(g.allowedHosts) == 0 {
		return false, "no inclusion entries defined in scope"
	}

	// 2. Check inclusions
	for _, allowedNet := range g.allowedNets {
		if allowedNet.Contains(ip) {
			return true, "allowed by subnet"
		}
	}
	for _, allowedIP := range g.allowedIPs {
		if allowedIP.Equal(ip) {
			return true, "allowed by single IP"
		}
	}

	return false, fmt.Sprintf("IP %s not found in any authorized scope entry", ip)
}

// ValidateAndResolve resolves a target string and verifies every resolved IP is within scope.
// This directly enforces protection against DNS rebinding attacks (§4.1 #5).
func (g *ScopeGuard) ValidateAndResolve(target string) ([]net.IP, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return nil, errors.New("empty target")
	}

	// Check if target is a raw IP
	if ip := net.ParseIP(trimmed); ip != nil {
		allowed, reason := g.IsIPAllowed(ip)
		if !allowed {
			return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, ip.String(), reason)
		}
		return []net.IP{ip}, nil
	}

	// Check if target is a CIDR block
	if strings.Contains(trimmed, "/") {
		ip, ipNet, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid target CIDR: %w", err)
		}
		// Test network and broadcast
		allowed, reason := g.IsIPAllowed(ip)
		if !allowed {
			return nil, fmt.Errorf("%w: network %s (%s)", ErrOutOfScope, trimmed, reason)
		}
		var ips []net.IP
		// Enumerate usable IPs up to /24 (max 256 for batch safety)
		for curr := ip.Mask(ipNet.Mask); ipNet.Contains(curr); incIP(curr) {
			ips = append(ips, net.ParseIP(curr.String()))
			if len(ips) > 256 {
				break
			}
		}
		return ips, nil
	}

	// Target is a hostname - perform DNS lookup and verify every resolved IP
	ips, err := net.LookupIP(trimmed)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", trimmed, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP records found for host %s", trimmed)
	}

	var validIPs []net.IP
	for _, ip := range ips {
		// Prefer IPv4 for scan operations
		if ip.To4() != nil {
			allowed, reason := g.IsIPAllowed(ip)
			if !allowed {
				return nil, fmt.Errorf("%w: host %s resolved to %s (%s)", ErrDNSRebinding, trimmed, ip.String(), reason)
			}
			validIPs = append(validIPs, ip)
		}
	}

	if len(validIPs) == 0 {
		return nil, fmt.Errorf("no authorized IPv4 addresses for host %s", trimmed)
	}

	return validIPs, nil
}

// PreFlightSocketCheck provides the final backstop check right before socket writes (§4.1 #4).
func (g *ScopeGuard) PreFlightSocketCheck(ip net.IP) error {
	allowed, reason := g.IsIPAllowed(ip)
	if !allowed {
		return fmt.Errorf("%w: socket write to %s blocked (%s)", ErrOutOfScope, ip.String(), reason)
	}
	return nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
