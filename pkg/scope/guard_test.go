package scope

import (
	"net"
	"testing"

	"github.com/mosfaqur/sieve-security/pkg/models"
)

func TestScopeGuard(t *testing.T) {
	s := &models.Scope{
		ID:       "scope-test-1",
		TenantID: "tenant-default",
		Status:   "active",
		Entries: []models.ScopeEntry{
			{Kind: "cidr", Value: "192.168.1.0/24"},
			{Kind: "ip", Value: "10.0.0.5"},
		},
		Exclusions: []models.ScopeEntry{
			{Kind: "ip", Value: "192.168.1.1"},    // Gateway exclusion
			{Kind: "cidr", Value: "192.168.1.200/29"}, // Excluded range
		},
	}

	guard, err := Compile(s)
	if err != nil {
		t.Fatalf("failed to compile scope: %v", err)
	}

	// Test allowed IP (192.168.1.30 - our test VM)
	targetVM := net.ParseIP("192.168.1.30")
	allowed, reason := guard.IsIPAllowed(targetVM)
	if !allowed {
		t.Errorf("expected 192.168.1.30 to be allowed, got false (%s)", reason)
	}

	// Test excluded gateway (192.168.1.1)
	gw := net.ParseIP("192.168.1.1")
	allowed, reason = guard.IsIPAllowed(gw)
	if allowed {
		t.Errorf("expected 192.168.1.1 to be excluded, got allowed")
	}

	// Test excluded subnet member (192.168.1.202)
	exMember := net.ParseIP("192.168.1.202")
	allowed, reason = guard.IsIPAllowed(exMember)
	if allowed {
		t.Errorf("expected 192.168.1.202 to be excluded, got allowed")
	}

	// Test completely out-of-scope IP (8.8.8.8)
	extIP := net.ParseIP("8.8.8.8")
	allowed, reason = guard.IsIPAllowed(extIP)
	if allowed {
		t.Errorf("expected 8.8.8.8 to be blocked, got allowed")
	}

	// Test PreFlightSocketCheck
	if err := guard.PreFlightSocketCheck(targetVM); err != nil {
		t.Errorf("expected PreFlightSocketCheck to succeed on targetVM: %v", err)
	}
	if err := guard.PreFlightSocketCheck(extIP); err == nil {
		t.Errorf("expected PreFlightSocketCheck to fail on out-of-scope IP")
	}
}
