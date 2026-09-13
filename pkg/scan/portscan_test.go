package scan

import (
	"reflect"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantLen int
		wantErr bool
	}{
		{"default", "", len(DefaultTopPorts), false},
		{"top1000", "top1000", len(DefaultTopPorts), false},
		{"all ports", "all", 65535, false},
		{"range 1-65535", "1-65535", 65535, false},
		{"single ports", "22,80,443", 3, false},
		{"ranges and ports", "22,80-82,443", 5, false},
		{"invalid port", "99999", 0, true},
		{"invalid range", "500-100", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePortSpec(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("ParsePortSpec(%q) len = %d, wantLen %d", tt.spec, len(got), tt.wantLen)
			}
		})
	}

	// Verify exact ports for range
	p, err := ParsePortSpec("22, 80-82, 443")
	if err != nil {
		t.Fatal(err)
	}
	expected := []int{22, 80, 81, 82, 443}
	if !reflect.DeepEqual(p, expected) {
		t.Errorf("got %v, want %v", p, expected)
	}
}
