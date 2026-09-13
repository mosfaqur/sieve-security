package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/models"
	"github.com/mosfaqur/sieve-security/pkg/scope"
)

// DefaultTopPorts provides curated high-frequency ports from Appendix C.
var DefaultTopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 514, 587, 623, 636, 873, 902, 989, 990, 993, 995, 1099, 1433, 1521, 1723,
	1883, 2049, 2181, 2375, 2376, 2379, 3000, 3128, 3268, 3306, 3389, 4444, 4786,
	5000, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986, 6081, 6379, 6443, 7001,
	8000, 8006, 8009, 8080, 8081, 8088, 8089, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200,
	9300, 9443, 10000, 11211, 27017, 33060, 50000,
}

// DiscoveryPingPorts provides fast liveness check ports.
var DiscoveryPingPorts = []int{21, 22, 80, 443, 445, 3128, 3389, 8006, 8080, 8443}

// ParsePortSpec parses a port specification string (e.g. "top1000", "all", "1-65535", "22,80,443", "1-1024").
func ParsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "default" || spec == "top1000" {
		return DefaultTopPorts, nil
	}
	if spec == "all" || spec == "1-65535" {
		all := make([]int, 65535)
		for i := 1; i <= 65535; i++ {
			all[i-1] = i
		}
		return all, nil
	}

	seen := make(map[int]bool)
	var ports []int

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return DefaultTopPorts, nil
	}
	sort.Ints(ports)
	return ports, nil
}

// PortResult represents an individual port probe outcome.
type PortResult struct {
	Port     int
	Protocol string
	State    string // open, closed, filtered
	Latency  time.Duration
}

// ScanOptions configures the scanner behaviour.
type ScanOptions struct {
	Ports          []int
	MaxConcurrency int
	MaxPPS         int // Rate limiter ceiling (§13.1)
	Timeout        time.Duration
	SafetyCeiling  models.SafetyClass
	OnProgress     func(scanned, total, openFound int)
}

// Scanner performs scoped, rate-limited network probes.
type Scanner struct {
	guard *scope.ScopeGuard
}

// NewScanner initializes a scanner bound to a compiled ScopeGuard.
func NewScanner(guard *scope.ScopeGuard) *Scanner {
	return &Scanner{
		guard: guard,
	}
}

// CheckHostLiveness performs fast TCP ping against known discovery ports (§11.2).
func (s *Scanner) CheckHostLiveness(ctx context.Context, targetIP net.IP, timeout time.Duration) (bool, time.Duration) {
	// 1. Mandatory scope check
	if err := s.guard.PreFlightSocketCheck(targetIP); err != nil {
		return false, 0
	}

	start := time.Now()
	for _, port := range DiscoveryPingPorts {
		select {
		case <-ctx.Done():
			return false, 0
		default:
		}

		target := fmt.Sprintf("%s:%d", targetIP.String(), port)
		conn, err := net.DialTimeout("tcp", target, timeout)
		if err == nil {
			_ = conn.Close()
			return true, time.Since(start)
		}
	}

	return false, 0
}

// ScanPorts executes a concurrent port scan against a verified destination IP.
func (s *Scanner) ScanPorts(ctx context.Context, targetIP net.IP, opts ScanOptions) ([]PortResult, error) {
	// Pre-flight scope check on target
	if err := s.guard.PreFlightSocketCheck(targetIP); err != nil {
		return nil, err
	}

	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultTopPorts
	}

	concurrency := opts.MaxConcurrency
	if concurrency <= 0 {
		if len(ports) > 5000 {
			concurrency = 400
		} else if len(ports) > 500 {
			concurrency = 150
		} else {
			concurrency = 50
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		if len(ports) > 5000 {
			timeout = 750 * time.Millisecond
		} else {
			timeout = 1500 * time.Millisecond
		}
	}

	pps := opts.MaxPPS
	if pps <= 0 {
		if len(ports) > 5000 {
			pps = 3000
		} else {
			pps = 2000
		}
	}

	rateLimiter := time.NewTicker(time.Second / time.Duration(max(pps, 100)))
	defer rateLimiter.Stop()

	resultsChan := make(chan PortResult, len(ports))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	var scannedCount int64
	var openCount int64
	total := len(ports)

	for _, p := range ports {
		select {
		case <-ctx.Done():
			break
		default:
		}

		// Rate limiting step
		<-rateLimiter.C

		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			res := s.probeTCPPort(targetIP, port, timeout)
			sc := atomic.AddInt64(&scannedCount, 1)
			if res.State == "open" {
				oc := atomic.AddInt64(&openCount, 1)
				resultsChan <- res
				if opts.OnProgress != nil {
					opts.OnProgress(int(sc), total, int(oc))
				}
			} else if opts.OnProgress != nil && sc%250 == 0 {
				oc := atomic.LoadInt64(&openCount)
				opts.OnProgress(int(sc), total, int(oc))
			}
		}(p)
	}

	wg.Wait()
	close(resultsChan)

	var openPorts []PortResult
	for r := range resultsChan {
		openPorts = append(openPorts, r)
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	return openPorts, nil
}

func (s *Scanner) probeTCPPort(ip net.IP, port int, timeout time.Duration) PortResult {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	start := time.Now()

	// Double-enforcement check right before socket creation
	if err := s.guard.PreFlightSocketCheck(ip); err != nil {
		return PortResult{Port: port, Protocol: "tcp", State: "filtered"}
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := time.Since(start)

	if err != nil {
		// Could differentiate between reset (closed) and timeout (filtered)
		return PortResult{Port: port, Protocol: "tcp", State: "closed", Latency: latency}
	}
	_ = conn.Close()

	return PortResult{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Latency:  latency,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
