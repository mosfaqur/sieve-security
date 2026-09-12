package reachability

import (
	"strings"

	"github.com/mosfaqur/sieve-security/pkg/collector"
	"github.com/mosfaqur/sieve-security/pkg/models"
)

// Evaluator computes Tier 1 and Tier 2 reachability proofs (§1.2, §38.4).
type Evaluator struct{}

// NewEvaluator creates a reachability evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateReachability correlates network service findings with authenticated host facts.
func (e *Evaluator) EvaluateReachability(
	finding *models.Finding,
	service *models.Service,
	facts *collector.HostAuditFact,
) models.ReachabilityState {
	if facts == nil {
		// No credentialed host facts available, default based on network exposure
		if finding.Port > 0 {
			return models.ReachabilityListeningProcess
		}
		return models.ReachabilityUnknown
	}

	// 1. Locate listening socket matching the finding's port
	var matchingSocket *collector.ListeningSocket
	for _, sock := range facts.ListeningPorts {
		if sock.Port == finding.Port {
			matchingSocket = &sock
			break
		}
	}

	// If no socket matches this port, but service was seen externally
	if matchingSocket == nil {
		if finding.Port > 0 {
			return models.ReachabilityListeningProcess
		}
		// If it's a software package finding, check if any process is running
		return e.checkPackageProcessState(finding, facts)
	}

	// Update service with process information discovered via Tier 1 reachability
	if service != nil {
		service.ProcessPID = matchingSocket.PID
		service.ProcessBinary = matchingSocket.Process
	}

	// Check if listening socket is network-accessible (0.0.0.0 or [::] or public IP)
	isPublicListener := matchingSocket.BindIP == "0.0.0.0" ||
		matchingSocket.BindIP == "[::]" ||
		matchingSocket.BindIP == "*" ||
		!isLocalhost(matchingSocket.BindIP)

	if isPublicListener {
		// Tier 1 reached: network-facing socket connected directly to running process
		return models.ReachabilityListeningAndLoaded
	}

	// Loopback / localhost only
	return models.ReachabilityListeningProcess
}

func (e *Evaluator) checkPackageProcessState(finding *models.Finding, facts *collector.HostAuditFact) models.ReachabilityState {
	// Extract probable package/binary names from finding or plugin ID
	targetPkg := strings.ToLower(finding.PluginID)

	// Check if any process matches
	for _, proc := range facts.Processes {
		cmd := strings.ToLower(proc.Command)
		if strings.Contains(cmd, targetPkg) {
			return models.ReachabilityInstalledRunning
		}
	}

	// If package is in installed packages list, but no process is running
	for pkg := range facts.Packages {
		if strings.Contains(strings.ToLower(pkg), targetPkg) {
			return models.ReachabilityInstalledNotRun
		}
	}

	return models.ReachabilityNotLoaded
}

func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "[::1]" || strings.HasPrefix(ip, "127.")
}
