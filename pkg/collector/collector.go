package collector

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	reSSLine = regexp.MustCompile(`^(tcp|udp)\s+\S+\s+\S+\s+\S+\s+(\S+):(\d+)\s+\S+\s+users:\(\("([^"]+)",pid=(\d+),`)
)

// HostAuditFact encapsulates facts gathered during authenticated assessment (§26).
type HostAuditFact struct {
	Hostname       string
	Kernel         string
	OSName         string
	OSVersion      string
	OSID           string // ubuntu, debian, rhel, etc.
	Packages       map[string]string // package name -> version
	ListeningPorts []ListeningSocket
	Processes      []HostProcess
}

// ListeningSocket captures process binding on a network socket.
type ListeningSocket struct {
	Protocol string
	BindIP   string
	Port     int
	Process  string
	PID      int
}

// HostProcess captures a running process.
type HostProcess struct {
	PID     int
	User    string
	Command string
}

// SSHCollector executes read-only inspection commands over SSH (§26.1).
type SSHCollector struct {
	Host    string
	Port    int
	User    string
	Timeout time.Duration
	Config  *ssh.ClientConfig
}

// NewSSHCollectorWithKey creates an SSH collector with private key auth.
func NewSSHCollectorWithKey(host string, port int, user string, keyBytes []byte, timeout time.Duration) (*SSHCollector, error) {
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH private key: %w", err)
	}

	conf := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	return &SSHCollector{
		Host:    host,
		Port:    port,
		User:    user,
		Timeout: timeout,
		Config:  conf,
	}, nil
}

// NewSSHCollectorWithPassword creates an SSH collector with password auth.
func NewSSHCollectorWithPassword(host string, port int, user, password string, timeout time.Duration) *SSHCollector {
	conf := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	return &SSHCollector{
		Host:    host,
		Port:    port,
		User:    user,
		Timeout: timeout,
		Config:  conf,
	}
}

// NewSSHCollectorAuto attempts key auth from specified or default paths, falling back to password.
func NewSSHCollectorAuto(host string, port int, user, password, customKeyPath string, timeout time.Duration) (*SSHCollector, error) {
	var authMethods []ssh.AuthMethod

	// Check custom key path first
	candidateKeys := []string{}
	if customKeyPath != "" {
		candidateKeys = append(candidateKeys, customKeyPath)
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		candidateKeys = append(candidateKeys,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
		)
	}

	for _, keyPath := range candidateKeys {
		if keyBytes, err := os.ReadFile(keyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(keyBytes); err == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
				break
			}
		}
	}

	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no valid SSH keys or passwords available for user %s", user)
	}

	conf := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	return &SSHCollector{
		Host:    host,
		Port:    port,
		User:    user,
		Timeout: timeout,
		Config:  conf,
	}, nil
}

// Collect gathers authoritative OS info, packages, and listening sockets.
func (c *SSHCollector) Collect(ctx context.Context) (*HostAuditFact, error) {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	client, err := ssh.Dial("tcp", addr, c.Config)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed to %s: %w", addr, err)
	}
	defer client.Close()

	fact := &HostAuditFact{
		Packages: make(map[string]string),
	}

	// 1. Gather OS release and kernel
	osOut, err := runSSHCmd(client, "cat /etc/os-release 2>/dev/null; echo '---'; uname -r; echo '---'; hostname")
	if err == nil {
		parts := strings.Split(osOut, "---")
		if len(parts) >= 1 {
			parseOSRelease(parts[0], fact)
		}
		if len(parts) >= 2 {
			fact.Kernel = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 {
			fact.Hostname = strings.TrimSpace(parts[2])
		}
	}

	// 2. Gather listening sockets with process attribution
	ssOut, err := runSSHCmd(client, "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
	if err == nil {
		fact.ListeningPorts = parseListeningSockets(ssOut)
	}

	// 3. Gather installed packages based on distro family
	if fact.OSID == "ubuntu" || fact.OSID == "debian" {
		pkgOut, err := runSSHCmd(client, "dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null")
		if err == nil {
			parsePackageList(pkgOut, fact.Packages)
		}
	} else {
		// RPM fallback
		pkgOut, err := runSSHCmd(client, "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null")
		if err == nil {
			parsePackageList(pkgOut, fact.Packages)
		}
	}

	return fact, nil
}

func runSSHCmd(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	if err != nil {
		return "", fmt.Errorf("cmd '%s' failed: %v, stderr: %s", cmd, err, stderr.String())
	}

	return stdout.String(), nil
}

func parseOSRelease(out string, fact *HostAuditFact) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			fact.OSID = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "NAME=") {
			fact.OSName = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			fact.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
}

func parseListeningSockets(out string) []ListeningSocket {
	var sockets []ListeningSocket
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		m := reSSLine.FindStringSubmatch(line)
		if len(m) >= 6 {
			proto := m[1]
			bindIP := m[2]
			port, _ := strconv.Atoi(m[3])
			proc := m[4]
			pid, _ := strconv.Atoi(m[5])

			sockets = append(sockets, ListeningSocket{
				Protocol: proto,
				BindIP:   bindIP,
				Port:     port,
				Process:  proc,
				PID:      pid,
			})
		}
	}
	return sockets
}

func parsePackageList(out string, pkgs map[string]string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkgs[fields[0]] = fields[1]
		}
	}
}
