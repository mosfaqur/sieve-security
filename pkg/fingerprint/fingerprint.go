package fingerprint

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/mosfaqur/sieve-security/pkg/models"
	"github.com/mosfaqur/sieve-security/pkg/scope"
)

var (
	reOpenSSH = regexp.MustCompile(`^SSH-2\.0-OpenSSH[_-]([0-9a-zA-Z\.\-]+)`)
	reNginx   = regexp.MustCompile(`nginx/([0-9\.]+)`)
	reApache  = regexp.MustCompile(`Apache/([0-9\.]+)`)
	reProFTPD = regexp.MustCompile(`ProFTPD\s+([0-9\.]+[a-zA-Z0-9_-]*)`)
	rePostfix = regexp.MustCompile(`Postfix`)
	reMySQL   = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9_\-\.]*)`)
	reVarnish = regexp.MustCompile(`(?i)varnish`)
)

// Fingerprinter interrogates open ports to determine service, product, version, and TLS configuration.
type Fingerprinter struct {
	guard   *scope.ScopeGuard
	timeout time.Duration
}

// NewFingerprinter creates a service interrogator with scope checking.
func NewFingerprinter(guard *scope.ScopeGuard, timeout time.Duration) *Fingerprinter {
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	return &Fingerprinter{
		guard:   guard,
		timeout: timeout,
	}
}

// Identify probes an open port and returns an enriched Service entity.
func (f *Fingerprinter) Identify(ctx context.Context, targetIP net.IP, port int) (*models.Service, error) {
	if err := f.guard.PreFlightSocketCheck(targetIP); err != nil {
		return nil, err
	}

	svc := &models.Service{
		Port:      port,
		Protocol:  "tcp",
		State:     "open",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	// 1. Check TLS capability first if likely TLS port or upon testing
	isTLS := port == 443 || port == 8443 || port == 993 || port == 995 || port == 636
	if isTLS || f.probeTLS(targetIP, port, svc) {
		svc.Tunnel = "tls"
	}

	// 2. Protocol-specific interrogation
	switch port {
	case 21:
		f.probeFTP(targetIP, port, svc)
	case 22:
		f.probeSSH(targetIP, port, svc)
	case 25, 587:
		f.probeSMTP(targetIP, port, svc)
	case 80, 443, 6081, 8080, 8443:
		f.probeHTTP(targetIP, port, svc)
	case 3306, 33060:
		f.probeMySQL(targetIP, port, svc)
	case 6379:
		f.probeRedis(targetIP, port, svc)
	default:
		// Generic banner grab fallback
		f.probeGenericBanner(targetIP, port, svc)
	}

	// Calculate banner hash for change tracking
	if svc.Banner != "" {
		h := sha256.Sum256([]byte(svc.Banner))
		svc.BannerHash = hex.EncodeToString(h[:16])
	}

	if svc.ServiceName == "" {
		svc.ServiceName = deriveDefaultServiceName(port)
	}

	return svc, nil
}

func (f *Fingerprinter) probeTLS(ip net.IP, port int, svc *models.Service) bool {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conf := &tls.Config{
		InsecureSkipVerify: true, // Scanner must interrogate self-signed & invalid certs
	}

	dialer := &net.Dialer{Timeout: f.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsInfo := &models.TLSInfo{
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}

	switch state.Version {
	case tls.VersionTLS13:
		tlsInfo.Version = "TLS 1.3"
	case tls.VersionTLS12:
		tlsInfo.Version = "TLS 1.2"
	case tls.VersionTLS11:
		tlsInfo.Version = "TLS 1.1"
		tlsInfo.WeakCiphersFound = append(tlsInfo.WeakCiphersFound, "Deprecated protocol TLS 1.1")
	case tls.VersionTLS10:
		tlsInfo.Version = "TLS 1.0"
		tlsInfo.WeakCiphersFound = append(tlsInfo.WeakCiphersFound, "Deprecated protocol TLS 1.0")
	default:
		tlsInfo.Version = fmt.Sprintf("TLS 0x%04x", state.Version)
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.CertSubject = cert.Subject.CommonName
		if cert.Issuer.CommonName != "" {
			tlsInfo.CertIssuer = cert.Issuer.CommonName
		} else {
			tlsInfo.CertIssuer = cert.Issuer.String()
		}
		tlsInfo.CertSANs = cert.DNSNames
		tlsInfo.CertNotAfter = cert.NotAfter
		tlsInfo.IsExpired = time.Now().After(cert.NotAfter)
		tlsInfo.DaysUntilExpiraton = int(time.Until(cert.NotAfter).Hours() / 24)

		if cert.Issuer.String() == cert.Subject.String() {
			tlsInfo.IsSelfSigned = true
		}
	}

	svc.TLSInfo = tlsInfo
	return true
}

func (f *Fingerprinter) probeSSH(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "ssh"
	svc.Product = "OpenSSH"
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	svc.Banner = strings.TrimSpace(banner)

	if m := reOpenSSH.FindStringSubmatch(svc.Banner); len(m) > 1 {
		svc.Version = m[1]
		svc.CPE = []string{fmt.Sprintf("cpe:/a:openbsd:openssh:%s", m[1])}
	}
}

func (f *Fingerprinter) probeFTP(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "ftp"
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	svc.Banner = strings.TrimSpace(line)

	if m := reProFTPD.FindStringSubmatch(svc.Banner); len(m) > 1 {
		svc.Product = "ProFTPD"
		svc.Version = m[1]
		svc.CPE = []string{fmt.Sprintf("cpe:/a:proftpd:proftpd:%s", m[1])}
	}
}

func (f *Fingerprinter) probeSMTP(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "smtp"
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	svc.Banner = strings.TrimSpace(line)

	if rePostfix.MatchString(svc.Banner) {
		svc.Product = "Postfix"
		svc.CPE = []string{"cpe:/a:postfix:postfix"}
	}
}

func (f *Fingerprinter) probeHTTP(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "http"
	scheme := "http"
	if svc.Tunnel == "tls" {
		scheme = "https"
		svc.ServiceName = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip.String(), port)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: f.timeout,
		}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   f.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects, inspect original response headers
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Sieve-Security/1.0 (+https://sieve-security.org)")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	viaHeader := resp.Header.Get("Via")
	svc.Banner = fmt.Sprintf("Server: %s; Status: %d", serverHeader, resp.StatusCode)

	if viaHeader != "" && reVarnish.MatchString(viaHeader) {
		svc.ExtraInfo = fmt.Sprintf("Proxy: %s", viaHeader)
	}

	if m := reNginx.FindStringSubmatch(serverHeader); len(m) > 1 {
		svc.Product = "nginx"
		svc.Version = m[1]
		svc.CPE = []string{fmt.Sprintf("cpe:/a:f5:nginx:%s", m[1])}
	} else if m := reApache.FindStringSubmatch(serverHeader); len(m) > 1 {
		svc.Product = "Apache httpd"
		svc.Version = m[1]
		svc.CPE = []string{fmt.Sprintf("cpe:/a:apache:http_server:%s", m[1])}
	} else if strings.Contains(serverHeader, "nginx") {
		svc.Product = "nginx"
		svc.CPE = []string{"cpe:/a:f5:nginx"}
	}
}

func (f *Fingerprinter) probeMySQL(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "mysql"
	svc.Product = "MySQL"
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// MySQL initial handshake packet: packet length (3 bytes), sequence id (1 byte), proto version (1 byte), server version (null terminated string)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return
	}

	// Server version string starts at byte index 5 until null byte (0x00)
	payload := buf[4:n]
	nullIdx := -1
	for i := 1; i < len(payload); i++ {
		if payload[i] == 0x00 {
			nullIdx = i
			break
		}
	}

	if nullIdx > 1 {
		verStr := string(payload[1:nullIdx])
		svc.Banner = fmt.Sprintf("MySQL Handshake: %s", verStr)
		if m := reMySQL.FindStringSubmatch(verStr); len(m) > 1 {
			svc.Version = m[1]
			svc.CPE = []string{fmt.Sprintf("cpe:/a:oracle:mysql:%s", m[1])}
		}
	}
}

func (f *Fingerprinter) probeRedis(ip net.IP, port int, svc *models.Service) {
	svc.ServiceName = "redis"
	svc.Product = "Redis"
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Send PING command
	_, _ = conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		svc.Banner = strings.TrimSpace(string(buf[:n]))
	}
}

func (f *Fingerprinter) probeGenericBanner(ip net.IP, port int, svc *models.Service) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		svc.Banner = strings.TrimSpace(string(buf[:n]))
	}
}

func deriveDefaultServiceName(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgres"
	case 6081:
		return "varnish"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 11211:
		return "memcached"
	default:
		return "unknown"
	}
}
