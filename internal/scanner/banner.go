package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ServiceInfo is the result of probing one open port for what's actually
// listening on it. This is banner-grabbing, not nmap's probe/signature
// database: it reads whatever the service volunteers (or, for HTTP/TLS,
// asks a minimal question) and reports that back verbatim. It correctly
// identifies most common services and their version strings, but a service
// that doesn't advertise a version in its banner will only get the
// conventional name for its port.
type ServiceInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
}

var httpPorts = map[int]bool{
	80: true, 8000: true, 8008: true, 8080: true, 8081: true,
	8083: true, 8888: true, 9000: true, 9999: true, 3000: true,
}

var tlsPorts = map[int]bool{
	443: true, 8443: true, 993: true, 995: true, 465: true, 990: true,
}

// DetectService probes one host:port and reports its best guess at what's
// running there, within timeout.
func DetectService(ctx context.Context, ip string, port int, timeout time.Duration) ServiceInfo {
	info := ServiceInfo{Port: port, Service: PortName(port)}

	if tlsPorts[port] {
		if banner, ok := tlsBanner(ip, port, timeout); ok {
			info.TLS = true
			info.Banner = banner
			return info
		}
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if httpPorts[port] {
		if banner := httpServerBanner(conn, ip); banner != "" {
			info.Banner = banner
			info.Service = "HTTP"
		}
		return info
	}

	// Many services (SSH, FTP, SMTP, POP3/IMAP, MySQL, Redis, and plenty of
	// unlisted custom daemons) greet first, before the client says
	// anything -- try reading one line; it costs nothing but the timeout
	// if the service instead waits for the client to speak first.
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if err == nil && line != "" {
		info.Banner = truncate(line, 140)
		if guess := guessServiceFromBanner(line); guess != "" {
			info.Service = guess
		}
	}
	return info
}

func tlsBanner(ip string, port int, timeout time.Duration) (string, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- inspecting the peer cert we're shown, not verifying identity
	if err != nil {
		return "", false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	version := tlsVersionName(state.Version)
	if len(state.PeerCertificates) == 0 {
		return version, true
	}
	cert := state.PeerCertificates[0]
	cn := cert.Subject.CommonName
	if cn == "" && len(cert.DNSNames) > 0 {
		cn = cert.DNSNames[0]
	}
	if cn == "" {
		return version, true
	}
	return fmt.Sprintf("%s, cert CN: %s", version, cn), true
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "TLS"
	}
}

func httpServerBanner(conn net.Conn, host string) string {
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	reader := bufio.NewReader(conn)
	var statusLine, server string
	for i := 0; i < 40; i++ {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if statusLine == "" && line != "" {
			statusLine = line
		}
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server = strings.TrimSpace(line[len("server:"):])
		}
		if err != nil || line == "" {
			break
		}
	}
	if server != "" {
		return server
	}
	return statusLine
}

// guessServiceFromBanner recognizes a handful of very common greeting
// formats so the service name shown is more specific than just "the
// well-known name for this port number".
func guessServiceFromBanner(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.HasPrefix(l, "ssh-"):
		return "SSH"
	case strings.Contains(l, "esmtp") || (strings.HasPrefix(l, "220") && strings.Contains(l, "smtp")):
		return "SMTP"
	case strings.HasPrefix(l, "220") && strings.Contains(l, "ftp"):
		return "FTP"
	case strings.HasPrefix(l, "+ok") || strings.Contains(l, "pop3"):
		return "POP3"
	case strings.HasPrefix(l, "* ok") && strings.Contains(l, "imap"):
		return "IMAP"
	case strings.Contains(l, "mysql") || strings.Contains(l, "mariadb"):
		return "MySQL/MariaDB"
	case strings.HasPrefix(l, "-noauth") || strings.HasPrefix(l, "-err") || strings.HasPrefix(l, "-denied"):
		return "Redis"
	default:
		return ""
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
