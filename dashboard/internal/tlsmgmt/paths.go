package tlsmgmt

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

func SSLDir() string {
	if p := os.Getenv("FLUX_SSL_DIR"); p != "" {
		return p
	}
	return "/etc/nginx/ssl_certs"
}

func ACMEWebroot() string {
	if p := os.Getenv("FLUX_ACME_WEBROOT"); p != "" {
		return p
	}
	return "/var/www/certbot"
}

func DomainToFileBase(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var b strings.Builder
	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "cert"
	}
	return s
}

func NewCertID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "tls-" + hex.EncodeToString(buf)
}

func LECertPaths(domain string) (crt, key string) {
	base := "le_" + DomainToFileBase(domain)
	dir := SSLDir()
	return filepath.Join(dir, base+".crt"), filepath.Join(dir, base+".key")
}

func CustomCertPaths(id string) (crt, key string) {
	dir := SSLDir()
	safe := strings.TrimPrefix(id, "tls-")
	if safe == "" {
		safe = "x"
	}
	return filepath.Join(dir, "cust_"+safe+".crt"), filepath.Join(dir, "cust_"+safe+".key")
}
