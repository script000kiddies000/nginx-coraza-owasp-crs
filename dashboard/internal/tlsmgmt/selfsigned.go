package tlsmgmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

// GenerateSelfSignedCertificate creates a built-in self-signed cert and stores it
// as managed TLS certificate (source=selfsigned).
func GenerateSelfSignedCertificate(db *bbolt.DB, domain string, validDays int) (models.TLSCertificate, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return models.TLSCertificate{}, fmt.Errorf("domain is required")
	}
	if validDays <= 0 {
		validDays = 365
	}
	if validDays > 3650 {
		validDays = 3650
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("generate private key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("generate serial: %w", err)
	}

	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Flux WAF Self-Signed"},
		},
		Issuer:                pkix.Name{CommonName: "Flux WAF Self-Signed CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(domain); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
	} else {
		tpl.DNSNames = append(tpl.DNSNames, domain)
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("create self-signed cert: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	id := NewCertID()
	crtPath, keyPath := CustomCertPaths(id)
	if err := WritePEMFiles(crtPath, keyPath, certPEM, keyPEM, ""); err != nil {
		return models.TLSCertificate{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := models.TLSCertificate{
		ID:        id,
		Domain:    domain,
		Source:    "selfsigned",
		CertPath:  crtPath,
		KeyPath:   keyPath,
		Issuer:    "Flux WAF Self-Signed",
		NotAfter:  notAfter.Format(time.RFC3339),
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	return rec, store.SaveTLSCertificate(db, rec)
}

