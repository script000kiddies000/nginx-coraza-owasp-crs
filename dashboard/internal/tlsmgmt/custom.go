package tlsmgmt

import (
	"fmt"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

// SaveCustomCertificate writes PEM to disk and stores metadata in Bolt.
func SaveCustomCertificate(db *bbolt.DB, domain, certPEM, keyPEM, chainPEM string) (models.TLSCertificate, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return models.TLSCertificate{}, fmt.Errorf("domain is required")
	}
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return models.TLSCertificate{}, fmt.Errorf("certificate and private key PEM are required")
	}

	id := NewCertID()
	crtPath, keyPath := CustomCertPaths(id)
	if err := WritePEMFiles(crtPath, keyPath, certPEM, keyPEM, chainPEM); err != nil {
		return models.TLSCertificate{}, err
	}

	issuer, na, err := CertMetaFromFile(crtPath)
	if err != nil {
		issuer = "Custom"
		na = time.Now().Add(365 * 24 * time.Hour)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := models.TLSCertificate{
		ID:        id,
		Domain:    domain,
		Source:    "custom",
		CertPath:  crtPath,
		KeyPath:   keyPath,
		Issuer:    issuer,
		NotAfter:  na.UTC().Format(time.RFC3339),
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	return rec, store.SaveTLSCertificate(db, rec)
}
