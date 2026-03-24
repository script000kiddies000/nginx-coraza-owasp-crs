package tlsmgmt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func WritePEMFiles(crtPath, keyPath, certPEM, keyPEM, chainPEM string) error {
	certPEM = strings.TrimSpace(certPEM) + "\n"
	keyPEM = strings.TrimSpace(keyPEM) + "\n"
	fullCRT := certPEM
	if strings.TrimSpace(chainPEM) != "" {
		fullCRT += strings.TrimSpace(chainPEM) + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(crtPath), 0755); err != nil {
		return err
	}
	tmpC := crtPath + ".tmp"
	if err := os.WriteFile(tmpC, []byte(fullCRT), 0644); err != nil {
		return err
	}
	tmpK := keyPath + ".tmp"
	if err := os.WriteFile(tmpK, []byte(keyPEM), 0600); err != nil {
		_ = os.Remove(tmpC)
		return err
	}
	if err := os.Rename(tmpC, crtPath); err != nil {
		return err
	}
	return os.Rename(tmpK, keyPath)
}

// CertMetaFromPEM returns issuer CN/O and NotAfter from first certificate block.
func CertMetaFromFile(crtPath string) (issuer string, notAfter time.Time, err error) {
	b, err := os.ReadFile(crtPath)
	if err != nil {
		return "", time.Time{}, err
	}
	return CertMetaFromBytes(b)
}

func CertMetaFromBytes(pemData []byte) (issuer string, notAfter time.Time, err error) {
	var cert *x509.Certificate
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", time.Time{}, err
		}
		break
	}
	if cert == nil {
		return "", time.Time{}, fmt.Errorf("no certificate in PEM")
	}
	issuer = cert.Issuer.CommonName
	if issuer == "" && len(cert.Issuer.Organization) > 0 {
		issuer = cert.Issuer.Organization[0]
	}
	return issuer, cert.NotAfter, nil
}
