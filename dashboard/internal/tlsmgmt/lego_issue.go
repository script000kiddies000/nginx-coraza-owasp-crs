package tlsmgmt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"

	bbolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func caDirectoryURL(staging bool) string {
	if staging {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return "https://acme-v02.api.letsencrypt.org/directory"
}

// ObtainLetsEncrypt issues a cert via HTTP-01 webroot. Persists ACME account in settings.
func ObtainLetsEncrypt(db *bbolt.DB, domain, email string, staging bool) (models.TLSCertificate, error) {
	domain = stringsTrimDomain(domain)
	email = strings.TrimSpace(email)
	if domain == "" || email == "" {
		return models.TLSCertificate{}, fmt.Errorf("domain and email are required")
	}

	if err := os.MkdirAll(ACMEWebroot(), 0755); err != nil {
		return models.TLSCertificate{}, fmt.Errorf("webroot: %w", err)
	}

	priv, acct, err := loadOrCreateACMEKey(db, email)
	if err != nil {
		return models.TLSCertificate{}, err
	}

	user := &acmeUser{Email: email, key: priv, Registration: acct}
	cfg := lego.NewConfig(user)
	cfg.CADirURL = caDirectoryURL(staging)

	client, err := lego.NewClient(cfg)
	if err != nil {
		return models.TLSCertificate{}, err
	}

	prov, err := webroot.NewHTTPProvider(ACMEWebroot())
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("http-01 webroot: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(prov); err != nil {
		return models.TLSCertificate{}, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return models.TLSCertificate{}, fmt.Errorf("acme register: %w", err)
		}
	}
	user.Registration = reg
	if err := persistACMEAccount(db, email, priv, reg); err != nil {
		return models.TLSCertificate{}, err
	}

	req := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return models.TLSCertificate{}, fmt.Errorf("certificate obtain: %w", err)
	}

	crtPath, keyPath := LECertPaths(domain)
	certPEM := string(res.Certificate) + "\n"
	keyPEM := string(res.PrivateKey) + "\n"
	if err := WritePEMFiles(crtPath, keyPath, certPEM, keyPEM, ""); err != nil {
		return models.TLSCertificate{}, err
	}

	issuer, na, err := CertMetaFromFile(crtPath)
	if err != nil {
		issuer, na = "Let's Encrypt", time.Now().Add(90*24*time.Hour)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := models.TLSCertificate{
		ID:        NewCertID(),
		Domain:    domain,
		Source:    "letsencrypt",
		Email:     email,
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

func stringsTrimDomain(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func loadOrCreateACMEKey(db *bbolt.DB, email string) (crypto.PrivateKey, *registration.Resource, error) {
	st := store.GetACMEAccount(db)
	if st.PrivateKeyPEM != "" && strings.EqualFold(strings.TrimSpace(st.Email), email) {
		priv, err := decodePrivateKeyPEM(st.PrivateKeyPEM)
		if err != nil {
			return nil, nil, err
		}
		var reg *registration.Resource
		if st.RegistrationJSON != "" {
			_ = json.Unmarshal([]byte(st.RegistrationJSON), &reg)
		}
		return priv, reg, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, nil, nil
}

func persistACMEAccount(db *bbolt.DB, email string, priv crypto.PrivateKey, reg *registration.Resource) error {
	pemBytes, err := encodePrivateKeyPEM(priv)
	if err != nil {
		return err
	}
	var regJSON string
	if reg != nil {
		b, _ := json.Marshal(reg)
		regJSON = string(b)
	}
	return store.SaveACMEAccount(db, models.ACMEAccountData{
		Email:            email,
		PrivateKeyPEM:    string(pemBytes),
		RegistrationJSON: regJSON,
	})
}

func encodePrivateKeyPEM(priv crypto.PrivateKey) ([]byte, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func decodePrivateKeyPEM(s string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}
