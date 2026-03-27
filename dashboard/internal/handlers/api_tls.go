package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	bbolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/tlsmgmt"
)

func hostsUsingCertID(db *bbolt.DB, certID string) []string {
	hosts, _ := store.ListHosts(db)
	var out []string
	for _, h := range hosts {
		if strings.TrimSpace(h.SSLCertID) == certID {
			out = append(out, h.Domain)
		}
	}
	return out
}

// APITLSList returns managed certificates + summary for UI.
func (app *App) APITLSList(w http.ResponseWriter, r *http.Request) {
	list, err := store.ListTLSCertificates(app.DB)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	exp30 := 0
	var leN, custN int
	rows := make([]map[string]any, 0, len(list))
	for _, c := range list {
		if c.Source == "letsencrypt" {
			leN++
		} else {
			custN++
		}
		if t, e := time.Parse(time.RFC3339, c.NotAfter); e == nil {
			if t.After(now) && !t.After(now.Add(30*24*time.Hour)) {
				exp30++
			}
		}
		used := hostsUsingCertID(app.DB, c.ID)
		rows = append(rows, map[string]any{
			"id":         c.ID,
			"domain":     c.Domain,
			"source":     c.Source,
			"email":      c.Email,
			"issuer":     c.Issuer,
			"not_after":  c.NotAfter,
			"status":     c.Status,
			"error_msg":  c.ErrorMsg,
			"cert_path":  c.CertPath,
			"key_path":   c.KeyPath,
			"created_at": c.CreatedAt,
			"used_by":    used,
			"days_left":  daysLeft(c.NotAfter),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"certificates": rows,
		"summary": map[string]any{
			"total":       len(list),
			"lets_encrypt": leN,
			"custom":       custN,
			"expiring_30d": exp30,
		},
		"acme_webroot": tlsmgmt.ACMEWebroot(),
		"ssl_dir":      tlsmgmt.SSLDir(),
	})
}

func daysLeft(notAfterRFC string) any {
	t, err := time.Parse(time.RFC3339, notAfterRFC)
	if err != nil {
		return nil
	}
	d := int(time.Until(t).Hours() / 24)
	return d
}

// APITLSCustom creates cert from pasted PEM.
func (app *App) APITLSCustom(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string `json:"domain"`
		CertPEM  string `json:"cert_pem"`
		KeyPEM   string `json:"key_pem"`
		ChainPEM string `json:"chain_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	rec, err := tlsmgmt.SaveCustomCertificate(app.DB, body.Domain, body.CertPEM, body.KeyPEM, body.ChainPEM)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, "cert saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, rec)
}

// APITLSLetsEncrypt issues cert via ACME HTTP-01.
func (app *App) APITLSLetsEncrypt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain  string `json:"domain"`
		Email   string `json:"email"`
		Staging bool   `json:"staging"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if os.Getenv("FLUX_ACME_STAGING") == "1" || os.Getenv("FLUX_ACME_STAGING") == "true" {
		body.Staging = true
	}
	rec, err := tlsmgmt.ObtainLetsEncrypt(app.DB, body.Domain, body.Email, body.Staging)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, "cert issued but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, rec)
}

// APITLSSelfSigned generates self-signed certificate for local/testing use.
func (app *App) APITLSSelfSigned(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Days   int    `json:"days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	rec, err := tlsmgmt.GenerateSelfSignedCertificate(app.DB, body.Domain, body.Days)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, "certificate generated but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, rec)
}

// APITLSDelete removes cert files and DB record if not in use.
func (app *App) APITLSDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		jsonError(w, "id required", http.StatusBadRequest)
		return
	}
	used := hostsUsingCertID(app.DB, id)
	if len(used) > 0 {
		jsonError(w, fmt.Sprintf("certificate in use by hosts: %s", strings.Join(used, ", ")), http.StatusConflict)
		return
	}
	c, err := store.GetTLSCertificate(app.DB, id)
	if err != nil {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	_ = os.Remove(c.CertPath)
	_ = os.Remove(c.KeyPath)
	if err := store.DeleteTLSCertificate(app.DB, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = nginx.ReloadNginx()
	jsonOK(w, map[string]string{"deleted": id})
}

// resolveHostSSL fills SSLCert/SSLKey from ssl_cert_id when enabled.
func resolveHostSSL(db *bbolt.DB, h *models.HostConfig) error {
	if !h.SSLEnabled || strings.TrimSpace(h.SSLCertID) == "" {
		return nil
	}
	c, err := store.GetTLSCertificate(db, strings.TrimSpace(h.SSLCertID))
	if err != nil {
		return fmt.Errorf("TLS certificate %q not found", h.SSLCertID)
	}
	if c.Status != "active" {
		return fmt.Errorf("TLS certificate %q is not active", h.SSLCertID)
	}
	h.SSLCert = c.CertPath
	h.SSLKey = c.KeyPath
	return nil
}
