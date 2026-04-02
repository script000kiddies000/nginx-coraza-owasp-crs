package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

var reRealIPHeader = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// APIGetRealIPSettings returns global Real IP extraction settings.
func (app *App) APIGetRealIPSettings(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetRealIPConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// APIPostRealIPSettings saves global Real IP extraction settings.
func (app *App) APIPostRealIPSettings(w http.ResponseWriter, r *http.Request) {
	var body models.RealIPConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	body.Enabled = !!body.Enabled
	body.Header = strings.TrimSpace(body.Header)
	if body.Enabled {
		// real_ip_header expects a header-name-like token; prevent injection/invalid values.
		if body.Header == "" || !reRealIPHeader.MatchString(body.Header) {
			jsonError(w, "header must be a valid header token (e.g. X-Forwarded-For)", http.StatusBadRequest)
			return
		}
	}

	// Clean up trusted proxies.
	var cleaned []string
	for _, p := range body.TrustedProxies {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Keep as-is (Nginx supports IP/CIDR). Validation is intentionally permissive.
		cleaned = append(cleaned, p)
	}
	if body.Enabled && len(cleaned) == 0 {
		// Keep safe defaults if user enables but doesn't provide trust sources.
		def := store.GetRealIPConfig(app.DB)
		cleaned = def.TrustedProxies
	}
	body.TrustedProxies = cleaned

	if err := store.SaveRealIPConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Regenerate host conf so server blocks pick up the new realip directives.
	if err := nginx.SyncAllConfigs(app.DB); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
}

