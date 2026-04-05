package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// APIGetAuditLogFormat returns GET /api/settings/audit-log-format
func (app *App) APIGetAuditLogFormat(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetAuditLogFormatConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// APIPostAuditLogFormat saves format, rewrites flux_audit_log_format.conf, reloads nginx.
func (app *App) APIPostAuditLogFormat(w http.ResponseWriter, r *http.Request) {
	var body models.AuditLogFormatConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.Format = strings.TrimSpace(strings.ToLower(body.Format))
	if body.Format != "json" && body.Format != "native" {
		jsonError(w, `format must be "json" or "native"`, http.StatusBadRequest)
		return
	}
	if err := store.SaveAuditLogFormatConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.WriteAuditLogFormat(body.Format); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, "saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
}
