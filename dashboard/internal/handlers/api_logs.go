package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"

	"flux-waf/internal/logs"
	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

func (app *App) APISecurityEvents(w http.ResponseWriter, r *http.Request) {
	events, err := store.ListSecurityEvents(app.DB, 500)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []models.SecurityEvent{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

// ── Access logs (nginx flux_json) ─────────────────────────────────────────────

func (app *App) APIGetAccessLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	path := os.Getenv("FLUX_ACCESS_JSON_LOG")
	if path == "" {
		path = logs.DefaultAccessJSONLog
	}
	entries, err := logs.ReadAccessJSONTail(path, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"path":    path,
		"count":   len(entries),
		"entries": entries,
	})
}

// ── Event Logs (nginx error.log) ─────────────────────────────────────────────

func (app *App) APIGetEventLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	path := os.Getenv("FLUX_NGINX_ERROR_LOG")
	if path == "" {
		path = logs.DefaultNginxErrorLog
	}

	lines, err := logs.ReadNginxErrorLogTail(path, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"path":  path,
		"count": len(lines),
		"lines": lines,
	})
}
