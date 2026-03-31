package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"flux-waf/internal/store"
)

// ── Auth ──────────────────────────────────────────────────────────────────────

func (app *App) APIMe(w http.ResponseWriter, r *http.Request) {
	u, _ := store.GetUser(app.DB, usernameFromCtx(r))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": u.Username, "role": u.Role})
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func (app *App) APIStats(w http.ResponseWriter, r *http.Request) {
	hosts, _ := store.ListHosts(app.DB)
	waf := store.GetWAFSettings(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"host_count": len(hosts),
		"waf_mode":   waf.Mode,
	})
}

func (app *App) APITraffic(w http.ResponseWriter, r *http.Request) {
	// Placeholder — will be implemented in Fase 3 (log tailer worker)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"labels":[],"requests":[],"blocked":[]}`)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func stubJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true,"note":"not yet implemented"}`)
}
