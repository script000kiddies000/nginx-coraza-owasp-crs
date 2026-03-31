package handlers

import (
	"encoding/json"
	"net/http"

	"flux-waf/internal/models"
	"flux-waf/internal/monitor"
)

// ── Malware ───────────────────────────────────────────────────────────────────

func (app *App) APIStartMalwareScan(w http.ResponseWriter, r *http.Request)  { stubJSON(w) }
func (app *App) APIMalwareScanHistory(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

// ── System ────────────────────────────────────────────────────────────────────

func (app *App) APINginxStatus(w http.ResponseWriter, r *http.Request) {
	st, err := monitor.FetchNginxStatus(nil)
	w.Header().Set("Content-Type", "application/json")
	type resp struct {
		models.NginxStatus
		Reachable bool   `json:"reachable"`
		Detail    string `json:"detail,omitempty"`
	}
	out := resp{NginxStatus: st, Reachable: err == nil}
	if err != nil {
		out.Detail = err.Error()
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (app *App) APIServerHealth(w http.ResponseWriter, r *http.Request) {
	h := monitor.CollectServerHealthWithNginx()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h)
}
