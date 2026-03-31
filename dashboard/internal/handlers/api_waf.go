package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── WAF ───────────────────────────────────────────────────────────────────────

func (app *App) APIGetWAFSettings(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetWAFSettings(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIPostWAFSettings(w http.ResponseWriter, r *http.Request) {
	var body models.WAFSettings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	switch body.Mode {
	case "On", "Off", "DetectionOnly":
	default:
		jsonError(w, "mode must be On, Off, or DetectionOnly", http.StatusBadRequest)
		return
	}
	if body.ParanoiaLevel < 1 || body.ParanoiaLevel > 4 {
		jsonError(w, "paranoia_level must be between 1 and 4", http.StatusBadRequest)
		return
	}
	if body.AnomalyInbound < 1 || body.AnomalyInbound > 999 {
		jsonError(w, "anomaly_inbound must be between 1 and 999", http.StatusBadRequest)
		return
	}
	if err := store.SaveWAFSettings(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ApplyWAFConfig(body); err != nil {
		log.Printf("[waf] apply config: %v", err)
		jsonError(w, "saved to database but nginx apply failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, nil)
}

func (app *App) APIWafToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	switch body.Mode {
	case "On", "Off", "DetectionOnly":
	default:
		jsonError(w, "mode must be On, Off, or DetectionOnly", http.StatusBadRequest)
		return
	}
	cfg := store.GetWAFSettings(app.DB)
	cfg.Mode = body.Mode
	if err := store.SaveWAFSettings(app.DB, cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ApplyWAFConfig(cfg); err != nil {
		log.Printf("[waf] apply config: %v", err)
		jsonError(w, "could not apply WAF config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, nil)
}

func (app *App) APIWAFTopMessages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `[]`)
}

func (app *App) APICustomRules(w http.ResponseWriter, r *http.Request) {
	stubJSON(w)
}

func (app *App) APIConfigureRules(w http.ResponseWriter, r *http.Request) {
	stubJSON(w)
}

// ── Bot Management ────────────────────────────────────────────────────────────

func (app *App) APIGetBotConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetAdvBotConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// ── DLP ───────────────────────────────────────────────────────────────────────

func (app *App) APIGetDLPConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetDLPConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}
