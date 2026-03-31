package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── Bot Management ────────────────────────────────────────────────────────────

func (app *App) APIApplyBotConfig(w http.ResponseWriter, r *http.Request) {
	var body models.AdvBotConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.BotThreshold < 1 || body.BotThreshold > 100000 {
		jsonError(w, "bot_threshold must be 1–100000", http.StatusBadRequest)
		return
	}
	if body.LimitLoginRPM < 1 || body.LimitLoginRPM > 10000 {
		jsonError(w, "limit_login_rpm must be 1–10000", http.StatusBadRequest)
		return
	}
	if body.CredStuffWindowMin < 1 || body.CredStuffWindowMin > 1440 {
		jsonError(w, "cred_stuff_window_min must be 1–1440", http.StatusBadRequest)
		return
	}
	switch strings.ToLower(body.ChallengeType) {
	case "", "js", "captcha", "none", "off":
	default:
		jsonError(w, "challenge_type must be js, captcha, none, or off", http.StatusBadRequest)
		return
	}
	if err := store.SaveAdvBotConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[advbot] nginx reload: %v", err)
	}
	jsonOK(w, body)
}

func (app *App) APIBotStatus(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetAdvBotConfig(app.DB)
	blocked, _ := store.ListBotBlocked(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":         cfg,
		"blocked_count":  len(blocked),
		"nginx_reloaded": time.Now().UTC().Format(time.RFC3339),
	})
}

func (app *App) APIBotBlockedIPs(w http.ResponseWriter, r *http.Request) {
	list, err := store.ListBotBlocked(app.DB)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": list})
}

func (app *App) APIBotUnblock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.IP = strings.TrimSpace(body.IP)
	if body.IP == "" {
		jsonError(w, "ip required", http.StatusBadRequest)
		return
	}
	if err := store.RemoveBotBlocked(app.DB, body.IP); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = nginx.ReloadNginx()
	jsonOK(w, map[string]string{"ip": body.IP})
}
