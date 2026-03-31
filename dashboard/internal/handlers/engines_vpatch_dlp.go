package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── Virtual Patching ──────────────────────────────────────────────────────────

func vpatchRulesPath() string {
	if p := os.Getenv("FLUX_VPATCH_RULES_PATH"); p != "" {
		return p
	}
	return "/etc/nginx/coraza/custom/vpatch.rules"
}

func (app *App) APIGetVPatchConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetVirtualPatchConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIApplyVPatchConfig(w http.ResponseWriter, r *http.Request) {
	var body models.VirtualPatchConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	body.LastReload = time.Now().UTC().Format(time.RFC3339)
	if err := store.SaveVirtualPatchConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[vpatch] nginx reload: %v", err)
		jsonError(w, "saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
}

func (app *App) APIReloadVPatch(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetVirtualPatchConfig(app.DB)
	cfg.LastReload = time.Now().UTC().Format(time.RFC3339)
	_ = store.SaveVirtualPatchConfig(app.DB, cfg)
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"last_reload": cfg.LastReload})
}

func (app *App) APIVPatchStatus(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetVirtualPatchConfig(app.DB)
	entries, err := nginx.ReadVPatchEntries(vpatchRulesPath(), 200)
	if err != nil {
		log.Printf("[vpatch] parse entries: %v", err)
		entries = []models.VirtualPatchEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":     cfg,
		"rules_file": nginx.StatConfigFile(vpatchRulesPath()),
		"entries":    entries,
	})
}

// ── DLP / Data Guard ─────────────────────────────────────────────────────────

func (app *App) APIApplyDLPConfig(w http.ResponseWriter, r *http.Request) {
	var body models.DLPConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.MaxBodySizeKB < 64 {
		body.MaxBodySizeKB = 64
	}
	if body.MaxBodySizeKB > 524288 {
		body.MaxBodySizeKB = 524288
	}
	body.ConfigVersion = 1
	if err := nginx.WriteDLPConfigFiles(body); err != nil {
		jsonError(w, "write dlp files: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := store.SaveDLPConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[dlp] nginx reload: %v", err)
		jsonError(w, "saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
}

func (app *App) APIGetDLPStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":          store.GetDLPConfig(app.DB),
		"rules_file":      nginx.StatConfigFile(nginx.FLUXDLPRulesPath()),
		"inspection_file": nginx.StatConfigFile(nginx.FLUXDLPInspectionPath()),
	})
}

func (app *App) APIDLPEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	events, err := store.ListDLPEvents(app.DB, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (app *App) APIDLPClearEvents(w http.ResponseWriter, r *http.Request) {
	if err := store.ClearDLPEvents(app.DB); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, nil)
}
