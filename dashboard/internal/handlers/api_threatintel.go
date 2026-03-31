package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
)

// ── Threat Intel ──────────────────────────────────────────────────────────────

func threatIntelIPRulesPath() string {
	if p := os.Getenv("FLUX_THREAT_INTEL_IP_RULES"); p != "" {
		return p
	}
	return threatintel.DefaultIPRulesPath
}

func threatIntelJSONPath() string {
	if p := os.Getenv("FLUX_THREAT_INTEL_JSON"); p != "" {
		return p
	}
	return threatintel.DefaultJSONPath
}

func (app *App) APIGetThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetThreatIntelConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIPostThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	var body models.ThreatIntelConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.UpdateInterval < 1 || body.UpdateInterval > 8760 {
		jsonError(w, "update_interval must be 1–8760 (hours)", http.StatusBadRequest)
		return
	}
	if body.BlockScore < 0 || body.BlockScore > 100 {
		jsonError(w, "block_score must be 0–100", http.StatusBadRequest)
		return
	}
	cur := store.GetThreatIntelConfig(app.DB)
	if body.LastSync == "" {
		body.LastSync = cur.LastSync
	}
	info := threatintel.ReadIPRulesInfo(threatIntelIPRulesPath(), 1)
	body.IPCount = info.DenyCount
	if err := store.SaveThreatIntelConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
}

func (app *App) APIGetThreatIntelStatus(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetThreatIntelConfig(app.DB)
	ipPath := threatIntelIPRulesPath()
	jsonPath := threatIntelJSONPath()
	info := threatintel.ReadIPRulesInfo(ipPath, 80)
	var feedsObj any
	var feedsErr string
	raw, err := threatintel.ReadFeedsJSON(jsonPath)
	if err != nil {
		feedsErr = err.Error()
	} else if len(raw) > 0 {
		if err := json.Unmarshal(raw, &feedsObj); err != nil {
			feedsErr = "invalid feeds JSON: " + err.Error()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":      cfg,
		"ip_rules":    info,
		"feeds_file":  feedsObj,
		"feeds_error": feedsErr,
		"paths": map[string]string{
			"ip_rules": ipPath,
			"feeds":    jsonPath,
		},
	})
}

func (app *App) APIGetThreatIntelFeeds(w http.ResponseWriter, r *http.Request) {
	jsonPath := threatIntelJSONPath()
	cfg, err := threatintel.ReadFileConfig(jsonPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled": cfg.Enabled,
		"action":  cfg.Action,
		"feeds":   cfg.Feeds,
		"path":    jsonPath,
	})
}

func (app *App) APIPostThreatIntelFeeds(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool               `json:"enabled"`
		Action  string             `json:"action"`
		Feeds   []threatintel.Feed `json:"feeds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.Action == "" {
		body.Action = "block"
	}
	if body.Action != "block" && body.Action != "allow" {
		jsonError(w, "action must be block or allow", http.StatusBadRequest)
		return
	}
	for i := range body.Feeds {
		f := &body.Feeds[i]
		f.Name = strings.TrimSpace(f.Name)
		f.Type = strings.TrimSpace(strings.ToLower(f.Type))
		f.URL = strings.TrimSpace(f.URL)
		f.APIKey = strings.TrimSpace(f.APIKey)
		if f.Name == "" || f.Type == "" || f.URL == "" {
			jsonError(w, "feed name/type/url is required", http.StatusBadRequest)
			return
		}
		switch f.Type {
		case "spamhaus_drop", "emerging_threats", "abuseipdb":
		default:
			jsonError(w, "unsupported feed type: "+f.Type, http.StatusBadRequest)
			return
		}
	}

	jsonPath := threatIntelJSONPath()
	cfg, err := threatintel.ReadFileConfig(jsonPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Enabled = body.Enabled
	cfg.Action = body.Action
	cfg.Feeds = body.Feeds
	if err := threatintel.WriteFileConfig(jsonPath, cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"ok":      true,
		"enabled": cfg.Enabled,
		"action":  cfg.Action,
		"feeds":   cfg.Feeds,
	})
}

func (app *App) APIForceSyncIntel(w http.ResponseWriter, r *http.Request) {
	ipPath := threatIntelIPRulesPath()
	jsonPath := threatIntelJSONPath()
	cfg := store.GetThreatIntelConfig(app.DB)
	res, err := threatintel.SyncFeeds(cfg, jsonPath, ipPath)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		jsonError(w, "sync done but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.LastSync = res.LastSync
	cfg.IPCount = res.IPCount
	if err := store.SaveThreatIntelConfig(app.DB, cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"ok":         true,
		"message":    "Threat intel sync sukses (feeds fetched, ip_rules.conf updated, nginx reloaded).",
		"last_sync":  cfg.LastSync,
		"deny_count": cfg.IPCount,
	})
}

func (app *App) APIGetThreatIntelBlocked(w http.ResponseWriter, r *http.Request) {
	path := threatIntelIPRulesPath()
	info := threatintel.ReadIPRulesInfo(path, 500)
	type row struct {
		Target string `json:"target"`
		Line   string `json:"line"`
	}
	rows := make([]row, 0, len(info.Preview))
	for _, line := range info.Preview {
		target := strings.TrimPrefix(line, "deny ")
		target = strings.TrimSuffix(strings.TrimSpace(target), ";")
		rows = append(rows, row{Target: target, Line: line})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"deny_count": info.DenyCount,
		"path":       info.Path,
		"entries":    rows,
		"truncated":  info.DenyCount > len(rows),
		"read_error": info.ReadError,
	})
}
