package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
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
		// Keep dashboard responsive even if parsing fails.
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
		"config":           store.GetDLPConfig(app.DB),
		"rules_file":       nginx.StatConfigFile(nginx.FLUXDLPRulesPath()),
		"inspection_file":  nginx.StatConfigFile(nginx.FLUXDLPInspectionPath()),
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

// ── WordPress Security ──────────────────────────────────────────────────────

func (app *App) APIGetWPSecConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetWPSecurityConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIApplyWPSecConfig(w http.ResponseWriter, r *http.Request) {
	var body models.WPSecurityConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	path, err := nginx.WriteWPSecuritySnippet(body)
	if err != nil {
		log.Printf("[wpsec] write snippet: %v", err)
		jsonError(w, "write snippet: "+err.Error(), http.StatusInternalServerError)
		return
	}
	body.LastWritten = time.Now().UTC().Format(time.RFC3339)
	if err := store.SaveWPSecurityConfig(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[wpsec] nginx reload: %v", err)
		jsonError(w, "saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"config": body, "snippet_path": path})
}

// ── IP Reputations (aggregate audit + threat intel) ───────────────────────────

type ipHit struct {
	IP   string `json:"ip"`
	Hits int    `json:"hits"`
}

func (app *App) APIIPReputations(w http.ResponseWriter, r *http.Request) {
	events, _ := store.ListSecurityEvents(app.DB, 2500)
	counts := make(map[string]int)
	for _, e := range events {
		ip := strings.TrimSpace(e.ClientIP)
		if ip == "" {
			continue
		}
		counts[ip]++
	}
	pairs := make([]ipHit, 0, len(counts))
	for ip, n := range counts {
		pairs = append(pairs, ipHit{IP: ip, Hits: n})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Hits == pairs[j].Hits {
			return pairs[i].IP < pairs[j].IP
		}
		return pairs[i].Hits > pairs[j].Hits
	})
	if len(pairs) > 80 {
		pairs = pairs[:80]
	}

	ti := store.GetThreatIntelConfig(app.DB)
	ipPath := threatIntelIPRulesPath()
	tiRules := threatintel.ReadIPRulesInfo(ipPath, 40)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"threat_intel_config": ti,
		"threat_intel_rules":  tiRules,
		"top_offenders":       pairs,
		"audit_events_sample": minLen(events, 25),
	})
}

func minLen(events []models.SecurityEvent, n int) []models.SecurityEvent {
	if len(events) <= n {
		return events
	}
	return events[:n]
}
