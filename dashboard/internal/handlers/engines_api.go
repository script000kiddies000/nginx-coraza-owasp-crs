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

// ── JA3 Management ────────────────────────────────────────────────────────────

func (app *App) APIGetJA3Config(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetJA3Config(app.DB)
	// Seed builtin defaults (known automation clients) so the UI is immediately useful.
	// Action "log" is kept for visibility in UI but will not block.
	builtinDefaults := []models.JA3FingerprintEntry{
			{
				Name:    "Python requests / urllib3",
				Hash:    "3b5074b1b5d032e5620f69f9159c1665",
				Enabled: true,
				Action:  "block",
				Source:  "python-requests",
				Builtin: true,
			},
			{
				Name:    "Python requests v2 (urllib3 2.x)",
				Hash:    "cd08e31494f9531f560d64c695473da9",
				Enabled: true,
				Action:  "block",
				Source:  "python-requests",
				Builtin: true,
			},
			{
				Name:    "Go net/http client",
				Hash:    "b12db4fdfbfcd938bce09551fbce576e",
				Enabled: false,
				Action:  "block",
				Source:  "go-http",
				Builtin: true,
			},
			{
				Name:    "Scrapy / Python generic",
				Hash:    "e6573e91e6eb777c0933c5b8f97f10cd",
				Enabled: true,
				Action:  "block",
				Source:  "scrapy",
				Builtin: true,
			},
			{
				Name:    "Go Golang default TLS",
				Hash:    "a0e9f5d64349fb13191bc781f81f42e1",
				Enabled: false,
				Action:  "block",
				Source:  "golang",
				Builtin: true,
			},
			{
				Name:    "curl (generic TLS)",
				Hash:    "456523fc94726331955098c33bf38cf8",
				Enabled: false,
				Action:  "log",
				Source:  "curl",
				Builtin: true,
			},
			{
				Name:    "Java 11 HttpClient",
				Hash:    "c4ff540cbfa78c851a228e4f4aff64be",
				Enabled: false,
				Action:  "log",
				Source:  "java-11",
				Builtin: true,
			},
			{
				Name:    "Java HttpURLConnection",
				Hash:    "4c1a6a6f85c5f8c7c2e5a6e13f3827eb",
				Enabled: false,
				Action:  "log",
				Source:  "java-http",
				Builtin: true,
			},
			{
				Name:    "Headless Chrome (Puppeteer/Playwright)",
				Hash:    "de350869b8c85de67a350c8d186f11e6",
				Enabled: true,
				Action:  "block",
				Source:  "headless-chrome",
				Builtin: true,
			},
			{
				Name:    "Masscan / ZMap scanner",
				Hash:    "5555555555555555555555555555555a",
				Enabled: true,
				Action:  "block",
				Source:  "masscan",
				Builtin: true,
			},
		}

	// Replace previous builtin list with the desired one (one-time),
	// without overwriting non-builtin/custom entries.
	desiredByHash := make(map[string]models.JA3FingerprintEntry, len(builtinDefaults))
	for _, d := range builtinDefaults {
		desiredByHash[strings.ToLower(strings.TrimSpace(d.Hash))] = d
	}
	customEntries := make([]models.JA3FingerprintEntry, 0, len(cfg.Entries))
	builtinByHash := make(map[string]models.JA3FingerprintEntry, len(cfg.Entries))
	for _, e := range cfg.Entries {
		if e.Builtin {
			builtinByHash[strings.ToLower(strings.TrimSpace(e.Hash))] = e
		} else {
			customEntries = append(customEntries, e)
		}
	}

	needsReplace := len(cfg.Entries) == 0
	if !needsReplace {
		// Trigger replacement if builtin hash set differs from desired set.
		// This ensures missing disabled/log entries are added.
		for k := range builtinByHash {
			if _, ok := desiredByHash[k]; !ok {
				needsReplace = true
				break
			}
		}
		if !needsReplace {
			for k := range desiredByHash {
				if _, ok := builtinByHash[k]; !ok {
					needsReplace = true
					break
				}
			}
		}
	}

	if needsReplace {
		// Keep custom entries, rebuild builtin entries to match desired hash set.
		// If a builtin hash already exists, preserve its current enabled/action/name.
		newEntries := make([]models.JA3FingerprintEntry, 0, len(customEntries)+len(builtinDefaults))
		newEntries = append(newEntries, customEntries...)

		// Avoid duplicates if custom entries happen to contain desired hashes.
		customByHash := make(map[string]struct{}, len(customEntries))
		for _, e := range customEntries {
			customByHash[strings.ToLower(strings.TrimSpace(e.Hash))] = struct{}{}
		}

		for _, d := range builtinDefaults {
			k := strings.ToLower(strings.TrimSpace(d.Hash))
			if _, exists := customByHash[k]; exists {
				continue
			}
			if cur, ok := builtinByHash[k]; ok {
				newEntries = append(newEntries, cur)
			} else {
				newEntries = append(newEntries, d)
			}
		}
		cfg.Entries = newEntries
		_ = store.SaveJA3Config(app.DB, cfg)
		_ = nginx.WriteJA3Map(cfg.Enabled, cfg.Entries)
		_ = nginx.ReloadNginx()
	}
	if len(cfg.JA4Entries) == 0 {
		if list, err := nginx.ReadJA4Entries(nginx.JA4MapPath()); err == nil && len(list) > 0 {
			cfg.JA4Entries = list
			_ = store.SaveJA3Config(app.DB, cfg)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"config":   cfg,
		"map_file": nginx.StatConfigFile(nginx.JA3MapPath()),
		"map_file_ja4": nginx.StatConfigFile(nginx.JA4MapPath()),
	})
}

func (app *App) APIApplyJA3Config(w http.ResponseWriter, r *http.Request) {
	var body models.JA3Config
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	entries := body.Entries
	// Legacy client compatibility: allow plain hash array.
	if len(entries) == 0 && len(body.Hashes) > 0 {
		for _, h := range body.Hashes {
			entries = append(entries, models.JA3FingerprintEntry{
				Name:    "JA3 " + strings.TrimSpace(h),
				Hash:    h,
				Enabled: true,
				Action:  "block",
			})
		}
	}
	normalized := make([]models.JA3FingerprintEntry, 0, len(entries))
	for _, e := range entries {
		v, ok := nginx.NormalizeJA3Hash(e.Hash)
		if !ok {
			jsonError(w, "invalid JA3 hash: "+strings.TrimSpace(e.Hash), http.StatusBadRequest)
			return
		}
		action := strings.ToLower(strings.TrimSpace(e.Action))
		enabled := e.Enabled
		// Backward compat: older clients/UI might only send name+hash.
		// If action is missing, we assume block+enabled=true.
		if action == "" {
			action = "block"
			enabled = true
		}
		if action != "block" && action != "log" {
			action = "block"
		}
		name := strings.TrimSpace(e.Name)
		if name == "" {
			short := v
			if len(short) > 8 {
				short = short[:8]
			}
			name = "JA3 " + short
		}
		normalized = append(normalized, models.JA3FingerprintEntry{
			Name:    name,
			Hash:    v,
			Enabled: enabled,
			Action:  action,
			Source:  strings.TrimSpace(e.Source),
			Builtin: e.Builtin,
		})
	}
	body.Entries = normalized
	body.Hashes = nil

	// JA4
	ja4Entries := body.JA4Entries
	if len(ja4Entries) == 0 && len(body.JA4Hashes) > 0 {
		for _, h := range body.JA4Hashes {
			ja4Entries = append(ja4Entries, models.JA3FingerprintEntry{
				Name: "JA4 " + strings.TrimSpace(h),
				Hash: h,
			})
		}
	}
	ja4Norm := make([]models.JA3FingerprintEntry, 0, len(ja4Entries))
	for _, e := range ja4Entries {
		v, ok := nginx.NormalizeJA4Hash(e.Hash)
		if !ok {
			jsonError(w, "invalid JA4 hash: "+strings.TrimSpace(e.Hash), http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(e.Name)
		if name == "" {
			short := v
			if len(short) > 8 {
				short = short[:8]
			}
			name = "JA4 " + short
		}
		action := strings.ToLower(strings.TrimSpace(e.Action))
		enabled := e.Enabled
		if action == "" {
			action = "block"
			enabled = true
		}
		if action != "block" && action != "log" {
			action = "block"
		}
		ja4Norm = append(ja4Norm, models.JA3FingerprintEntry{
			Name:    name,
			Hash:    v,
			Enabled: enabled,
			Action:  action,
			Source:  strings.TrimSpace(e.Source),
			Builtin: e.Builtin,
		})
	}
	body.JA4Entries = ja4Norm
	body.JA4Hashes = nil

	if err := store.SaveJA3Config(app.DB, body); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.WriteJA3Map(body.Enabled, body.Entries); err != nil {
		jsonError(w, "write ja3 map: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.WriteJA4Map(body.JA4Enabled, body.JA4Entries); err != nil {
		jsonError(w, "write ja4 map: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[ja3] nginx reload: %v", err)
		jsonError(w, "saved but nginx reload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, body)
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
