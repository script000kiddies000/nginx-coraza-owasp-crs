package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/logs"
	"flux-waf/internal/models"
	"flux-waf/internal/monitor"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
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

// ── Hosts ─────────────────────────────────────────────────────────────────────

func (app *App) APIGetHosts(w http.ResponseWriter, r *http.Request) {
	hosts, _ := store.ListHosts(app.DB)
	if hosts == nil {
		hosts = []models.HostConfig{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// APISaveHost handles POST /api/hosts — add or update a host, write nginx conf, reload.
func (app *App) APISaveHost(w http.ResponseWriter, r *http.Request) {
	var h models.HostConfig
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if h.Domain == "" {
		jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}
	if len(h.UpstreamServers) == 0 {
		jsonError(w, "at least one upstream server is required", http.StatusBadRequest)
		return
	}
	if h.WAFMode == "" {
		h.WAFMode = "On"
	}
	if h.LBAlgorithm == "" {
		h.LBAlgorithm = "round_robin"
	}

	if err := store.SaveHost(app.DB, h); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Enabled {
		if err := nginx.WriteHostConf(h); err != nil {
			jsonError(w, "nginx conf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := nginx.ReloadNginx(); err != nil {
			// Config is written; log the reload warning but don't fail the request.
			log.Printf("[hosts] nginx reload warning: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// APIDeleteHost handles DELETE /api/hosts/{domain} — remove host from DB + nginx conf.
func (app *App) APIDeleteHost(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := store.DeleteHost(app.DB, domain); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.DeleteHostConf(domain); err != nil {
		log.Printf("[hosts] delete conf %q: %v", domain, err)
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[hosts] nginx reload after delete: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

func (app *App) APIGetSSL(w http.ResponseWriter, r *http.Request)    { stubJSON(w) }
func (app *App) APIUploadSSL(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

// ── Bot Management ────────────────────────────────────────────────────────────

func (app *App) APIGetBotConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetAdvBotConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIApplyBotConfig(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIBotStatus(w http.ResponseWriter, r *http.Request)      { stubJSON(w) }
func (app *App) APIBotBlockedIPs(w http.ResponseWriter, r *http.Request)  { stubJSON(w) }
func (app *App) APIBotUnblock(w http.ResponseWriter, r *http.Request)     { stubJSON(w) }

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

func (app *App) APIForceSyncIntel(w http.ResponseWriter, r *http.Request) {
	ipPath := threatIntelIPRulesPath()
	info := threatintel.ReadIPRulesInfo(ipPath, 1)
	cfg := store.GetThreatIntelConfig(app.DB)
	if info.LastSyncLine != "" && info.LastSyncLine != "Never" {
		cfg.LastSync = info.LastSyncLine
	} else {
		cfg.LastSync = time.Now().Format(time.RFC3339) + " (refresh — feed sync belum dijalankan)"
	}
	cfg.IPCount = info.DenyCount
	if err := store.SaveThreatIntelConfig(app.DB, cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"ok":         true,
		"message":    "Status dimuat ulang dari ip_rules.conf. Untuk sync penuh jalankan: python3 scripts/sync_threat_intel.py (di host).",
		"last_sync":  cfg.LastSync,
		"deny_count": info.DenyCount,
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

func (app *App) APIIPReputations(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

// ── Virtual Patching ──────────────────────────────────────────────────────────

func (app *App) APIGetVPatchConfig(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIApplyVPatchConfig(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIReloadVPatch(w http.ResponseWriter, r *http.Request)     { stubJSON(w) }
func (app *App) APIVPatchStatus(w http.ResponseWriter, r *http.Request)     { stubJSON(w) }

// ── DLP ───────────────────────────────────────────────────────────────────────

func (app *App) APIGetDLPConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetDLPConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIApplyDLPConfig(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIDLPEvents(w http.ResponseWriter, r *http.Request)      { stubJSON(w) }
func (app *App) APIDLPClearEvents(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

// ── WordPress ─────────────────────────────────────────────────────────────────

func (app *App) APIGetWPSecConfig(w http.ResponseWriter, r *http.Request)   { stubJSON(w) }
func (app *App) APIApplyWPSecConfig(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

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

// ── Reports ───────────────────────────────────────────────────────────────────

func (app *App) APIDownloadSecurityReport(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIDownloadAttackReport(w http.ResponseWriter, r *http.Request)   { stubJSON(w) }

// ── helpers ───────────────────────────────────────────────────────────────────

func stubJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true,"note":"not yet implemented"}`)
}
