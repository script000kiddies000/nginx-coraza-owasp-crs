package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

	// ── Basic validation ──────────────────────────────────────────────────────
	h.Domain = strings.TrimSpace(h.Domain)
	if h.Domain == "" {
		jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}

	// Default mode
	if h.Mode == "" {
		h.Mode = "reverse_proxy"
	}
	switch h.Mode {
	case "reverse_proxy", "static", "redirect":
	default:
		jsonError(w, "mode must be reverse_proxy, static, or redirect", http.StatusBadRequest)
		return
	}

	// ── Listen ports ──────────────────────────────────────────────────────────
	// Filter out empty/zero ports
	var validPorts []models.ListenPort
	for _, lp := range h.ListenPorts {
		if lp.Port > 0 && lp.Port <= 65535 {
			validPorts = append(validPorts, lp)
		}
	}
	if len(validPorts) == 0 {
		// Legacy fallback
		validPorts = []models.ListenPort{{Port: 80, HTTPS: false}}
	}
	h.ListenPorts = validPorts

	// Derive ssl_enabled from HTTPS ports
	h.SSLEnabled = false
	for _, lp := range h.ListenPorts {
		if lp.HTTPS {
			h.SSLEnabled = true
			break
		}
	}

	// ── Mode-specific validation ───────────────────────────────────────────────
	switch h.Mode {
	case "reverse_proxy":
		var clean []string
		for _, s := range h.UpstreamServers {
			if s = strings.TrimSpace(s); s != "" {
				clean = append(clean, s)
			}
		}
		if len(clean) == 0 {
			jsonError(w, "at least one upstream server is required", http.StatusBadRequest)
			return
		}
		h.UpstreamServers = clean
		if h.LBAlgorithm == "" || len(clean) == 1 {
			h.LBAlgorithm = "round_robin"
		}
		switch h.LBAlgorithm {
		case "round_robin", "least_conn", "ip_hash":
		default:
			h.LBAlgorithm = "round_robin"
		}

	case "static":
		h.StaticRoot = strings.TrimSpace(h.StaticRoot)
		if h.StaticRoot == "" {
			jsonError(w, "static_root is required for static mode", http.StatusBadRequest)
			return
		}
		h.UpstreamServers = nil

	case "redirect":
		h.RedirectURL = strings.TrimSpace(h.RedirectURL)
		if h.RedirectURL == "" {
			jsonError(w, "redirect_url is required for redirect mode", http.StatusBadRequest)
			return
		}
		if h.RedirectCode != 301 && h.RedirectCode != 302 {
			h.RedirectCode = 301
		}
		h.UpstreamServers = nil
	}

	// ── WAF mode default ──────────────────────────────────────────────────────
	if h.WAFMode == "" {
		h.WAFMode = "On"
	}
	switch h.WAFMode {
	case "On", "Off", "DetectionOnly":
	default:
		jsonError(w, "waf_mode must be On, Off, or DetectionOnly", http.StatusBadRequest)
		return
	}

	// ── SSL cert resolution ───────────────────────────────────────────────────
	if h.SSLEnabled {
		if err := resolveHostSSL(app.DB, &h); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		h.SSLCert = ""
		h.SSLKey = ""
		h.SSLCertID = ""
	}

	// ── Persist ───────────────────────────────────────────────────────────────
	if err := store.SaveHost(app.DB, h); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ── Write nginx conf + reload ─────────────────────────────────────────────
	if h.Enabled {
		if err := nginx.WriteHostConf(h); err != nil {
			jsonError(w, "nginx conf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := nginx.ReloadNginx(); err != nil {
			// Config written; log the reload warning but don't fail the API.
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

func sslCertDir() string {
	if p := os.Getenv("FLUX_SSL_DIR"); p != "" {
		return p
	}
	return "/etc/nginx/ssl_certs"
}

var reSSLBaseName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func sanitizeSSLBaseName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "localhost"
	}
	if !reSSLBaseName.MatchString(s) {
		return "localhost"
	}
	return s
}

type sslPair struct {
	Name    string `json:"name"`
	CRTPath string `json:"crt_path,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	HasCRT  bool   `json:"has_crt"`
	HasKey  bool   `json:"has_key"`
	ModTime string `json:"mod_time,omitempty"`
}

// APIGetSSL lists available cert/key pairs in /etc/nginx/ssl_certs.
func (app *App) APIGetSSL(w http.ResponseWriter, r *http.Request) {
	dir := sslCertDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dir":   dir,
				"pairs": []sslPair{},
			})
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type pairParts struct {
		hasCRT bool
		hasKey bool
	}
	parts := map[string]*pairParts{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".crt") {
			base := strings.TrimSuffix(name, ".crt")
			p := parts[base]
			if p == nil {
				p = &pairParts{}
				parts[base] = p
			}
			p.hasCRT = true
		} else if strings.HasSuffix(name, ".key") {
			base := strings.TrimSuffix(name, ".key")
			p := parts[base]
			if p == nil {
				p = &pairParts{}
				parts[base] = p
			}
			p.hasKey = true
		}
	}

	bases := make([]string, 0, len(parts))
	for b := range parts {
		bases = append(bases, b)
	}
	sort.Strings(bases)

	pairs := make([]sslPair, 0, len(bases))
	for _, base := range bases {
		p := parts[base]
		crtPath := filepath.Join(dir, base+".crt")
		keyPath := filepath.Join(dir, base+".key")

		pair := sslPair{
			Name:   base,
			HasCRT: p.hasCRT,
			HasKey: p.hasKey,
		}
		if p.hasCRT {
			pair.CRTPath = crtPath
		}
		if p.hasKey {
			pair.KeyPath = keyPath
		}
		// Use CRT mtime as display time when available.
		if p.hasCRT {
			if st, err := os.Stat(crtPath); err == nil {
				pair.ModTime = st.ModTime().UTC().Format(time.RFC3339)
			}
		}
		pairs = append(pairs, pair)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"dir":   dir,
		"pairs": pairs,
	})
}

// APIUploadSSL accepts multipart form fields:
// - name (basename, default "localhost")
// - crt (certificate file)
// - key (private key file)
func (app *App) APIUploadSSL(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	name := sanitizeSSLBaseName(r.FormValue("name"))
	dir := sslCertDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		jsonError(w, "mkdir ssl dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	crtFile, _, err := r.FormFile("crt")
	if err != nil {
		jsonError(w, "crt file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer crtFile.Close()

	keyFile, _, err := r.FormFile("key")
	if err != nil {
		jsonError(w, "key file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer keyFile.Close()

	crtPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	writeTo := func(path string, src io.Reader, mode os.FileMode) error {
		tmp := path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(f, src)
		closeErr := f.Close()
		if cpErr != nil {
			_ = os.Remove(tmp)
			return cpErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if err := os.Chmod(tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, path)
	}

	if err := writeTo(crtPath, crtFile, 0644); err != nil {
		jsonError(w, "write crt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// keyFile is separate reader; already at start.
	if err := writeTo(keyPath, keyFile, 0600); err != nil {
		jsonError(w, "write key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Default server uses localhost cert; reload nginx so changes apply.
	reloadErr := nginx.ReloadNginx()
	w.Header().Set("Content-Type", "application/json")
	if reloadErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"name":       name,
			"crt_path":  crtPath,
			"key_path":  keyPath,
			"reload_err": reloadErr.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"name":      name,
		"crt_path":  crtPath,
		"key_path":  keyPath,
		"reloaded":  true,
	})
}

// ── Bot Management ────────────────────────────────────────────────────────────

func (app *App) APIGetBotConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetAdvBotConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

// Bot apply/status/blocked/unblock: engines_api.go

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

// IP reputations, vpatch, dlp apply/events, wpsec: engines_api.go

// ── DLP ───────────────────────────────────────────────────────────────────────

func (app *App) APIGetDLPConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetDLPConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

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
