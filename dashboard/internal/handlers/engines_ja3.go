package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── JA3 Management ────────────────────────────────────────────────────────────

func (app *App) APIGetJA3Config(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetJA3Config(app.DB)
	builtinDefaults := []models.JA3FingerprintEntry{
		{Name: "Python requests / urllib3", Hash: "3b5074b1b5d032e5620f69f9159c1665", Enabled: true, Action: "block", Source: "python-requests", Builtin: true},
		{Name: "Python requests v2 (urllib3 2.x)", Hash: "cd08e31494f9531f560d64c695473da9", Enabled: true, Action: "block", Source: "python-requests", Builtin: true},
		{Name: "Go net/http client", Hash: "b12db4fdfbfcd938bce09551fbce576e", Enabled: false, Action: "block", Source: "go-http", Builtin: true},
		{Name: "Scrapy / Python generic", Hash: "e6573e91e6eb777c0933c5b8f97f10cd", Enabled: true, Action: "block", Source: "scrapy", Builtin: true},
		{Name: "Go Golang default TLS", Hash: "a0e9f5d64349fb13191bc781f81f42e1", Enabled: false, Action: "block", Source: "golang", Builtin: true},
		{Name: "curl (generic TLS)", Hash: "456523fc94726331955098c33bf38cf8", Enabled: false, Action: "log", Source: "curl", Builtin: true},
		{Name: "Java 11 HttpClient", Hash: "c4ff540cbfa78c851a228e4f4aff64be", Enabled: false, Action: "log", Source: "java-11", Builtin: true},
		{Name: "Java HttpURLConnection", Hash: "4c1a6a6f85c5f8c7c2e5a6e13f3827eb", Enabled: false, Action: "log", Source: "java-http", Builtin: true},
		{Name: "Headless Chrome (Puppeteer/Playwright)", Hash: "de350869b8c85de67a350c8d186f11e6", Enabled: true, Action: "block", Source: "headless-chrome", Builtin: true},
		{Name: "Masscan / ZMap scanner", Hash: "5555555555555555555555555555555a", Enabled: true, Action: "block", Source: "masscan", Builtin: true},
	}

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
		newEntries := make([]models.JA3FingerprintEntry, 0, len(customEntries)+len(builtinDefaults))
		newEntries = append(newEntries, customEntries...)
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
		"config":       cfg,
		"map_file":     nginx.StatConfigFile(nginx.JA3MapPath()),
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
	if len(entries) == 0 && len(body.Hashes) > 0 {
		for _, h := range body.Hashes {
			entries = append(entries, models.JA3FingerprintEntry{Name: "JA3 " + strings.TrimSpace(h), Hash: h, Enabled: true, Action: "block"})
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
			Name: name, Hash: v, Enabled: enabled, Action: action,
			Source: strings.TrimSpace(e.Source), Builtin: e.Builtin,
		})
	}
	body.Entries = normalized
	body.Hashes = nil

	ja4Entries := body.JA4Entries
	if len(ja4Entries) == 0 && len(body.JA4Hashes) > 0 {
		for _, h := range body.JA4Hashes {
			ja4Entries = append(ja4Entries, models.JA3FingerprintEntry{Name: "JA4 " + strings.TrimSpace(h), Hash: h})
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
			Name: name, Hash: v, Enabled: enabled, Action: action,
			Source: strings.TrimSpace(e.Source), Builtin: e.Builtin,
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
