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

func (app *App) APIWafToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	cfg := store.GetWAFSettings(app.DB)
	cfg.Mode = body.Mode
	if err := store.SaveWAFSettings(app.DB, cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
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
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `[]`)
}

func (app *App) APIAttackMapData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `[]`)
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
func (app *App) APIUsers(w http.ResponseWriter, r *http.Request)     { stubJSON(w) }

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

// ── Threat Intel ──────────────────────────────────────────────────────────────

func (app *App) APIGetThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	cfg := store.GetThreatIntelConfig(app.DB)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (app *App) APIForceSyncIntel(w http.ResponseWriter, r *http.Request)    { stubJSON(w) }
func (app *App) APIGetThreatIntelBlocked(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIIPReputations(w http.ResponseWriter, r *http.Request)     { stubJSON(w) }

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

func (app *App) APINginxStatus(w http.ResponseWriter, r *http.Request)  { stubJSON(w) }
func (app *App) APIServerHealth(w http.ResponseWriter, r *http.Request) { stubJSON(w) }

// ── Reports ───────────────────────────────────────────────────────────────────

func (app *App) APIDownloadSecurityReport(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIDownloadAttackReport(w http.ResponseWriter, r *http.Request)   { stubJSON(w) }

// ── helpers ───────────────────────────────────────────────────────────────────

func stubJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true,"note":"not yet implemented"}`)
}
