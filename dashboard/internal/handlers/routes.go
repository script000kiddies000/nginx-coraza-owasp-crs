package handlers

import (
	"net/http"

	bolt "go.etcd.io/bbolt"
)

// NewRouter creates the App and registers all HTTP routes.
// Returns a ready-to-serve http.Handler.
func NewRouter(db *bolt.DB) (http.Handler, error) {
	app, err := NewApp(db)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	// Static assets — served directly from embedded FS
	mux.Handle("GET /public/", http.FileServer(http.FS(publicFS())))

	// ── Auth (no middleware) ───────────────────────────────────────────────
	mux.HandleFunc("GET /login", app.PageLogin)
	mux.HandleFunc("POST /api/login", app.APILogin)
	mux.HandleFunc("POST /api/logout", app.RequireAuth(app.APILogout))

	// ── SSR Pages ─────────────────────────────────────────────────────────
	mux.HandleFunc("GET /", app.RequireAuth(app.PageDashboard))
	mux.HandleFunc("GET /attack-map", app.RequireAuth(app.PageAttackMap))
	mux.HandleFunc("GET /hosts", app.RequireAuth(app.PageHosts))
	mux.HandleFunc("GET /ssl", app.RequireAuth(app.PageSSL))
	mux.HandleFunc("GET /rules", app.RequireAuth(app.PageRules))
	mux.HandleFunc("GET /virtual-patching", app.RequireAuth(app.PageVirtualPatching))
	mux.HandleFunc("GET /bot-management", app.RequireAuth(app.PageBotManagement))
	mux.HandleFunc("GET /ip-reputations", app.RequireAuth(app.PageIPReputations))
	mux.HandleFunc("GET /wordpress-security", app.RequireAuth(app.PageWPSecurity))
	mux.HandleFunc("GET /data-guard", app.RequireAuth(app.PageDataGuard))
	mux.HandleFunc("GET /threat-intel", app.RequireAuth(app.PageThreatIntel))
	mux.HandleFunc("GET /security-logs", app.RequireAuth(app.PageSecurityLogs))
	mux.HandleFunc("GET /logs", app.RequireAuth(app.PageLogs))
	mux.HandleFunc("GET /security-report", app.RequireAuth(app.PageSecurityReport))
	mux.HandleFunc("GET /attack-report", app.RequireAuth(app.PageAttackReport))
	mux.HandleFunc("GET /malware-scan", app.RequireAuth(app.PageMalwareScan))
	mux.HandleFunc("GET /monitoring/nginx", app.RequireAuth(app.PageNginxMonitoring))
	mux.HandleFunc("GET /monitoring/server", app.RequireAuth(app.PageServerMonitoring))
	mux.HandleFunc("GET /settings", app.RequireAuth(app.PageSettings))

	// ── JSON API ──────────────────────────────────────────────────────────
	mux.HandleFunc("GET /api/me", app.RequireAuth(app.APIMe))
	mux.HandleFunc("GET /api/users", app.RequireAuth(app.APIUsers))
	mux.HandleFunc("GET /api/stats", app.RequireAuth(app.APIStats))
	mux.HandleFunc("GET /api/traffic", app.RequireAuth(app.APITraffic))
	mux.HandleFunc("GET /api/security-events", app.RequireAuth(app.APISecurityEvents))
	mux.HandleFunc("GET /api/attack-map", app.RequireAuth(app.APIAttackMapData))

	mux.HandleFunc("GET /api/hosts", app.RequireAuth(app.APIGetHosts))
	mux.HandleFunc("POST /api/hosts", app.RequireAuth(app.APISaveHost))
	mux.HandleFunc("DELETE /api/hosts/{domain}", app.RequireAuth(app.APIDeleteHost))
	mux.HandleFunc("GET /api/ssl", app.RequireAuth(app.APIGetSSL))
	mux.HandleFunc("POST /api/ssl/upload", app.RequireAuth(app.APIUploadSSL))

	mux.HandleFunc("GET /api/waf/settings", app.RequireAuth(app.APIGetWAFSettings))
	mux.HandleFunc("POST /api/waf/settings", app.RequireAuth(app.APIPostWAFSettings))
	mux.HandleFunc("POST /api/waf/toggle", app.RequireAuth(app.APIWafToggle))
	mux.HandleFunc("GET /api/waf/top-messages", app.RequireAuth(app.APIWAFTopMessages))
	mux.HandleFunc("POST /api/rules/custom", app.RequireAuth(app.APICustomRules))
	mux.HandleFunc("POST /api/rules/configure", app.RequireAuth(app.APIConfigureRules))

	mux.HandleFunc("GET /api/advbot/config", app.RequireAuth(app.APIGetBotConfig))
	mux.HandleFunc("POST /api/advbot/apply", app.RequireAuth(app.APIApplyBotConfig))
	mux.HandleFunc("GET /api/advbot/status", app.RequireAuth(app.APIBotStatus))
	mux.HandleFunc("GET /api/advbot/blocked", app.RequireAuth(app.APIBotBlockedIPs))
	mux.HandleFunc("POST /api/advbot/unblock", app.RequireAuth(app.APIBotUnblock))

	mux.HandleFunc("GET /api/threat-intel/config", app.RequireAuth(app.APIGetThreatIntelConfig))
	mux.HandleFunc("POST /api/threat-intel/sync", app.RequireAuth(app.APIForceSyncIntel))
	mux.HandleFunc("GET /api/threat-intel/blocked", app.RequireAuth(app.APIGetThreatIntelBlocked))
	mux.HandleFunc("GET /api/ip-reputations", app.RequireAuth(app.APIIPReputations))

	mux.HandleFunc("GET /api/vpatch/config", app.RequireAuth(app.APIGetVPatchConfig))
	mux.HandleFunc("POST /api/vpatch/apply", app.RequireAuth(app.APIApplyVPatchConfig))
	mux.HandleFunc("POST /api/vpatch/reload", app.RequireAuth(app.APIReloadVPatch))
	mux.HandleFunc("GET /api/vpatch/status", app.RequireAuth(app.APIVPatchStatus))

	mux.HandleFunc("GET /api/dlp/config", app.RequireAuth(app.APIGetDLPConfig))
	mux.HandleFunc("POST /api/dlp/apply", app.RequireAuth(app.APIApplyDLPConfig))
	mux.HandleFunc("GET /api/dlp/events", app.RequireAuth(app.APIDLPEvents))
	mux.HandleFunc("POST /api/dlp/clear-events", app.RequireAuth(app.APIDLPClearEvents))

	mux.HandleFunc("GET /api/wp-security/config", app.RequireAuth(app.APIGetWPSecConfig))
	mux.HandleFunc("POST /api/wp-security/apply", app.RequireAuth(app.APIApplyWPSecConfig))

	mux.HandleFunc("POST /api/malware-scan/start", app.RequireAuth(app.APIStartMalwareScan))
	mux.HandleFunc("GET /api/malware-scan/history", app.RequireAuth(app.APIMalwareScanHistory))

	mux.HandleFunc("GET /api/system/nginx-status", app.RequireAuth(app.APINginxStatus))
	mux.HandleFunc("GET /api/system/server-health", app.RequireAuth(app.APIServerHealth))

	mux.HandleFunc("GET /api/reports/security/download", app.RequireAuth(app.APIDownloadSecurityReport))
	mux.HandleFunc("GET /api/reports/attack/download", app.RequireAuth(app.APIDownloadAttackReport))

	return mux, nil
}
