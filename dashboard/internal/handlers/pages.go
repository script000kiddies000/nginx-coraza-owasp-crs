package handlers

import (
	"net/http"

	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

// ── Dashboard ─────────────────────────────────────────────────────────────────

func (app *App) PageDashboard(w http.ResponseWriter, r *http.Request) {
	hosts, _ := store.ListHosts(app.DB)
	waf := store.GetWAFSettings(app.DB)

	app.render(w, r, "dashboard", models.PageData{
		Title:      "Dashboard",
		ActiveMenu: "dashboard",
		Data: map[string]any{
			"HostCount": len(hosts),
			"WAFMode":   waf.Mode,
		},
	})
}

// ── Edge Network ──────────────────────────────────────────────────────────────

func (app *App) PageHosts(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "hosts", models.PageData{
		Title:      "Hosts & Upstreams",
		ActiveMenu: "hosts",
	})
}

func (app *App) PageSSL(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "_stub", models.PageData{Title: "SSL / TLS", ActiveMenu: "ssl"})
}

// ── WAF ───────────────────────────────────────────────────────────────────────

func (app *App) PageWAFSettings(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "waf-settings", models.PageData{Title: "WAF Settings", ActiveMenu: "wafsettings"})
}

func (app *App) PageRules(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "custom-rules", models.PageData{Title: "Custom Rules", ActiveMenu: "rules"})
}

// ── Security Engines ──────────────────────────────────────────────────────────

func (app *App) PageVirtualPatching(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "virtual-patching", models.PageData{Title: "Virtual Patching", ActiveMenu: "vpatch"})
}

func (app *App) PageGeoBlocking(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "geo-blocking", models.PageData{Title: "Geo IP Blocking", ActiveMenu: "geoblock"})
}

func (app *App) PageBotManagement(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "bot-management", models.PageData{Title: "Bot Management", ActiveMenu: "botmgmt"})
}

func (app *App) PageIPReputations(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "ip-reputations", models.PageData{Title: "IP Reputations", ActiveMenu: "iprep"})
}

func (app *App) PageWPSecurity(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "wordpress-security", models.PageData{Title: "WordPress Security", ActiveMenu: "wpsec"})
}

func (app *App) PageDataGuard(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "data-guard", models.PageData{Title: "Data Guard (DLP)", ActiveMenu: "dlp"})
}

// ── Logs ──────────────────────────────────────────────────────────────────────

func (app *App) PageSecurityLogs(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "security-logs", models.PageData{Title: "Security Events", ActiveMenu: "seclogs"})
}

func (app *App) PageLogs(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "access-logs", models.PageData{Title: "Access Logs", ActiveMenu: "logs"})
}

func (app *App) PageAttackMap(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "attack-map", models.PageData{Title: "Threat Live Map", ActiveMenu: "attackmap"})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func (app *App) PageSecurityReport(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "security-report", models.PageData{Title: "Security Report", ActiveMenu: "secreport"})
}

func (app *App) PageAttackReport(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "attack-report", models.PageData{Title: "Attack Report", ActiveMenu: "atkreport"})
}

func (app *App) PageMalwareScan(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "_stub", models.PageData{Title: "Malware Scan", ActiveMenu: "malware"})
}

// ── Monitoring ────────────────────────────────────────────────────────────────

func (app *App) PageNginxMonitoring(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "nginx-monitoring", models.PageData{Title: "Nginx Status", ActiveMenu: "nginx-mon"})
}

func (app *App) PageServerMonitoring(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "server-health", models.PageData{Title: "Server Health", ActiveMenu: "srv-mon"})
}

// ── Settings ──────────────────────────────────────────────────────────────────

func (app *App) PageSettings(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "settings", models.PageData{
		Title:      "Settings",
		ActiveMenu: "settings",
	})
}

func (app *App) PageSettingsUsers(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "settings-users", models.PageData{
		Title:      "User Management",
		ActiveMenu: "users",
	})
}

func (app *App) PageThreatIntel(w http.ResponseWriter, r *http.Request) {
	app.render(w, r, "threat-intel", models.PageData{
		Title:      "Threat Intelligence",
		ActiveMenu: "threatintel",
	})
}
