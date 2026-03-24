package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"flux-waf/internal/logs"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
)

const geoLiteCountryPath = "/etc/nginx/geoip/GeoLite2-Country.mmdb"

// APIDashboardAnalytics serves GET /api/dashboard/analytics?range=24h|7d|30d
func (app *App) APIDashboardAnalytics(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	var window time.Duration
	maxLines := 15000
	maxBytes := int64(16 << 20)
	switch rng {
	case "7d":
		window = 7 * 24 * time.Hour
		maxLines = 40000
		maxBytes = 48 << 20
	case "30d":
		window = 30 * 24 * time.Hour
		maxLines = 80000
		maxBytes = 64 << 20
	default:
		rng = "24h"
		window = 24 * time.Hour
	}

	now := time.Now().UTC()
	windowStart := now.Add(-window)
	windowEnd := now

	entries, err := logs.ReadAccessJSONRecent(logs.DefaultAccessJSONLog, maxBytes, maxLines)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	analytics := logs.BuildDashboardAnalytics(entries, windowStart, windowEnd, rng)

	hosts, _ := store.ListHosts(app.DB)
	enabled := 0
	for _, h := range hosts {
		if h.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		enabled = len(hosts)
	}
	analytics.Summary.ActiveHosts = enabled

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(analytics)
}

// APIDashboardProtection serves GET /api/dashboard/protection — layer status for UI.
func (app *App) APIDashboardProtection(w http.ResponseWriter, r *http.Request) {
	waf := store.GetWAFSettings(app.DB)
	tiPath := threatIntelIPRulesPath()
	ti := threatintel.ReadIPRulesInfo(tiPath, 1)

	geoOK := false
	if st, err := os.Stat(geoLiteCountryPath); err == nil && st.Size() > 0 {
		geoOK = true
	}

	threatState := "pending"
	threatDetail := "Sync feeds / run sync"
	if ti.DenyCount > 0 {
		threatState = "active"
		threatDetail = "IP rules loaded"
	} else if ti.ReadError != "" && ti.ReadError != "file not found" {
		threatState = "warn"
		threatDetail = ti.ReadError
	}

	crs := "loaded"
	if waf.Mode == "Off" {
		crs = "off"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"coraza_waf": map[string]string{
			"state":  wafStateLabel(waf.Mode),
			"detail": waf.Mode,
		},
		"owasp_crs": map[string]string{
			"state":  crs,
			"detail": "CRS v4",
		},
		"geoip": map[string]string{
			"state":  ternaryStr(geoOK, "active", "inactive"),
			"detail": ternaryStr(geoOK, "Country DB", "MMDB missing"),
		},
		"threat_intel": map[string]string{
			"state":  threatState,
			"detail": threatDetail,
		},
		"tls_ja": map[string]string{
			"state":  "active",
			"detail": "JA3 / JA4",
		},
		"dlp": map[string]string{
			"state":  "active",
			"detail": "Request body rules",
		},
	})
}

func wafStateLabel(mode string) string {
	switch mode {
	case "On":
		return "active"
	case "DetectionOnly":
		return "detect"
	default:
		return "inactive"
	}
}

func ternaryStr(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}
