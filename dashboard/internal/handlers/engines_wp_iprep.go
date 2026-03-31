package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
)

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
