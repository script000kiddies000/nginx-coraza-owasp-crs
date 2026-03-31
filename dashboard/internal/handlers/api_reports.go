package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/store"
)

type attackReportItem struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Action   string `json:"action"`
	URI      string `json:"uri"`
	Domain   string `json:"domain"`
}

// APIAttackReport returns aggregated attack report data for dashboard page.
func (app *App) APIAttackReport(w http.ResponseWriter, r *http.Request) {
	limit := 5000
	if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 20000 {
		limit = 20000
	}

	period := strings.TrimSpace(r.URL.Query().Get("period"))
	if period == "" {
		period = "24h"
	}
	cutoff := time.Time{}
	now := time.Now()
	switch period {
	case "24h":
		cutoff = now.Add(-24 * time.Hour)
	case "7d":
		cutoff = now.Add(-7 * 24 * time.Hour)
	case "30d":
		cutoff = now.Add(-30 * 24 * time.Hour)
	case "all":
		// no cutoff
	default:
		jsonError(w, "period must be one of: 24h, 7d, 30d, all", http.StatusBadRequest)
		return
	}

	events, err := store.ListSecurityEvents(app.DB, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	items := make([]attackReportItem, 0, len(events))
	topRules := map[string]int{}
	topIPs := map[string]int{}
	domainHits := map[string]int{}
	blocked := 0
	detected := 0

	for _, e := range events {
		if !cutoff.IsZero() {
			t, ok := parseSecurityEventTime(e.Time)
			if !ok || t.Before(cutoff) {
				continue
			}
		}
		action := strings.ToLower(strings.TrimSpace(e.Action))
		if strings.Contains(action, "block") || action == "deny" {
			blocked++
		} else {
			detected++
		}
		rule := strings.TrimSpace(e.RuleID)
		if rule == "" {
			rule = "—"
		}
		ip := strings.TrimSpace(e.ClientIP)
		if ip == "" {
			ip = "—"
		}
		domain := deriveDomainFromURI(e.URI)
		topRules[rule]++
		topIPs[ip]++
		domainHits[domain]++
		items = append(items, attackReportItem{
			Time:     e.Time,
			ClientIP: ip,
			RuleID:   rule,
			Message:  e.Message,
			Action:   e.Action,
			URI:      e.URI,
			Domain:   domain,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"generated_at": time.Now().Format(time.RFC3339),
		"period":       period,
		"summary": map[string]int{
			"total":    len(items),
			"blocked":  blocked,
			"detected": detected,
			"domains":  len(domainHits),
		},
		"top_rules":   toTopPairs(topRules, "id", 12),
		"top_ips":     toTopPairs(topIPs, "ip", 12),
		"domain_hits": toTopPairs(domainHits, "domain", 20),
		"events":      items,
	})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func (app *App) APIDownloadSecurityReport(w http.ResponseWriter, r *http.Request) { stubJSON(w) }
func (app *App) APIDownloadAttackReport(w http.ResponseWriter, r *http.Request) {
	req := r.Clone(r.Context())
	q := req.URL.Query()
	if strings.TrimSpace(q.Get("period")) == "" {
		q.Set("period", "all")
	}
	if strings.TrimSpace(q.Get("limit")) == "" {
		q.Set("limit", "20000")
	}
	req.URL.RawQuery = q.Encode()

	rr := &responseCapture{header: http.Header{}}
	app.APIAttackReport(rr, req)
	if rr.status >= 400 {
		w.WriteHeader(rr.status)
		_, _ = w.Write(rr.body)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="attack-report.json"`)
	_, _ = w.Write(rr.body)
}

type responseCapture struct {
	header http.Header
	status int
	body   []byte
}

func (r *responseCapture) Header() http.Header { return r.header }
func (r *responseCapture) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(b), nil
}
func (r *responseCapture) WriteHeader(statusCode int) { r.status = statusCode }

func parseSecurityEventTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05 -0700 MST",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func deriveDomainFromURI(uri string) string {
	u := strings.TrimSpace(uri)
	if u == "" {
		return "unknown"
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		if i := strings.Index(u, "://"); i > -1 {
			hostPortPath := u[i+3:]
			if j := strings.Index(hostPortPath, "/"); j > -1 {
				hostPortPath = hostPortPath[:j]
			}
			if hostPortPath != "" {
				return strings.Split(hostPortPath, ":")[0]
			}
		}
	}
	return "unknown"
}

func toTopPairs(m map[string]int, keyName string, max int) []map[string]any {
	type kv struct {
		K string
		V int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{K: k, V: v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].V == arr[j].V {
			return arr[i].K < arr[j].K
		}
		return arr[i].V > arr[j].V
	})
	if max > 0 && len(arr) > max {
		arr = arr[:max]
	}
	out := make([]map[string]any, 0, len(arr))
	for _, x := range arr {
		out = append(out, map[string]any{
			keyName: x.K,
			"count": x.V,
		})
	}
	return out
}
