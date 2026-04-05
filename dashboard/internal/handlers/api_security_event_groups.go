package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/securityevent"
	"flux-waf/internal/store"
)

// SecurityEventGroupRow is one aggregated row (IP + host) for the Events tab.
type SecurityEventGroupRow struct {
	ClientIP    string `json:"client_ip"`
	Country     string `json:"country"`
	Application string `json:"application"` // hostname / host:port (bukan URL penuh)
	CountHigh   int    `json:"count_high"`
	CountMedium int    `json:"count_medium"`
	CountLow    int    `json:"count_low"`
	StartAt     string `json:"start_at"`
	EndAt       string `json:"end_at"`
	DurationMin int    `json:"duration_minutes"`
}

type securityEventGroupsResponse struct {
	Rows       []SecurityEventGroupRow `json:"rows"`
	Total      int                     `json:"total"`
	Page       int                     `json:"page"`
	PerPage    int                     `json:"per_page"`
	TotalPages int                     `json:"total_pages"`
}

// APISecurityEventGroups serves GET /api/security-events/groups — aggregated by attacker IP + application.
func (app *App) APISecurityEventGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ipQ := strings.TrimSpace(q.Get("ip"))
	domainQ := strings.ToLower(strings.TrimSpace(q.Get("domain")))
	portQ := strings.TrimSpace(q.Get("port"))
	startQ := strings.TrimSpace(q.Get("start"))
	endQ := strings.TrimSpace(q.Get("end"))

	page := 1
	if p := q.Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	perPage := 20
	if pp := q.Get("per_page"); pp != "" {
		if n, err := strconv.Atoi(pp); err == nil && n > 0 && n <= 200 {
			perPage = n
		}
	}

	var winStart, winEnd time.Time
	var hasStart, hasEnd bool
	if startQ != "" {
		if t, ok := parseSecurityEventTime(startQ); ok {
			winStart = t
			hasStart = true
		}
	}
	if endQ != "" {
		if t, ok := parseSecurityEventTime(endQ); ok {
			winEnd = t
			hasEnd = true
		}
	}

	events, err := store.ListSecurityEvents(app.DB, 3000)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []models.SecurityEvent{}
	}

	filtered := make([]models.SecurityEvent, 0, len(events))
	for _, ev := range events {
		if ipQ != "" && !strings.Contains(strings.ToLower(ev.ClientIP), strings.ToLower(ipQ)) {
			continue
		}
		dom := applicationDomain(ev.URI, ev.Host)
		if domainQ != "" && !strings.Contains(dom, domainQ) {
			continue
		}
		if portQ != "" {
			if !uriMatchesPort(ev.URI, portQ, ev.Host) {
				continue
			}
		}
		if et, ok := parseSecurityEventTime(ev.Time); ok {
			if hasStart && et.Before(winStart) {
				continue
			}
			if hasEnd && et.After(winEnd) {
				continue
			}
		} else if hasStart || hasEnd {
			continue
		}
		filtered = append(filtered, ev)
	}

	type agg struct {
		clientIP    string
		application string
		high, med   int
		low         int
		minT, maxT  time.Time
		hasT        bool
	}
	byKey := make(map[string]*agg)

	for _, ev := range filtered {
		dom := applicationDomain(ev.URI, ev.Host)
		key := ev.ClientIP + "\x00" + dom
		a, ok := byKey[key]
		if !ok {
			a = &agg{clientIP: ev.ClientIP, application: dom}
			byKey[key] = a
		}
		switch securityevent.EffectiveSeverity(ev) {
		case "high":
			a.high++
		case "medium":
			a.med++
		default:
			a.low++
		}
		if et, ok := parseSecurityEventTime(ev.Time); ok {
			if !a.hasT {
				a.minT, a.maxT = et, et
				a.hasT = true
			} else {
				if et.Before(a.minT) {
					a.minT = et
				}
				if et.After(a.maxT) {
					a.maxT = et
				}
			}
		}
	}

	rows := make([]SecurityEventGroupRow, 0, len(byKey))
	for _, a := range byKey {
		r := SecurityEventGroupRow{
			ClientIP:    a.clientIP,
			Country:     "", // optional: wire GeoLite later
			Application: a.application,
			CountHigh:   a.high,
			CountMedium: a.med,
			CountLow:    a.low,
		}
		if a.hasT {
			r.StartAt = a.minT.UTC().Format(time.RFC3339)
			r.EndAt = a.maxT.UTC().Format(time.RFC3339)
			d := a.maxT.Sub(a.minT)
			r.DurationMin = int(d.Minutes())
			if r.DurationMin < 0 {
				r.DurationMin = 0
			}
		}
		rows = append(rows, r)
	}

	sort.Slice(rows, func(i, j int) bool {
		ti, ok1 := parseSecurityEventTime(rows[i].EndAt)
		tj, ok2 := parseSecurityEventTime(rows[j].EndAt)
		if ok1 && ok2 {
			return ti.After(tj)
		}
		return rows[i].ClientIP < rows[j].ClientIP
	})

	total := len(rows)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	pageRows := rows[start:end]

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(securityEventGroupsResponse{
		Rows:       pageRows,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	})
}

// applicationDomain returns hostname (lowercase), dengan port bila non-default: app.example.com atau app.example.com:8443.
// Jika tidak ada host di URI/header, fallback potongan path agar baris tetap terkelompok.
func applicationDomain(uri, hostHeader string) string {
	uri = strings.TrimSpace(uri)
	hostHeader = strings.TrimSpace(hostHeader)

	if uri != "" {
		u, err := url.Parse(uri)
		if err == nil && u.Host != "" {
			return strings.ToLower(u.Host)
		}
		if strings.HasPrefix(uri, "//") {
			if u, err := url.Parse("http:" + uri); err == nil && u.Host != "" {
				return strings.ToLower(u.Host)
			}
		}
	}
	if hostHeader != "" {
		return strings.ToLower(hostHeader)
	}
	if uri == "" {
		return "—"
	}
	if len(uri) > 64 {
		return uri[:64] + "…"
	}
	return uri
}

func uriMatchesPort(uri, port, hostHeader string) bool {
	port = strings.TrimSpace(port)
	if port == "" {
		return true
	}
	uri = strings.TrimSpace(uri)
	hostHeader = strings.TrimSpace(hostHeader)

	u, err := url.Parse(uri)
	if err != nil || u == nil || u.Host == "" {
		u, err = url.Parse("http://" + uri)
	}
	if err == nil && u != nil && u.Host != "" {
		if p := u.Port(); p == port {
			return true
		}
		if u.Port() == "" {
			if u.Scheme == "https" && port == "443" {
				return true
			}
			if (u.Scheme == "http" || u.Scheme == "") && port == "80" {
				return true
			}
		}
	}
	if strings.Contains(uri, ":"+port) {
		return true
	}
	if hostHeader != "" && strings.Contains(hostHeader, ":"+port) {
		return true
	}
	return false
}
