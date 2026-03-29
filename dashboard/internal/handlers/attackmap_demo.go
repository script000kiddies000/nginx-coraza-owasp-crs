package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/logs"
	"flux-waf/internal/models"
)

// WafX-style detection categories (codes match live map UI).
var attackMapCategoryDefs = []struct {
	Code  string
	Label string
}{
	{"ME", "Method Enforcement"},
	{"SCAN", "Scanner Detection"},
	{"PE", "Protocol Enforcement"},
	{"PA", "Protocol Attack"},
	{"MP", "Multipart Attack"},
	{"LFI", "Local File Inclusion"},
	{"RFI", "Remote File Inclusion"},
	{"RCE", "Remote Code Execution"},
	{"PHP", "PHP Attack"},
	{"GA", "Generic Attack"},
	{"XSS", "Cross-Site Scripting"},
	{"SQLI", "SQL Injection"},
	{"SF", "Session Fixation"},
	{"JAVA", "Java Attack"},
	{"DL", "Data Leakage"},
	{"WSH", "Web Shells"},
}

// attackMapCategory is one row for the left sidebar.
type attackMapCategory struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// attackMapLogEntry is one row for the global feed + audit trail.
type attackMapLogEntry struct {
	TS         string `json:"ts"`
	Time       string `json:"time"` // HH:MM:SS display
	TypeCode   string `json:"type_code"`
	SourceIP   string `json:"source_ip"`
	Country    string `json:"country"` // display name
	Source     string `json:"source"`
	Target     string `json:"target"`
	AttackType string `json:"attack_type"`
	RuleID     string `json:"rule_id,omitempty"`
}

type attackMapPayload struct {
	Demo        bool                    `json:"demo"`
	Label       string                  `json:"label"`
	TotalToday  int                     `json:"total_today"`
	TargetLabel string                  `json:"target_label"`
	Points      []models.AttackMapPoint `json:"points"`
	Categories  []attackMapCategory     `json:"categories"`
	Logs24h     []attackMapLogEntry     `json:"logs_24h"`
}

var countryDisplay = map[string]string{
	"CN": "China", "RU": "Russia", "GB": "United Kingdom", "US": "United States",
	"DE": "Germany", "FR": "France", "JP": "Japan", "MX": "Mexico", "BR": "Brazil",
	"SG": "Singapore", "IN": "India", "EG": "Egypt", "ID": "Indonesia", "NL": "Netherlands",
	"KR": "South Korea", "AU": "Australia", "CA": "Canada", "IT": "Italy", "ES": "Spain",
	"TR": "Turkey", "UA": "Ukraine", "VN": "Vietnam", "TH": "Thailand", "MY": "Malaysia",
}

var countryCentroid = map[string]struct {
	lat float64
	lon float64
}{
	"ID": {-2.5, 118.0},
	"CN": {35.9, 104.2}, "RU": {61.5, 105.3}, "GB": {55.4, -3.4}, "US": {39.8, -98.6},
	"DE": {51.1, 10.4}, "FR": {46.2, 2.2}, "JP": {36.2, 138.3}, "MX": {23.6, -102.5},
	"BR": {-14.2, -51.9}, "SG": {1.3, 103.8}, "IN": {20.6, 78.9}, "EG": {26.8, 30.8},
	"NL": {52.1, 5.3}, "KR": {36.5, 127.8}, "AU": {-25.3, 133.8}, "CA": {56.1, -106.3},
	"IT": {41.9, 12.6}, "ES": {40.5, -3.7}, "TR": {39.1, 35.2}, "UA": {48.4, 31.2},
	"VN": {14.1, 108.3}, "TH": {15.8, 100.9}, "MY": {4.2, 102.0},
}

func labelForCountry(code string) string {
	if n, ok := countryDisplay[code]; ok {
		return n
	}
	return code
}

func toStr(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	switch x := v.(type) {
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}

func parseStatus(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func detectAttackCode(uri, method string, status int) string {
	u := strings.ToLower(uri)
	switch {
	case strings.Contains(u, "../") || strings.Contains(u, "%2e%2e") || strings.Contains(u, "..%2f"):
		return "LFI"
	case strings.Contains(u, "<script") || strings.Contains(u, "%3cscript"):
		return "XSS"
	case strings.Contains(u, "union+select") || strings.Contains(u, "union%20select") || strings.Contains(u, "' or '1'='1"):
		return "SQLI"
	}
	m := strings.ToUpper(method)
	if m != "GET" && m != "POST" && m != "HEAD" && m != "PUT" && m != "PATCH" && m != "DELETE" && m != "OPTIONS" {
		return "ME"
	}
	if status == 429 {
		return "SCAN"
	}
	return "PE"
}

func buildLiveAttackMap(entries []map[string]any) attackMapPayload {
	const tgtLat, tgtLon = -2.5, 118.0
	targetCountry := "ID"
	targetLabel := "Protected origin · Indonesia"
	catCount := make(map[string]int)
	for _, c := range attackMapCategoryDefs {
		catCount[c.Code] = 0
	}

	type pointAgg struct {
		country string
		code    string
		count   int
	}
	pointByCountryCode := map[string]*pointAgg{}
	logRows := make([]attackMapLogEntry, 0, 128)

	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	for _, e := range entries {
		ts, err := time.Parse(time.RFC3339, strings.TrimSpace(toStr(e["time"])))
		if err != nil || ts.Before(cutoff) {
			continue
		}
		status := parseStatus(e["status"])
		if status < 400 {
			continue
		}

		cc := strings.ToUpper(strings.TrimSpace(toStr(e["country"])))
		if len(cc) != 2 {
			cc = "ID"
		}
		method := strings.ToUpper(strings.TrimSpace(toStr(e["method"])))
		uri := toStr(e["uri"])
		code := detectAttackCode(uri, method, status)
		catCount[code]++

		key := cc + "|" + code
		pa, ok := pointByCountryCode[key]
		if !ok {
			pa = &pointAgg{country: cc, code: code}
			pointByCountryCode[key] = pa
		}
		pa.count++

		logRows = append(logRows, attackMapLogEntry{
			TS:         ts.Format(time.RFC3339),
			Time:       ts.Format("15:04:05"),
			TypeCode:   code,
			SourceIP:   toStr(e["remote_addr"]),
			Country:    labelForCountry(cc),
			Source:     labelForCountry(cc) + " (" + cc + ")",
			Target:     targetLabel,
			AttackType: code,
		})
	}

	sort.Slice(logRows, func(i, j int) bool { return logRows[i].TS > logRows[j].TS })
	if len(logRows) > 200 {
		logRows = logRows[:200]
	}

	points := make([]models.AttackMapPoint, 0, len(pointByCountryCode))
	for _, p := range pointByCountryCode {
		centroid, ok := countryCentroid[p.country]
		if !ok {
			continue
		}
		points = append(points, models.AttackMapPoint{
			SourceLat:     centroid.lat,
			SourceLon:     centroid.lon,
			SourceCountry: p.country,
			SourceCity:    labelForCountry(p.country),
			AttackType:    p.code,
			TargetLat:     tgtLat,
			TargetLon:     tgtLon,
			TargetCountry: targetCountry,
			Count:         p.count,
		})
	}

	categories := make([]attackMapCategory, 0, len(attackMapCategoryDefs))
	total := 0
	for _, d := range attackMapCategoryDefs {
		n := catCount[d.Code]
		total += n
		categories = append(categories, attackMapCategory{
			Code:  d.Code,
			Label: d.Label,
			Count: n,
		})
	}

	return attackMapPayload{
		Demo:        false,
		Label:       "Live data from access_json.log (status 4xx/5xx, last 24h)",
		TotalToday:  total,
		TargetLabel: targetLabel,
		Points:      points,
		Categories:  categories,
		Logs24h:     logRows,
	}
}

func (app *App) APIAttackMapData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries, err := logs.ReadAccessJSONRecent(logs.DefaultAccessJSONLog, 128<<20, 300000)
	if err != nil {
		_ = json.NewEncoder(w).Encode(attackMapPayload{
			Demo:       false,
			Label:      "Failed to read access_json.log: " + err.Error(),
			TotalToday: 0,
			Points:     []models.AttackMapPoint{},
			Categories: []attackMapCategory{},
			Logs24h:    []attackMapLogEntry{},
		})
		return
	}
	_ = json.NewEncoder(w).Encode(buildLiveAttackMap(entries))
}
