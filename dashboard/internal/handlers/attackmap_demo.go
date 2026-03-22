package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

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
	"SG": "Singapore", "IN": "India", "EG": "Egypt", "ID": "Indonesia",
}

func fakeIPv4(rng *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", 1+rng.Intn(223), rng.Intn(256), rng.Intn(256), 1+rng.Intn(254))
}

func labelForCountry(code string) string {
	if n, ok := countryDisplay[code]; ok {
		return n
	}
	return code
}

// buildSampleAttackMap returns demo geo points, category counts, and feed rows.
func buildSampleAttackMap() attackMapPayload {
	const tgtLat, tgtLon = -2.5, 118.0
	targetCountry := "ID"
	targetLabel := "Protected origin · Indonesia"

	sources := []struct {
		lat, lon float64
		country  string
		city     string
	}{
		{39.90, 116.41, "CN", "Beijing"},
		{55.76, 37.62, "RU", "Moscow"},
		{51.51, -0.13, "GB", "London"},
		{37.39, -122.06, "US", "San Jose"},
		{52.52, 13.41, "DE", "Berlin"},
		{48.86, 2.35, "FR", "Paris"},
		{35.68, 139.76, "JP", "Tokyo"},
		{19.43, -99.13, "MX", "Mexico City"},
		{-23.55, -46.63, "BR", "São Paulo"},
		{1.35, 103.82, "SG", "Singapore"},
		{28.61, 77.21, "IN", "New Delhi"},
		{30.04, 31.24, "EG", "Cairo"},
	}

	codes := make([]string, 0, len(attackMapCategoryDefs))
	for _, d := range attackMapCategoryDefs {
		codes = append(codes, d.Code)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano() / 3600))

	points := make([]models.AttackMapPoint, 0, len(sources))
	catCount := make(map[string]int)
	for _, c := range attackMapCategoryDefs {
		catCount[c.Code] = rng.Intn(8) // base noise
	}

	for _, s := range sources {
		code := codes[rng.Intn(len(codes))]
		n := 15 + rng.Intn(140)
		catCount[code] += n
		points = append(points, models.AttackMapPoint{
			SourceLat:     s.lat,
			SourceLon:     s.lon,
			SourceCountry: s.country,
			SourceCity:    s.city,
			AttackType:    code,
			TargetLat:     tgtLat,
			TargetLon:     tgtLon,
			TargetCountry: targetCountry,
			Count:         n,
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

	codeToLabel := make(map[string]string)
	for _, d := range attackMapCategoryDefs {
		codeToLabel[d.Code] = d.Label
	}

	now := time.Now().UTC()
	logs := make([]attackMapLogEntry, 0, 64)
	for i := 0; i < 64; i++ {
		s := sources[rng.Intn(len(sources))]
		code := codes[rng.Intn(len(codes))]
		rule := fmt.Sprintf("%d", 941100+rng.Intn(800))
		minutesAgo := rng.Intn(24 * 60)
		ts := now.Add(-time.Duration(minutesAgo) * time.Minute)
		logs = append(logs, attackMapLogEntry{
			TS:         ts.Format(time.RFC3339),
			Time:       ts.Format("15:04:05"),
			TypeCode:   code,
			SourceIP:   fakeIPv4(rng),
			Country:    labelForCountry(s.country),
			Source:     fmt.Sprintf("%s (%s)", s.city, s.country),
			Target:     targetLabel,
			AttackType: codeToLabel[code],
			RuleID:     rule,
		})
	}

	return attackMapPayload{
		Demo:        true,
		Label:       "Sample data — integrasi GeoIP + coraza_audit direncanakan di flux_waf_implementation_plan.md (§2.F)",
		TotalToday:  total,
		TargetLabel: targetLabel,
		Points:      points,
		Categories:  categories,
		Logs24h:     logs,
	}
}

func (app *App) APIAttackMapData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildSampleAttackMap())
}
