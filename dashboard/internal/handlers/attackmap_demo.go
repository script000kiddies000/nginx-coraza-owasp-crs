package handlers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"flux-waf/internal/models"
)

// attackMapLogEntry is one synthetic row for the demo feed (last 24h window).
type attackMapLogEntry struct {
	TS         string `json:"ts"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	AttackType string `json:"attack_type"`
	RuleID     string `json:"rule_id,omitempty"`
}

type attackMapPayload struct {
	Demo    bool                   `json:"demo"`
	Label   string                 `json:"label"`
	Points  []models.AttackMapPoint `json:"points"`
	Logs24h []attackMapLogEntry     `json:"logs_24h"`
}

// buildSampleAttackMap returns demo geo points + ~48 log lines spread across 24h.
func buildSampleAttackMap() attackMapPayload {
	// Target: protected origin (contoh — Indonesia)
	const tgtLat, tgtLon = -2.5, 118.0
	targetCountry := "ID"

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

	types := []string{"SQLi", "XSS", "RCE", "Scanner", "LFI", "Protocol", "Bot", "CRS-942"}

	points := make([]models.AttackMapPoint, 0, len(sources))
	rng := rand.New(rand.NewSource(time.Now().UnixNano() / 3600)) // stable-ish per hour
	for _, s := range sources {
		n := 5 + rng.Intn(120)
		points = append(points, models.AttackMapPoint{
			SourceLat:     s.lat,
			SourceLon:     s.lon,
			SourceCountry: s.country,
			SourceCity:    s.city,
			AttackType:    types[rng.Intn(len(types))],
			TargetLat:     tgtLat,
			TargetLon:     tgtLon,
			TargetCountry: targetCountry,
			Count:         n,
		})
	}

	now := time.Now().UTC()
	logs := make([]attackMapLogEntry, 0, 48)
	for i := 0; i < 48; i++ {
		s := sources[rng.Intn(len(sources))]
		at := types[rng.Intn(len(types))]
		rule := fmt.Sprintf("%d", 941100+rng.Intn(800))
		// Acak dalam jendela 24 jam terakhir
		minutesAgo := rng.Intn(24 * 60)
		ts := now.Add(-time.Duration(minutesAgo) * time.Minute)
		logs = append(logs, attackMapLogEntry{
			TS:         ts.Format(time.RFC3339),
			Source:     fmt.Sprintf("%s (%s)", s.city, s.country),
			Target:     "Origin · " + targetCountry,
			AttackType: at,
			RuleID:     rule,
		})
	}

	return attackMapPayload{
		Demo:    true,
		Label:   "Sample data — ganti dengan feed GeoIP/audit nyata pada fase berikutnya",
		Points:  points,
		Logs24h: logs,
	}
}

func (app *App) APIAttackMapData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buildSampleAttackMap())
}
