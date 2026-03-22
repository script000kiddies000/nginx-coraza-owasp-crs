package store

import (
	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
)

const (
	keyWAF      = "waf"
	keyAdvBot   = "advbot"
	keyDLP      = "dlp"
	keyThreatIntel = "threat_intel"
)

// ── WAF Settings ──────────────────────────────────────────────────────────────

func GetWAFSettings(db *bolt.DB) models.WAFSettings {
	var s models.WAFSettings
	_ = get(db, BucketSettings, keyWAF, &s)
	if s.Mode == "" {
		s.Mode = "On"
		s.ParanoiaLevel = 1
		s.AnomalyInbound = 5
	}
	return s
}

func SaveWAFSettings(db *bolt.DB, s models.WAFSettings) error {
	return put(db, BucketSettings, keyWAF, s)
}

// ── Bot Config ────────────────────────────────────────────────────────────────

func GetAdvBotConfig(db *bolt.DB) models.AdvBotConfig {
	var c models.AdvBotConfig
	_ = get(db, BucketSettings, keyAdvBot, &c)
	if c.BotThreshold == 0 {
		c.BotThreshold = 100
		c.LimitLoginRPM = 10
		c.CredStuffWindowMin = 5
	}
	return c
}

func SaveAdvBotConfig(db *bolt.DB, c models.AdvBotConfig) error {
	return put(db, BucketSettings, keyAdvBot, c)
}

// ── DLP Config ────────────────────────────────────────────────────────────────

func GetDLPConfig(db *bolt.DB) models.DLPConfig {
	var c models.DLPConfig
	_ = get(db, BucketSettings, keyDLP, &c)
	return c
}

func SaveDLPConfig(db *bolt.DB, c models.DLPConfig) error {
	return put(db, BucketSettings, keyDLP, c)
}

// ── Threat Intel Config ───────────────────────────────────────────────────────

func GetThreatIntelConfig(db *bolt.DB) models.ThreatIntelConfig {
	var c models.ThreatIntelConfig
	_ = get(db, BucketSettings, keyThreatIntel, &c)
	if c.UpdateInterval == 0 {
		c.UpdateInterval = 24
		c.BlockScore = 90
		c.Enabled = true
	}
	return c
}

func SaveThreatIntelConfig(db *bolt.DB, c models.ThreatIntelConfig) error {
	return put(db, BucketSettings, keyThreatIntel, c)
}

// ── Hourly Stats ──────────────────────────────────────────────────────────────

func GetHourlyStat(db *bolt.DB, hour string) models.HourlyStats {
	var s models.HourlyStats
	_ = get(db, BucketStatsHourly, hour, &s)
	s.Hour = hour
	return s
}

func SaveHourlyStat(db *bolt.DB, s models.HourlyStats) error {
	return put(db, BucketStatsHourly, s.Hour, s)
}
