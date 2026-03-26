package store

import (
	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"strings"
)

const (
	keyWAF      = "waf"
	keyAdvBot   = "advbot"
	keyJA3      = "ja3"
	keyDLP      = "dlp"
	keyThreatIntel = "threat_intel"
	keyACME        = "acme_account"
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

// ── JA3 Config ────────────────────────────────────────────────────────────────

func GetJA3Config(db *bolt.DB) models.JA3Config {
	var c models.JA3Config
	_ = get(db, BucketSettings, keyJA3, &c)
	if len(c.Entries) == 0 && len(c.Hashes) > 0 {
		// Migrate legacy hashes -> named entries.
		ents := make([]models.JA3FingerprintEntry, 0, len(c.Hashes))
		for _, h := range c.Hashes {
			short := h
			if len(short) > 8 {
				short = short[:8]
			}
			ents = append(ents, models.JA3FingerprintEntry{
				Name: "JA3 " + short,
				Hash: h,
				Enabled: true,
				Action:  "block",
				Source:  "legacy",
			})
		}
		c.Entries = ents
		c.Hashes = nil
		_ = put(db, BucketSettings, keyJA3, c)
	}
	if len(c.Entries) == 0 {
		c.Entries = []models.JA3FingerprintEntry{}
	}
	if len(c.JA4Entries) == 0 && len(c.JA4Hashes) > 0 {
		ents := make([]models.JA3FingerprintEntry, 0, len(c.JA4Hashes))
		for _, h := range c.JA4Hashes {
			short := h
			if len(short) > 8 {
				short = short[:8]
			}
			ents = append(ents, models.JA3FingerprintEntry{
				Name: "JA4 " + short,
				Hash: h,
				Enabled: true,
				Action:  "block",
				Source:  "legacy",
			})
		}
		c.JA4Entries = ents
		c.JA4Hashes = nil
		_ = put(db, BucketSettings, keyJA3, c)
	}
	if len(c.JA4Entries) == 0 {
		c.JA4Entries = []models.JA3FingerprintEntry{}
	}

	// Backfill missing per-entry fields for older DB data.
	// Older entries likely only stored `name` + `hash`, so default to enabled+block.
	for i := range c.Entries {
		actionEmpty := strings.TrimSpace(c.Entries[i].Action) == ""
		if actionEmpty {
			c.Entries[i].Action = "block"
			c.Entries[i].Enabled = true
		} else if c.Entries[i].Action != "block" && c.Entries[i].Action != "log" {
			c.Entries[i].Action = "block"
		}
	}
	for i := range c.JA4Entries {
		actionEmpty := strings.TrimSpace(c.JA4Entries[i].Action) == ""
		if actionEmpty {
			c.JA4Entries[i].Action = "block"
			c.JA4Entries[i].Enabled = true
		} else if c.JA4Entries[i].Action != "block" && c.JA4Entries[i].Action != "log" {
			c.JA4Entries[i].Action = "block"
		}
	}
	// default enabled so existing snippet behavior remains active.
	if !c.Enabled {
		// keep false if explicitly saved false with hashes.
		var raw models.JA3Config
		err := get(db, BucketSettings, keyJA3, &raw)
		if err == ErrNotFound {
			c.Enabled = true
		}
	}
	return c
}

func SaveJA3Config(db *bolt.DB, c models.JA3Config) error {
	// Persist new format only.
	c.Hashes = nil
	c.JA4Hashes = nil
	return put(db, BucketSettings, keyJA3, c)
}

// ── DLP Config ────────────────────────────────────────────────────────────────

func defaultDLPPatterns() []string {
	return []string{
		"DLP: Credit Card Number",
		"DLP: Social Security Number",
		"DLP: API Key / Bearer Token",
		"DLP: AWS Access Key",
		"DLP: Private Key (PEM)",
		"DLP: Password field (audit only)",
		"DLP: JWT Token (audit only)",
	}
}

func defaultDLPConfig() models.DLPConfig {
	return models.DLPConfig{
		DLPEnabled:           true,
		DLPActive:            true,
		InspectRequestBody:   true,
		InspectResponseBody:  true,
		MaxBodySizeKB:        12800,
		AlertOnBlock:         true,
		ConfigVersion:        1,
		DLPPatterns:          defaultDLPPatterns(),
	}
}

func normalizeDLPConfig(c *models.DLPConfig) {
	if c.ConfigVersion < 1 {
		if c.MaxBodySizeKB <= 0 {
			c.MaxBodySizeKB = 12800
		}
		c.InspectRequestBody = true
		c.InspectResponseBody = true
		c.AlertOnBlock = true
		c.ConfigVersion = 1
	}
	if c.MaxBodySizeKB <= 0 {
		c.MaxBodySizeKB = 12800
	}
	if c.MaxBodySizeKB < 64 {
		c.MaxBodySizeKB = 64
	}
	if c.MaxBodySizeKB > 524288 {
		c.MaxBodySizeKB = 524288
	}
	if len(c.DLPPatterns) == 0 {
		c.DLPPatterns = defaultDLPPatterns()
	}
}

func GetDLPConfig(db *bolt.DB) models.DLPConfig {
	var c models.DLPConfig
	err := get(db, BucketSettings, keyDLP, &c)
	if err == ErrNotFound {
		def := defaultDLPConfig()
		_ = put(db, BucketSettings, keyDLP, def)
		return def
	}
	if err != nil {
		return defaultDLPConfig()
	}
	normalizeDLPConfig(&c)
	_ = put(db, BucketSettings, keyDLP, c)
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

// ── ACME (Let's Encrypt account key) ─────────────────────────────────────────

func GetACMEAccount(db *bolt.DB) models.ACMEAccountData {
	var a models.ACMEAccountData
	_ = get(db, BucketSettings, keyACME, &a)
	return a
}

func SaveACMEAccount(db *bolt.DB, a models.ACMEAccountData) error {
	return put(db, BucketSettings, keyACME, a)
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
