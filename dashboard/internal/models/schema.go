package models

import "time"

// ── Auth & Sessions ───────────────────────────────────────────────────────────

type UserAccount struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash,omitempty"`
	Role         string `json:"role"`
}

type Session struct {
	Username string    `json:"username"`
	Expires  time.Time `json:"expires"`
}

// ── Host / Reverse Proxy ──────────────────────────────────────────────────────

type HostConfig struct {
	Domain          string   `json:"domain"`
	Enabled         bool     `json:"enabled"`
	UpstreamServers []string `json:"upstream_servers"`
	LBAlgorithm     string   `json:"lb_algorithm"` // "round_robin" | "least_conn" | "ip_hash"
	WAFMode         string   `json:"waf_mode"`     // "On" | "Off" | "DetectionOnly"
	SSLEnabled      bool     `json:"ssl_enabled"`
	SSLCert         string   `json:"ssl_cert"` // path to .crt file
	SSLKey          string   `json:"ssl_key"`  // path to .key file
	HTTP2Enabled    bool     `json:"http2_enabled"`
	HTTP3Enabled    bool     `json:"http3_enabled"`
	ExcludePaths    []string `json:"waf_exclude_paths"`
}

// ── WAF Settings ──────────────────────────────────────────────────────────────

type WAFSettings struct {
	Mode           string `json:"mode"`           // "On" | "Off" | "DetectionOnly"
	ParanoiaLevel  int    `json:"paranoia_level"` // 1-4
	AnomalyInbound int    `json:"anomaly_inbound"`
}

// ── Bot Protection ────────────────────────────────────────────────────────────

type AdvBotConfig struct {
	AntibotEnabled     bool     `json:"antibot_enabled"`
	BotThreshold       int      `json:"bot_threshold"`
	ChallengeType      string   `json:"challenge_type"`
	LimitLoginEnabled  bool     `json:"limit_login_enabled"`
	LimitLoginRPM      int      `json:"limit_login_rpm"`
	CredStuffEnabled   bool     `json:"cred_stuff_enabled"`
	CredStuffWindowMin int      `json:"cred_stuff_window_min"`
	JA3Enabled         bool     `json:"ja3_enabled"`
	WhitelistIPs       []string `json:"whitelist_ips"`
}

// ── Threat Intelligence ───────────────────────────────────────────────────────

type ThreatIntelData struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	ISP                  string `json:"isp"`
	TotalReports         int    `json:"totalReports"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
}

type ThreatIntelConfig struct {
	Enabled        bool     `json:"enabled"`
	UpdateInterval int      `json:"update_interval"` // hours
	BlockScore     int      `json:"block_score"`     // AbuseIPDB confidence threshold
	WhitelistIPs   []string `json:"whitelist_ips"`
	LastSync       string   `json:"last_sync"`
	IPCount        int      `json:"ip_count"`
}

// ── DLP / Data Guard ──────────────────────────────────────────────────────────

type DLPConfig struct {
	DLPEnabled     bool     `json:"dlp_enabled"`
	DLPActive      bool     `json:"dlp_active"`
	AutoQuarantine bool     `json:"auto_quarantine"`
	DLPPatterns    []string `json:"dlp_patterns"`
}

// ── Virtual Patching (CRS companion / CVE-style rules file) ───────────────────

type VirtualPatchConfig struct {
	Enabled    bool   `json:"enabled"`
	Aggressive bool   `json:"aggressive"` // future: tighter SecAction presets
	LastReload string `json:"last_reload"`
	Notes      string `json:"notes"`
}

// ── WordPress Security (nginx snippet generation) ───────────────────────────

type WPSecurityConfig struct {
	Enabled             bool   `json:"enabled"`
	BlockXMLRPC         bool   `json:"block_xmlrpc"`
	BlockSensitiveFiles bool   `json:"block_sensitive_files"`
	BlockUploadsPHP     bool   `json:"block_uploads_php"`
	BlockAuthorEnum     bool   `json:"block_author_enum"`
	BlockScannerUA      bool   `json:"block_scanner_ua"`
	StripAssetVersion   bool   `json:"strip_asset_version"`
	Notes               string `json:"notes"`
	LastWritten         string `json:"last_written"`
}

// ── DLP events (dashboard log) ───────────────────────────────────────────────

type DLPEvent struct {
	Time     string `json:"time"`
	Type     string `json:"type"`
	ClientIP string `json:"client_ip"`
	URI      string `json:"uri"`
	Action   string `json:"action"`
	Message  string `json:"message"`
}

// ── Bot blocklist (manual / future worker) ───────────────────────────────────

type BotBlockedEntry struct {
	IP        string `json:"ip"`
	BlockedAt string `json:"blocked_at"`
	Reason    string `json:"reason"`
}

// ── System Monitoring (on-the-fly, not stored in DB) ─────────────────────────

type NginxStatus struct {
	ActiveConnections int `json:"active_connections"`
	Accepts           int `json:"accepts"`
	Handled           int `json:"handled"`
	Requests          int `json:"requests"`
	Reading           int `json:"reading"`
	Writing           int `json:"writing"`
	Waiting           int `json:"waiting"`
}

type ServerHealth struct {
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	MemoryTotalGB   float64 `json:"memory_total_gb"`
	MemoryUsedGB    float64 `json:"memory_used_gb"`
	DiskTotalGB     float64 `json:"disk_total_gb"`
	DiskUsedGB      float64 `json:"disk_used_gb"`
	UptimeSeconds   uint64  `json:"uptime_seconds"`
	NginxDaemonUp   bool    `json:"nginx_daemon_up"`
}

// ── Attack Map (geo-spatial) ──────────────────────────────────────────────────

type AttackMapPoint struct {
	SourceLat     float64 `json:"source_lat"`
	SourceLon     float64 `json:"source_lon"`
	SourceCountry string  `json:"source_country"`
	SourceCity    string  `json:"source_city"`
	AttackType    string  `json:"attack_type"`
	TargetLat     float64 `json:"target_lat"`
	TargetLon     float64 `json:"target_lon"`
	TargetCountry string  `json:"target_country"`
	Count         int     `json:"count"`
}

// ── Hourly Stats (stored in DB) ───────────────────────────────────────────────

type HourlyStats struct {
	Hour          string `json:"hour"` // "2026-03-22-14"
	TotalRequests int    `json:"total_requests"`
	BlockedCount  int    `json:"blocked_count"`
	AllowedCount  int    `json:"allowed_count"`
}

// ── Template Data (passed to html/template) ───────────────────────────────────

type FlashMsg struct {
	Type    string // "success" | "error" | "warning"
	Message string
}

type PageData struct {
	Title      string
	ActiveMenu string
	Username   string
	Flash      FlashMsg
	Data       any
}

// SecurityEvent — satu baris ringkas dari coraza_audit.log (disimpan di BoltDB).
type SecurityEvent struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Action   string `json:"action"`
	URI      string `json:"uri"`
}
