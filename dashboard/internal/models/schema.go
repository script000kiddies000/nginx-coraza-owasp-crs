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

// ListenPort represents a single port + protocol the server block listens on.
type ListenPort struct {
	Port  int  `json:"port"`
	HTTPS bool `json:"https"`
}

// HostConfig holds the full configuration for a managed application / proxy host.
type HostConfig struct {
	Domain      string `json:"domain"`
	Name        string `json:"name,omitempty"`
	Enabled     bool   `json:"enabled"`

	// Listen ports (e.g. [{80,false},{443,true}])
	// Legacy: if empty, defaults to port 80 HTTP.
	ListenPorts []ListenPort `json:"listen_ports,omitempty"`

	// Mode: "reverse_proxy" | "static" | "redirect"
	Mode string `json:"mode"`

	// Reverse proxy mode fields
	UpstreamServers []string `json:"upstream_servers"`
	LBAlgorithm     string   `json:"lb_algorithm"` // "round_robin" | "least_conn" | "ip_hash"

	// Static files mode
	StaticRoot string `json:"static_root,omitempty"`

	// Redirect mode
	RedirectURL  string `json:"redirect_url,omitempty"`
	RedirectCode int    `json:"redirect_code,omitempty"` // 301 | 302

	// WAF
	WAFMode      string   `json:"waf_mode"`              // "On" | "Off" | "DetectionOnly"
	ExcludePaths []string `json:"waf_exclude_paths"`

	// SSL / TLS (resolved at write time from ssl_cert_id)
	SSLEnabled  bool   `json:"ssl_enabled"`
	SSLCertID   string `json:"ssl_cert_id,omitempty"`
	SSLCert     string `json:"ssl_cert"`  // resolved path to .crt
	SSLKey      string `json:"ssl_key"`   // resolved path to .key
	HTTP2Enabled bool  `json:"http2_enabled"`
}

// TLSCertificate — managed TLS cert (Let's Encrypt or custom PEM), stored in BoltDB; files under ssl_certs.
type TLSCertificate struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	Source    string `json:"source"` // "letsencrypt" | "custom"
	Email     string `json:"email,omitempty"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	Issuer    string `json:"issuer,omitempty"`
	NotAfter  string `json:"not_after,omitempty"` // RFC3339
	Status    string `json:"status"`              // "active" | "error"
	ErrorMsg  string `json:"error_msg,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ACMEAccountData persists Let's Encrypt account key for renewals / repeat issuance.
type ACMEAccountData struct {
	Email             string `json:"email"`
	PrivateKeyPEM     string `json:"private_key_pem"`
	RegistrationJSON  string `json:"registration_json,omitempty"`
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

type JA3Config struct {
	Enabled bool                  `json:"enabled"`
	Entries []JA3FingerprintEntry `json:"entries,omitempty"`
	// Legacy compatibility: old UI/API used plain hash list.
	Hashes  []string              `json:"hashes,omitempty"`

	JA4Enabled bool                  `json:"ja4_enabled"`
	JA4Entries []JA3FingerprintEntry `json:"ja4_entries,omitempty"`
	// Legacy: plain JA4 hashes.
	JA4Hashes  []string              `json:"ja4_hashes,omitempty"`
}

type JA3FingerprintEntry struct {
	Name    string `json:"name"`
	Hash    string `json:"hash"`
	Enabled bool   `json:"enabled"`
	Action  string `json:"action"` // "block" | "log"
	Source  string `json:"source,omitempty"`
	Builtin bool   `json:"builtin,omitempty"`
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
	DLPEnabled          bool     `json:"dlp_enabled"`
	DLPActive           bool     `json:"dlp_active"`
	AutoQuarantine      bool     `json:"auto_quarantine"`
	InspectRequestBody  bool     `json:"inspect_request_body"`
	InspectResponseBody bool     `json:"inspect_response_body"`
	MaxBodySizeKB       int      `json:"max_body_size_kb"`
	AlertOnBlock        bool     `json:"alert_on_block"`
	ConfigVersion       int      `json:"config_version"`
	DLPPatterns         []string `json:"dlp_patterns"`
}

// ── Virtual Patching (CRS companion / CVE-style rules file) ───────────────────

type VirtualPatchConfig struct {
	Enabled    bool   `json:"enabled"`
	Aggressive bool   `json:"aggressive"` // future: tighter SecAction presets
	LastReload string `json:"last_reload"`
	Notes      string `json:"notes"`
}

// VirtualPatchEntry is a single CVE block extracted from /etc/nginx/coraza/custom/vpatch.rules.
// It's read-only for dashboard purposes (catalog / preview).
type VirtualPatchEntry struct {
	CVE       string `json:"cve"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	RuleID    string `json:"rule_id,omitempty"`
	RawRx     string `json:"raw_rx,omitempty"`
	RawRuleID string `json:"raw_rule_id,omitempty"`
}

// ── WordPress Security (nginx snippet generation) ───────────────────────────

type WPSecurityConfig struct {
	BlockXMLRPC         bool   `json:"block_xmlrpc"`
	BlockSensitiveFiles bool   `json:"block_sensitive_files"`
	BlockUploadsPHP     bool   `json:"block_uploads_php"`
	BlockAuthorEnum     bool   `json:"block_author_enum"`
	BlockScannerUA      bool   `json:"block_scanner_ua"`
	StripAssetVersion   bool   `json:"strip_asset_version"`
	HidePoweredBy       bool   `json:"hide_powered_by"`
	RateLimitLogin      bool   `json:"rate_limit_login"`
	RemindFileEdit      bool   `json:"remind_file_edit"`
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
	SwapTotalGB     float64 `json:"swap_total_gb"`
	SwapUsedGB      float64 `json:"swap_used_gb"`
	DiskTotalGB     float64 `json:"disk_total_gb"`
	DiskUsedGB      float64 `json:"disk_used_gb"`
	UptimeSeconds   uint64  `json:"uptime_seconds"`
	NginxDaemonUp   bool    `json:"nginx_daemon_up"`
	Hostname        string  `json:"hostname"`
	OSName          string  `json:"os_name"`
	KernelVersion   string  `json:"kernel_version"`
	CPUCores        int     `json:"cpu_cores"`
	PrimaryIP       string  `json:"primary_ip"`
	NetworkRxBytes  uint64  `json:"network_rx_bytes"`
	NetworkTxBytes  uint64  `json:"network_tx_bytes"`
	DiskReadBytes   uint64  `json:"disk_read_bytes"`
	DiskWriteBytes  uint64  `json:"disk_write_bytes"`
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
