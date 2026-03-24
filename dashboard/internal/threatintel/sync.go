package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"flux-waf/internal/models"
)

type Feed struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	APIKey   string `json:"api_key,omitempty"`
	LastSync string `json:"last_sync,omitempty"`
	IPCount  int    `json:"ip_count,omitempty"`
}

type FileConfig struct {
	Enabled        bool     `json:"enabled"`
	Action         string   `json:"action"`
	BlockScore     int      `json:"block_score"`
	UpdateInterval int      `json:"update_interval"`
	WhitelistIPs   []string `json:"whitelist_ips"`
	BlockedIPs     []string `json:"blocked_ips"`
	Feeds          []Feed   `json:"feeds"`
}

type SyncResult struct {
	LastSync string `json:"last_sync"`
	IPCount  int    `json:"ip_count"`
}

var (
	reCIDRLike = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+(\/\d+)?$`)
)

func SyncFeeds(dbCfg models.ThreatIntelConfig, configPath, outputPath string) (SyncResult, error) {
	cfg, err := loadAndMergeConfig(dbCfg, configPath)
	if err != nil {
		return SyncResult{}, err
	}
	if !cfg.Enabled {
		return SyncResult{LastSync: "disabled", IPCount: 0}, nil
	}

	whitelist := make(map[string]struct{}, len(cfg.WhitelistIPs))
	for _, w := range cfg.WhitelistIPs {
		w = strings.TrimSpace(w)
		if w != "" {
			whitelist[w] = struct{}{}
		}
	}

	all := make(map[string]struct{})
	for _, ip := range cfg.BlockedIPs {
		ip = strings.TrimSpace(ip)
		if isIPv4OrCIDR(ip) {
			if _, ok := whitelist[ip]; !ok {
				all[ip] = struct{}{}
			}
		}
	}

	nowStr := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	for i := range cfg.Feeds {
		feed := &cfg.Feeds[i]
		if !feed.Enabled {
			feed.LastSync = "skipped"
			continue
		}
		raw, err := fetchFeed(feed)
		if err != nil {
			feed.LastSync = "error (" + nowStr + ")"
			continue
		}
		parsed := parseFeed(feed.Type, raw, cfg.BlockScore)
		count := 0
		for _, ip := range parsed {
			if _, ok := whitelist[ip]; ok {
				continue
			}
			all[ip] = struct{}{}
			count++
		}
		feed.IPCount = count
		feed.LastSync = nowStr
	}

	ips := make([]string, 0, len(all))
	for ip := range all {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	action := strings.ToLower(strings.TrimSpace(cfg.Action))
	nginxAction := "deny"
	if action == "allow" {
		nginxAction = "allow"
	}

	var b strings.Builder
	b.WriteString("# Threat Intel IP Rules\n")
	b.WriteString("# Managed by: flux-waf (Go sync) — DO NOT EDIT MANUALLY\n")
	b.WriteString("# Last sync:  " + nowStr + "\n")
	b.WriteString(fmt.Sprintf("# Total IPs:  %d\n\n", len(ips)))
	for _, ip := range ips {
		b.WriteString(nginxAction + " " + ip + ";\n")
	}
	if err := os.WriteFile(outputPath, []byte(b.String()), 0o644); err != nil {
		return SyncResult{}, fmt.Errorf("write ip_rules: %w", err)
	}

	cfg.BlockScore = dbCfg.BlockScore
	cfg.UpdateInterval = dbCfg.UpdateInterval
	cfg.Enabled = dbCfg.Enabled
	cfg.WhitelistIPs = dbCfg.WhitelistIPs
	if err := saveConfig(configPath, cfg); err != nil {
		return SyncResult{}, err
	}

	return SyncResult{LastSync: nowStr, IPCount: len(ips)}, nil
}

func ReadFileConfig(path string) (FileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FileConfig{}, fmt.Errorf("read threat_intel.json: %w", err)
	}
	var cfg FileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return FileConfig{}, fmt.Errorf("parse threat_intel.json: %w", err)
	}
	if cfg.Action == "" {
		cfg.Action = "block"
	}
	return cfg, nil
}

func WriteFileConfig(path string, cfg FileConfig) error {
	if cfg.Action == "" {
		cfg.Action = "block"
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode threat_intel.json: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("write threat_intel.json: %w", err)
	}
	return nil
}

func loadAndMergeConfig(dbCfg models.ThreatIntelConfig, path string) (FileConfig, error) {
	cfg, err := ReadFileConfig(path)
	if err != nil {
		return FileConfig{}, err
	}
	cfg.Enabled = dbCfg.Enabled
	cfg.UpdateInterval = dbCfg.UpdateInterval
	cfg.BlockScore = dbCfg.BlockScore
	cfg.WhitelistIPs = dbCfg.WhitelistIPs
	if cfg.Action == "" {
		cfg.Action = "block"
	}
	return cfg, nil
}

func saveConfig(path string, cfg FileConfig) error {
	return WriteFileConfig(path, cfg)
}

func fetchFeed(feed *Feed) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return "", err
	}
	if feed.Type == "abuseipdb" {
		if strings.TrimSpace(feed.APIKey) == "" {
			return "", fmt.Errorf("abuseipdb api_key empty")
		}
		req.Header.Set("Key", strings.TrimSpace(feed.APIKey))
		req.Header.Set("Accept", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func parseFeed(feedType, raw string, blockScore int) []string {
	switch feedType {
	case "spamhaus_drop":
		return parseSpamhaus(raw)
	case "emerging_threats":
		return parseEmerging(raw)
	case "abuseipdb":
		return parseAbuseIPDB(raw, blockScore)
	default:
		return nil
	}
}

func parseSpamhaus(raw string) []string {
	out := make([]string, 0, 2048)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		cidr := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		if isIPv4OrCIDR(cidr) {
			out = append(out, cidr)
		}
	}
	return out
}

func parseEmerging(raw string) []string {
	out := make([]string, 0, 2048)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isIPv4OrCIDR(line) {
			out = append(out, line)
		}
	}
	return out
}

func parseAbuseIPDB(raw string, blockScore int) []string {
	type row struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	}
	var payload struct {
		Data []row `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.Data))
	for _, r := range payload.Data {
		ip := strings.TrimSpace(r.IPAddress)
		if r.AbuseConfidenceScore >= blockScore && isIPv4OrCIDR(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func isIPv4OrCIDR(v string) bool {
	if !reCIDRLike.MatchString(v) {
		return false
	}
	if strings.Contains(v, "/") {
		_, _, err := net.ParseCIDR(v)
		return err == nil
	}
	return net.ParseIP(v) != nil
}
