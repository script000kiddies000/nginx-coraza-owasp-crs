package threatintel

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

const (
	DefaultIPRulesPath = "/etc/nginx/threat-intel/ip_rules.conf"
	DefaultJSONPath    = "/etc/nginx/threat-intel/threat_intel.json"
)

var (
	reDenyLine   = regexp.MustCompile(`(?m)^\s*deny\s+([^;]+);`)
	reLastSync   = regexp.MustCompile(`(?m)# Last sync:\s*(.+)`)
	reTotalIPs   = regexp.MustCompile(`(?m)# Total IPs:\s*(\d+)`)
	reManagedBy  = regexp.MustCompile(`(?m)# Managed by:\s*(.+)`)
)

// IPRulesInfo summarizes generated nginx deny rules.
type IPRulesInfo struct {
	Path           string   `json:"path"`
	DenyCount      int      `json:"deny_count"`
	LastSyncLine   string   `json:"last_sync_comment,omitempty"`
	TotalIPsLine   string   `json:"total_ips_comment,omitempty"`
	Preview        []string `json:"preview"` // last N deny lines as text
	ManagedByLine  string   `json:"managed_by,omitempty"`
	ReadError      string   `json:"read_error,omitempty"`
}

// ReadIPRulesInfo parses ip_rules.conf for metadata and deny directives.
func ReadIPRulesInfo(path string, previewN int) IPRulesInfo {
	if path == "" {
		path = DefaultIPRulesPath
	}
	if previewN <= 0 {
		previewN = 40
	}
	info := IPRulesInfo{Path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			info.ReadError = "file not found"
			return info
		}
		info.ReadError = err.Error()
		return info
	}
	raw := string(b)
	if m := reLastSync.FindStringSubmatch(raw); len(m) > 1 {
		info.LastSyncLine = strings.TrimSpace(m[1])
	}
	if m := reTotalIPs.FindStringSubmatch(raw); len(m) > 1 {
		info.TotalIPsLine = strings.TrimSpace(m[1])
	}
	if m := reManagedBy.FindStringSubmatch(raw); len(m) > 1 {
		info.ManagedByLine = strings.TrimSpace(m[1])
	}
	all := reDenyLine.FindAllStringSubmatch(raw, -1)
	info.DenyCount = len(all)
	var tail []string
	start := 0
	if len(all) > previewN {
		start = len(all) - previewN
	}
	for _, m := range all[start:] {
		if len(m) > 1 {
			tail = append(tail, "deny "+strings.TrimSpace(m[1])+";")
		}
	}
	info.Preview = tail
	return info
}

// FeedsFile wraps optional threat_intel.json from the repo / volume.
func ReadFeedsJSON(path string) (json.RawMessage, error) {
	if path == "" {
		path = DefaultJSONPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return json.RawMessage(b), nil
}
