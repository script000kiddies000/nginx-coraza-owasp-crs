package nginx

import (
	"fmt"
	"flux-waf/internal/models"
	"os"
	"regexp"
	"sort"
	"strings"
)

var reJA3Hex32 = regexp.MustCompile(`^[a-f0-9]{32}$`)

func JA3MapPath() string {
	if p := os.Getenv("FLUX_JA3_MAP_PATH"); p != "" {
		return p
	}
	return "/etc/nginx/snippets/wafx-ja3-map.conf"
}

func NormalizeJA3Hash(v string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	if !reJA3Hex32.MatchString(s) {
		return "", false
	}
	return s, true
}

func sanitizeJA3Name(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return "Unnamed"
	}
	// Keep comments single-line and compact.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func normalizeJA3Entries(entries []models.JA3FingerprintEntry) []models.JA3FingerprintEntry {
	byHash := make(map[string]models.JA3FingerprintEntry, len(entries))
	for _, e := range entries {
		h, ok := NormalizeJA3Hash(e.Hash)
		if !ok {
			continue
		}
		name := sanitizeJA3Name(e.Name)
		prev, exists := byHash[h]
		if !exists || prev.Name == "Unnamed" {
			byHash[h] = models.JA3FingerprintEntry{Name: name, Hash: h}
		}
	}
	out := make([]models.JA3FingerprintEntry, 0, len(byHash))
	for _, e := range byHash {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out
}

func ParseJA3Entries(content string) []models.JA3FingerprintEntry {
	lines := strings.Split(content, "\n")
	var list []models.JA3FingerprintEntry
	for _, ln := range lines {
		line := strings.TrimSpace(ln)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, " 1;") || !strings.Contains(line, "\"") {
			continue
		}
		i := strings.Index(line, "\"")
		j := strings.LastIndex(line, "\"")
		if i < 0 || j <= i {
			continue
		}
		if h, ok := NormalizeJA3Hash(line[i+1 : j]); ok {
			name := "Unnamed"
			if k := strings.Index(line, "#"); k >= 0 {
				name = sanitizeJA3Name(line[k+1:])
			}
			list = append(list, models.JA3FingerprintEntry{Name: name, Hash: h})
		}
	}
	return normalizeJA3Entries(list)
}

func ReadJA3Entries(path string) ([]models.JA3FingerprintEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseJA3Entries(string(b)), nil
}

func WriteJA3Map(enabled bool, entries []models.JA3FingerprintEntry) error {
	path := JA3MapPath()
	list := normalizeJA3Entries(entries)

	var b strings.Builder
	b.WriteString("## Flux WAF JA3 Management — generated, do not edit manually\n")
	b.WriteString("## Source variable from nginx-ssl-fingerprint: $http_ssl_ja3_hash\n")
	b.WriteString("## This map must be included from nginx.conf inside `http {}`.\n")
	b.WriteString("map $http_ssl_ja3_hash $wafx_ja3_blocked {\n")
	b.WriteString("    default 0;\n\n")
	if enabled {
		for _, e := range list {
			b.WriteString(fmt.Sprintf("    \"%s\" 1; # %s\n", e.Hash, e.Name))
		}
	} else {
		b.WriteString("    # JA3 filtering disabled from dashboard\n")
	}
	b.WriteString("}\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

