package nginx

import (
	"fmt"
	"flux-waf/internal/models"
	"os"
	"regexp"
	"sort"
	"strings"
)

var reJA4Hex32 = regexp.MustCompile(`^[a-f0-9]{32}$`)

func JA4MapPath() string {
	if p := os.Getenv("FLUX_JA4_MAP_PATH"); p != "" {
		return p
	}
	return "/etc/nginx/snippets/wafx-ja4-map.conf"
}

func NormalizeJA4Hash(v string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	if !reJA4Hex32.MatchString(s) {
		return "", false
	}
	return s, true
}

func sanitizeJA4Name(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return "Unnamed"
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func normalizeJA4Entries(entries []models.JA3FingerprintEntry) []models.JA3FingerprintEntry {
	byHash := make(map[string]models.JA3FingerprintEntry, len(entries))
	for _, e := range entries {
		h, ok := NormalizeJA4Hash(e.Hash)
		if !ok {
			continue
		}

		name := sanitizeJA4Name(e.Name)
		action := strings.ToLower(strings.TrimSpace(e.Action))
		if action != "log" && action != "block" {
			action = "block"
		}
		enabled := e.Enabled

		in := models.JA3FingerprintEntry{
			Name:    name,
			Hash:    h,
			Enabled: enabled,
			Action:  action,
			Source:  e.Source,
			Builtin: e.Builtin,
		}

		prev, exists := byHash[h]
		if !exists {
			byHash[h] = in
			continue
		}

		// Prefer entries that actually block.
		prevBlocks := prev.Enabled && prev.Action == "block"
		inBlocks := in.Enabled && in.Action == "block"
		if inBlocks && !prevBlocks {
			byHash[h] = in
			continue
		}

		// If both have same blocking state, prefer non-"Unnamed".
		if prevBlocks == inBlocks && prev.Name == "Unnamed" && in.Name != "Unnamed" {
			byHash[h] = in
			continue
		}
	}
	out := make([]models.JA3FingerprintEntry, 0, len(byHash))
	for _, e := range byHash {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out
}

func ParseJA4Entries(content string) []models.JA3FingerprintEntry {
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
		if h, ok := NormalizeJA4Hash(line[i+1 : j]); ok {
			name := "Unnamed"
			if k := strings.Index(line, "#"); k >= 0 {
				name = sanitizeJA4Name(line[k+1:])
			}
			list = append(list, models.JA3FingerprintEntry{
				Name:    name,
				Hash:    h,
				Enabled: true,
				Action:  "block",
				Builtin: true,
				Source:  "builtin",
			})
		}
	}
	return normalizeJA4Entries(list)
}

func ReadJA4Entries(path string) ([]models.JA3FingerprintEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseJA4Entries(string(b)), nil
}

func WriteJA4Map(enabled bool, entries []models.JA3FingerprintEntry) error {
	path := JA4MapPath()
	list := normalizeJA4Entries(entries)

	var b strings.Builder
	b.WriteString("## Flux WAF JA4 Management — generated, do not edit manually\n")
	b.WriteString("## Source variable from nginx-ssl-fingerprint: $http_ssl_ja4_hash\n")
	b.WriteString("## This map must be included from nginx.conf inside `http {}`.\n")
	b.WriteString("map $http_ssl_ja4_hash $wafx_ja4_blocked {\n")
	b.WriteString("    default 0;\n\n")
	if enabled {
		for _, e := range list {
			if !e.Enabled || strings.ToLower(strings.TrimSpace(e.Action)) != "block" {
				continue
			}
			b.WriteString(fmt.Sprintf("    \"%s\" 1; # %s\n", e.Hash, e.Name))
		}
	} else {
		b.WriteString("    # JA4 filtering disabled from dashboard\n")
	}
	b.WriteString("}\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

