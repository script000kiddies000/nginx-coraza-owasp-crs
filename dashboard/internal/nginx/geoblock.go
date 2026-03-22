package nginx

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// GeoBlockMapPath is the nginx map for country blocking (volume: config/geoip — rw).
const GeoBlockMapPath = "/etc/nginx/geoip/geoip-blocked-countries.conf"

var reGeoBlockLine = regexp.MustCompile(`(?m)^\s*([A-Z]{2})\s+1\s*;`)

// WriteGeoBlockMap regenerates the map file from ISO 3166-1 alpha-2 codes (uppercase).
func WriteGeoBlockMap(isoCodes []string) error {
	seen := make(map[string]struct{})
	var uniq []string
	for _, raw := range isoCodes {
		c := strings.ToUpper(strings.TrimSpace(raw))
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		uniq = append(uniq, c)
	}

	var b strings.Builder
	b.WriteString("# ==============================================================================\n")
	b.WriteString("# GeoIP2 Country Block Map — Managed by Flux WAF Dashboard\n")
	b.WriteString("# ISO 3166-1 alpha-2: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2\n")
	b.WriteString("# ==============================================================================\n")
	b.WriteString("map $geoip2_data_country_code $geoip2_blocked_country {\n")
	b.WriteString("    default 0;\n\n")
	for _, c := range uniq {
		fmt.Fprintf(&b, "    %s 1;\n", c)
	}
	b.WriteString("}\n")
	return os.WriteFile(GeoBlockMapPath, []byte(b.String()), 0o644)
}

// ReadGeoBlockedISOs parses blocked country codes from the current map file.
func ReadGeoBlockedISOs() ([]string, error) {
	raw, err := os.ReadFile(GeoBlockMapPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	matches := reGeoBlockLine.FindAllStringSubmatch(string(raw), -1)
	seen := make(map[string]struct{})
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		c := m[1]
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}
