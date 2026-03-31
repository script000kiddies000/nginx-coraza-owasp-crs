package logs

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

func topLabelCounts(m map[string]int, limit int) []LabelCount {
	type kv struct{ k string; v int }
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	if len(list) > limit {
		list = list[:limit]
	}
	out := make([]LabelCount, 0, len(list))
	for _, x := range list {
		out = append(out, LabelCount{Label: x.k, Count: x.v})
	}
	return out
}

func topBarRows(m map[string]int, limit int) []BarRow {
	lc := topLabelCounts(m, limit)
	var sum int
	for _, x := range lc {
		sum += x.Count
	}
	out := make([]BarRow, 0, len(lc))
	for _, x := range lc {
		pct := 0.0
		if sum > 0 {
			pct = math.Round(float64(x.Count)/float64(sum)*1000) / 10
		}
		out = append(out, BarRow{Label: x.Label, Count: x.Count, Pct: pct})
	}
	return out
}

func topBarRowsWithTotal(m map[string]int, total int, limit int) []BarRow {
	type kv struct{ k string; v int }
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	out := make([]BarRow, 0, len(list))
	base := float64(total)
	if base <= 0 {
		base = 1
	}
	for _, x := range list {
		pct := math.Round((float64(x.v)/base)*1000) / 10
		out = append(out, BarRow{Label: x.k, Count: x.v, Pct: pct})
	}
	return out
}

func normalizeCountryCode(s string) string {
	s = strings.TrimSpace(strings.ToUpper(s))
	if len(s) != 2 || s == "--" || s == "ZZ" {
		return ""
	}
	return s
}

func parseEntryTime(e map[string]any) time.Time {
	s := str(e["time"])
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t
	}
	if len(s) >= 19 {
		t, err = time.Parse("2006-01-02T15:04:05", s[:19])
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	default:
		return strings.TrimSpace(fmt.Sprint(x))
	}
}

func statusCode(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	default:
		return 0
	}
}

func summarizeUA(ua string) string {
	if ua == "" {
		return "Unknown · Unknown"
	}
	u := strings.ToLower(ua)
	mobile := strings.Contains(u, "mobile") ||
		strings.Contains(u, "android") ||
		strings.Contains(u, "iphone") ||
		strings.Contains(u, "ipad")
	dev := "Desktop"
	if mobile {
		dev = "Mobile"
	}
	b := "Other"
	switch {
	case strings.Contains(u, "edg/") || strings.Contains(u, "edga/") || strings.Contains(u, "edgios"):
		b = "Edge"
	case strings.Contains(u, "opr/") || strings.Contains(u, "opera"):
		b = "Opera"
	case strings.Contains(u, "chrome") && !strings.Contains(u, "edg"):
		b = "Chrome"
	case strings.Contains(u, "firefox") || strings.Contains(u, "fxios"):
		b = "Firefox"
	case strings.Contains(u, "safari") && !strings.Contains(u, "chrome"):
		b = "Safari"
	case strings.Contains(u, "curl"):
		b = "curl"
	case strings.Contains(u, "wget"):
		b = "wget"
	case strings.Contains(u, "bot") || strings.Contains(u, "spider") || strings.Contains(u, "crawl"):
		b = "Bot"
	}
	return b + " · " + dev
}

func normalizeReferer(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || ref == "-" {
		return "(direct)"
	}
	u, err := url.Parse(ref)
	if err != nil {
		if len(ref) > 64 {
			return ref[:64] + "…"
		}
		return ref
	}
	host := u.Host
	if host == "" {
		host = ref
	}
	path := u.Path
	if path == "" || path == "/" {
		return host
	}
	if len(path) > 32 {
		path = path[:32] + "…"
	}
	return host + path
}
