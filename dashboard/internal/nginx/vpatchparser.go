package nginx

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"flux-waf/internal/models"
)

var (
	reVPatchCVEWithSeverity = regexp.MustCompile(`^\s*#\s*(CVE-\d{4}-\d+)\s*[-–—]\s*(.*?)\s*\[([^\]]+)\]\s*$`)
	reVPatchCVEWithoutSev   = regexp.MustCompile(`^\s*#\s*(CVE-\d{4}-\d+)\s*[-–—]\s*(.*?)\s*$`)

	// Example: SecRule REQUEST_URI "@rx (?i)/path" \
	reVPatchRawRx = regexp.MustCompile(`"@rx\s*([^"]+)"`)
	reVPatchRuleID = regexp.MustCompile(`\bid:(\d+)\b`)
	reVPatchSeverityInRule = regexp.MustCompile(`severity:'([^']+)'`)
)

// ReadVPatchEntries parses CVE blocks from /etc/nginx/coraza/custom/vpatch.rules.
// Output is optimized for dashboard preview (read-only).
func ReadVPatchEntries(path string, limit int) ([]models.VirtualPatchEntry, error) {
	if path == "" {
		path = "/etc/nginx/coraza/custom/vpatch.rules"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []models.VirtualPatchEntry{}, nil
		}
		return nil, fmt.Errorf("read vpatch rules: %w", err)
	}

	lines := strings.Split(string(b), "\n")
	var out []models.VirtualPatchEntry

	var cur models.VirtualPatchEntry
	var curBuf strings.Builder
	curSet := false

	flush := func() {
		if !curSet {
			return
		}
		block := curBuf.String()

		if strings.TrimSpace(cur.RawRx) == "" {
			if m := reVPatchRawRx.FindStringSubmatch(block); len(m) == 2 {
				cur.RawRx = strings.TrimSpace(m[1])
			}
		}
		if strings.TrimSpace(cur.RuleID) == "" {
			if m := reVPatchRuleID.FindStringSubmatch(block); len(m) == 2 {
				cur.RuleID = strings.TrimSpace(m[1])
			}
		}
		if strings.TrimSpace(cur.Severity) == "" {
			if m := reVPatchSeverityInRule.FindStringSubmatch(block); len(m) == 2 {
				cur.Severity = normalizeSeverity(m[1])
			}
		}

		out = append(out, cur)
		if limit > 0 && len(out) >= limit {
			// caller will stop by checking length; safe to no-op further parsing
		}
	}

	for _, line := range lines {
		if m := reVPatchCVEWithSeverity.FindStringSubmatch(line); len(m) == 4 {
			cve := strings.TrimSpace(m[1])
			title := strings.TrimSpace(m[2])
			sev := normalizeSeverity(m[3])

			if curSet && cur.CVE == cve {
				// Same CVE repeated (common in this file): append title if useful.
				if title != "" && !strings.Contains(cur.Title, title) {
					if strings.TrimSpace(cur.Title) != "" {
						cur.Title = strings.TrimSpace(cur.Title) + " — " + title
					} else {
						cur.Title = title
					}
				}
				if cur.Severity == "" {
					cur.Severity = sev
				}
				curBuf.WriteString(line + "\n")
				continue
			}

			flush()
			if limit > 0 && len(out) >= limit {
				break
			}

			curSet = true
			cur = models.VirtualPatchEntry{CVE: cve, Title: title, Severity: sev}
			curBuf.Reset()
			curBuf.WriteString(line + "\n")
			continue
		}

		if m := reVPatchCVEWithoutSev.FindStringSubmatch(line); len(m) == 3 {
			cve := strings.TrimSpace(m[1])
			title := strings.TrimSpace(m[2])

			if curSet && cur.CVE == cve {
				if title != "" && !strings.Contains(cur.Title, title) {
					if strings.TrimSpace(cur.Title) != "" {
						cur.Title = strings.TrimSpace(cur.Title) + " — " + title
					} else {
						cur.Title = title
					}
				}
				curBuf.WriteString(line + "\n")
				continue
			}

			flush()
			if limit > 0 && len(out) >= limit {
				break
			}

			curSet = true
			cur = models.VirtualPatchEntry{CVE: cve, Title: title}
			curBuf.Reset()
			curBuf.WriteString(line + "\n")
			continue
		}

		if curSet {
			curBuf.WriteString(line + "\n")
		}
	}

	flush()
	return out, nil
}

func normalizeSeverity(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	u = strings.Trim(u, "[] ")
	switch {
	case strings.Contains(u, "CRIT"):
		return "CRITICAL"
	case strings.Contains(u, "HIGH"):
		return "HIGH"
	case strings.Contains(u, "MED"):
		return "MEDIUM"
	case strings.Contains(u, "LOW"):
		return "LOW"
	case strings.Contains(u, "INFO"):
		return "INFO"
	default:
		// Keep original if unknown; dashboard will still render.
		return u
	}
}

