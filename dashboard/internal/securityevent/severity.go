// Package securityevent maps audit rows to severity tiers for grouping UI.
package securityevent

import (
	"strconv"
	"strings"

	"flux-waf/internal/models"
)

// EffectiveSeverity returns high | medium | low for dashboards and grouping.
func EffectiveSeverity(e models.SecurityEvent) string {
	s := strings.TrimSpace(strings.ToLower(e.Severity))
	if s != "" {
		return normalizeSeverityLabel(s)
	}
	return inferFromLegacy(e)
}

func normalizeSeverityLabel(s string) string {
	switch s {
	case "high", "critical", "crit":
		return "high"
	case "medium", "med", "warning", "warn":
		return "medium"
	case "low", "info", "notice", "debug":
		return "low"
	}
	switch {
	case strings.Contains(s, "crit"), strings.Contains(s, "emerg"), strings.Contains(s, "fatal"):
		return "high"
	case strings.Contains(s, "high"):
		return "high"
	case strings.Contains(s, "med"), strings.Contains(s, "warn"), s == "3", s == "4":
		return "medium"
	case strings.Contains(s, "low"), strings.Contains(s, "info"), strings.Contains(s, "notice"), s == "5", s == "6":
		return "low"
	}
	if n, err := strconv.Atoi(s); err == nil {
		switch {
		case n <= 2:
			return "high"
		case n <= 4:
			return "medium"
		default:
			return "low"
		}
	}
	return "medium"
}

func inferFromLegacy(e models.SecurityEvent) string {
	a := strings.ToLower(strings.TrimSpace(e.Action))
	switch {
	case strings.Contains(a, "block"), strings.Contains(a, "deny"), strings.Contains(a, "drop"), a == "rejected":
		return "high"
	case strings.Contains(a, "detect"), strings.Contains(a, "log"), strings.Contains(a, "monitor"):
		return "medium"
	}

	rule := strings.TrimSpace(e.RuleID)
	if n, err := strconv.Atoi(rule); err == nil {
		// OWASP CRS coarse buckets: SQLi / XSS / RCE families often critical
		switch {
		case n >= 941000 && n < 942000, n >= 942000 && n < 943000, n >= 932000 && n < 934000:
			return "high"
		case n >= 920000 && n < 921000, n >= 921000 && n < 930000:
			return "medium"
		}
	}

	msg := strings.ToLower(e.Message)
	if strings.Contains(msg, "critical") || strings.Contains(msg, "attack") {
		return "high"
	}
	if strings.Contains(msg, "warning") || strings.Contains(msg, "anomal") {
		return "medium"
	}

	if a != "" {
		return "low"
	}
	return "medium"
}
