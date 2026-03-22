package nginx

import (
	"fmt"
	"os"
)

// WAFModeConfPath is the include file that sets SecRuleEngine (mounted rw in Docker).
const WAFModeConfPath = "/etc/nginx/coraza/custom/flux_waf_mode.conf"

// NormalizeWAFMode returns a valid Coraza SecRuleEngine value.
func NormalizeWAFMode(mode string) string {
	switch mode {
	case "Off", "DetectionOnly", "On":
		return mode
	default:
		return "On"
	}
}

// WriteWAFMode writes flux_waf_mode.conf so nginx/Coraza picks up the global engine mode.
func WriteWAFMode(mode string) error {
	m := NormalizeWAFMode(mode)
	content := fmt.Sprintf("# Managed by Flux WAF Dashboard — do not edit manually\n# Values: On | Off | DetectionOnly\nSecRuleEngine %s\n", m)
	return os.WriteFile(WAFModeConfPath, []byte(content), 0o644)
}
