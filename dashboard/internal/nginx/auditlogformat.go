package nginx

import (
	"fmt"
	"os"
)

// AuditLogFormatConfPath is included from coraza.conf (volume: config/coraza/custom — rw).
const AuditLogFormatConfPath = "/etc/nginx/coraza/custom/flux_audit_log_format.conf"

// NormalizeAuditLogFormat returns "json" or "native".
func NormalizeAuditLogFormat(f string) string {
	switch f {
	case "native":
		return "native"
	default:
		return "json"
	}
}

// WriteAuditLogFormat writes flux_audit_log_format.conf (SecAuditLogFormat directive).
func WriteAuditLogFormat(format string) error {
	f := NormalizeAuditLogFormat(format)
	sec := "JSON"
	if f == "native" {
		sec = "Native"
	}
	content := fmt.Sprintf(`# Managed by Flux WAF Dashboard (Settings → Pengaturan Umum)
# json = satu baris JSON per event — disarankan untuk halaman Security Events
# native = format multipart ModSecurity (Serial) — parser dashboard lebih kompleks
SecAuditLogFormat %s
`, sec)
	return os.WriteFile(AuditLogFormatConfPath, []byte(content), 0o644)
}
