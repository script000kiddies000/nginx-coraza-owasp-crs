package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"flux-waf/internal/models"
)

// DefaultWPSnippetPath is included manually from server{} (see UI note).
const DefaultWPSnippetPath = "/etc/nginx/snippets/flux-wp-managed.conf"

// WriteWPSecuritySnippet writes nginx directives safe to include inside server{}.
// Does not add proxy_pass — only deny/if/location blocks compatible with any upstream.
func WriteWPSecuritySnippet(cfg models.WPSecurityConfig) (path string, err error) {
	path = os.Getenv("FLUX_WP_SNIPPET_PATH")
	if path == "" {
		path = DefaultWPSnippetPath
	}

	var b strings.Builder
	b.WriteString("# Managed by Flux WAF dashboard — WordPress Security\n")
	b.WriteString("# Generated: ")
	b.WriteString(time.Now().UTC().Format(time.RFC3339))
	b.WriteString("\n# Include inside server { }:  include ")
	b.WriteString(path)
	b.WriteString(";\n")
	b.WriteString("# DEBUG CRS ONLY: semua directive WordPress hardening di-comment sementara.\n\n")

	if cfg.HidePoweredBy {
		b.WriteString("# proxy_hide_header X-Powered-By;\n\n")
	}

	if cfg.RateLimitLogin {
		b.WriteString("# /wp-login.php only — zone key empty for other URIs (see http{} map $flux_wp_login_key)\n")
		b.WriteString("# limit_req zone=flux_wp_login burst=5 nodelay;\n\n")
	}

	if cfg.BlockXMLRPC {
		b.WriteString("# location = /xmlrpc.php {\n#     deny all;\n#     return 444;\n# }\n\n")
	}
	if cfg.BlockSensitiveFiles {
		b.WriteString("# location ~* /(wp-config\\.php|\\.env|\\.htaccess|\\.git) {\n#     deny all;\n#     return 404;\n# }\n\n")
	}
	if cfg.BlockUploadsPHP {
		b.WriteString("# location ~* /wp-content/uploads/.*\\.php$ {\n#     deny all;\n#     return 403;\n# }\n\n")
	}
	if cfg.BlockAuthorEnum {
		b.WriteString("# if ($query_string ~* \"author=[0-9]+\") {\n#     return 403;\n# }\n\n")
	}
	if cfg.BlockScannerUA {
		b.WriteString("# if ($http_user_agent ~* \"(WPScan|sqlmap|nikto|nmap|masscan|ZmEu|w3af|dirbuster|nuclei)\") {\n#     return 403;\n# }\n\n")
	}
	if cfg.StripAssetVersion {
		b.WriteString("# location ~* \\.(css|js)$ {\n#     if ($arg_ver ~* \"[0-9]+\\.[0-9]+\") {\n#         rewrite ^(.*)$ $1? permanent;\n#     }\n# }\n\n")
	}

	if cfg.RemindFileEdit {
		b.WriteString("# Reminder — not enforced by nginx: set in wp-config.php:\n")
		b.WriteString("#   define('DISALLOW_FILE_EDIT', true);\n\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return path, fmt.Errorf("mkdir snippet dir: %w", err)
	}
	return path, os.WriteFile(path, []byte(b.String()), 0644)
}
