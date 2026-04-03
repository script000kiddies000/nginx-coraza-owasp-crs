package nginx

import (
	"os"
	"path/filepath"
	"strings"

	"flux-waf/internal/models"
)

const defaultStaticWebRoot = "/var/www/html"

// StaticWebRootBase returns the base directory for dashboard-managed static sites.
func StaticWebRootBase() string {
	if p := strings.TrimSpace(os.Getenv("FLUX_STATIC_WEBROOT")); p != "" {
		return filepath.Clean(p)
	}
	return defaultStaticWebRoot
}

// SanitizeDomainDir turns a hostname into a single path segment (safe for filesystem).
func SanitizeDomainDir(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	var b strings.Builder
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "host"
	}
	return b.String()
}

// DashboardStaticRoot is the nginx root when static_source=dashboard for a host.
func DashboardStaticRoot(domain string) string {
	return filepath.Join(StaticWebRootBase(), SanitizeDomainDir(domain))
}

// EffectiveStaticRoot resolves the document root for static mode (manual vs dashboard).
func EffectiveStaticRoot(h models.HostConfig) string {
	if strings.EqualFold(strings.TrimSpace(h.StaticSource), "dashboard") {
		return DashboardStaticRoot(h.Domain)
	}
	return strings.TrimSpace(h.StaticRoot)
}

// StaticIndexPath returns the absolute path to index.html for a static host.
func StaticIndexPath(h models.HostConfig) (string, error) {
	if h.Mode != "static" {
		return "", os.ErrInvalid
	}
	root := EffectiveStaticRoot(h)
	if root == "" {
		return "", os.ErrInvalid
	}
	return filepath.Join(root, "index.html"), nil
}

// StaticIndexPathMustBeUnderBase returns index path only if root resolves under base (for dashboard writes).
func StaticIndexPathMustBeUnderBase(h models.HostConfig, base string) (string, error) {
	p, err := StaticIndexPath(h)
	if err != nil {
		return "", err
	}
	if !pathHasPrefix(p, base) {
		return "", os.ErrInvalid
	}
	return p, nil
}

func pathHasPrefix(full, base string) bool {
	full = filepath.Clean(full)
	base = filepath.Clean(base)
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
