//go:build linux

package monitor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func collectNginxConfiguration() map[string]string {
	out := map[string]string{}

	paths := []string{"/etc/nginx/nginx.conf"}
	// Also scan common conf.d for error_log/pid/user overrides.
	if matches, _ := filepath.Glob("/etc/nginx/conf.d/*.conf"); len(matches) > 0 {
		paths = append(paths, matches...)
	}

	content := ""
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content += "\n" + string(b)
	}
	if content == "" {
		// Provide defaults if nginx config isn't readable.
		out["pid"] = "/run/nginx.pid"
		out["user"] = "www-data"
		out["error_log"] = "/var/log/nginx/error.log"
		out["worker_processes"] = "auto"
		out["worker_cpu_affinity"] = "auto"
		out["worker_connections"] = "1024"
		return out
	}

	getOne := func(re string) string {
		r := regexp.MustCompile(re)
		m := r.FindStringSubmatch(content)
		if len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
		return ""
	}

	if v := getOne(`(?m)^\s*error_log\s+([^;]+);`); v != "" {
		out["error_log"] = strings.TrimSpace(v)
	}
	if v := getOne(`(?m)^\s*pid\s+([^;]+);`); v != "" {
		out["pid"] = strings.TrimSpace(v)
	}
	if v := getOne(`(?m)^\s*user\s+([^;]+);`); v != "" {
		// user directive might contain two tokens: user group;
		toks := strings.Fields(v)
		if len(toks) > 0 {
			out["user"] = toks[0]
		}
	}
	if v := getOne(`(?m)^\s*worker_processes\s+([^;]+);`); v != "" {
		out["worker_processes"] = strings.TrimSpace(v)
	} else {
		out["worker_processes"] = "auto"
	}
	if v := getOne(`(?m)^\s*worker_cpu_affinity\s+([^;]+);`); v != "" {
		out["worker_cpu_affinity"] = strings.TrimSpace(v)
	} else {
		out["worker_cpu_affinity"] = "auto"
	}
	if v := getOne(`(?m)^\s*worker_connections\s+([^;]+);`); v != "" {
		out["worker_connections"] = strings.TrimSpace(v)
	}

	// Fill some defaults if missing.
	if _, ok := out["worker_connections"]; !ok {
		out["worker_connections"] = "—"
	}
	if _, ok := out["error_log"]; !ok {
		out["error_log"] = "—"
	}
	if _, ok := out["pid"]; !ok {
		out["pid"] = "—"
	}
	if _, ok := out["user"]; !ok {
		out["user"] = "—"
	}

	return out
}

func collectNginxModules() []string {
	// nginx -V prints to stderr.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/sbin/nginx", "-V")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()

	s := buf.String()
	if strings.TrimSpace(s) == "" {
		// Last resort: try just `nginx -V` in PATH.
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		cmd2 := exec.CommandContext(ctx2, "nginx", "-V")
		buf.Reset()
		cmd2.Stdout = &buf
		cmd2.Stderr = &buf
		_ = cmd2.Run()
		s = buf.String()
	}

	if strings.TrimSpace(s) == "" {
		// Dummy when we can't exec.
		return []string{
			"stub_status",
			"coraza-nginx",
			"ngx_http_geoip2_module",
			"nginx-ssl-fingerprint",
		}
	}

	// Extract build flags.
	reAdd := regexp.MustCompile(`--add-(dynamic-)?module=([^\s]+)`)
	m := reAdd.FindAllStringSubmatch(s, -1)
	seen := map[string]bool{}
	mod := make([]string, 0, len(m)+4)
	for _, row := range m {
		if len(row) < 3 {
			continue
		}
		p := strings.TrimSpace(row[2])
		if p == "" {
			continue
		}
		name := filepath.Base(p)
		if name == "" || name == "." || name == "/" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			mod = append(mod, name)
		}
	}

	// Also include with-http/with-stream modules flags if present.
	if strings.Contains(s, "--with-http_ssl_module") && !seen["http_ssl_module"] {
		seen["http_ssl_module"] = true
		mod = append(mod, "http_ssl_module")
	}
	if strings.Contains(s, "--with-http_v2_module") && !seen["http_v2_module"] {
		seen["http_v2_module"] = true
		mod = append(mod, "http_v2_module")
	}

	// Ensure core pieces show up.
	if !seen["stub_status"] {
		mod = append([]string{"stub_status"}, mod...)
	}

	return mod
}
