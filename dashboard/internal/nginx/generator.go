package nginx

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/store"
)

const confDir = "/etc/nginx/conf.d"

const (
	defaultSSLDir = "/etc/nginx/ssl_certs"
	defaultSSLCrt = defaultSSLDir + "/localhost.crt"
	defaultSSLKey = defaultSSLDir + "/localhost.key"
)

// upstreamName converts a domain like "example.com" to "flux_example_com"
// for use as an nginx upstream block name.
func upstreamName(domain string) string {
	safe := strings.NewReplacer(".", "_", "-", "_", ":", "_").Replace(domain)
	return "flux_" + safe
}

func sslCertPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultSSLCrt
	}
	return p
}

func sslKeyPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultSSLKey
	}
	return p
}

// tlsPEMFileOK returns true if path exists and is non-empty (PEM on disk).
func tlsPEMFileOK(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}

// parseOneUpstream converts dashboard input (http(s)://host:port or bare host:port) to an nginx
// upstream "server" line and whether TLS should be used to the backend.
func parseOneUpstream(s string) (serverLine string, https bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false, fmt.Errorf("empty upstream")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", false, fmt.Errorf("invalid upstream URL %q", s)
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(host, port), true, nil
	}
	if strings.HasPrefix(lower, "http://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", false, fmt.Errorf("invalid upstream URL %q", s)
		}
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "80"
		}
		return net.JoinHostPort(host, port), false, nil
	}
	if strings.Contains(s, "://") {
		return "", false, fmt.Errorf("unsupported upstream %q (use http:// or https://)", s)
	}
	// Legacy bare host / host:port / IPv4 — implied HTTP port 80 if no port (nginx default).
	return s, false, nil
}

func normalizeUpstreamServers(raw []string) (lines []string, https bool, err error) {
	if len(raw) == 0 {
		return nil, false, fmt.Errorf("no upstream servers")
	}
	var wantHTTPS bool
	for i, s := range raw {
		line, isHTTPS, e := parseOneUpstream(s)
		if e != nil {
			return nil, false, e
		}
		if i == 0 {
			wantHTTPS = isHTTPS
		} else if isHTTPS != wantHTTPS {
			return nil, false, fmt.Errorf("all upstream servers must use the same scheme (http or https)")
		}
		lines = append(lines, line)
	}
	return lines, wantHTTPS, nil
}

// hostRenderData is passed to the nginx template (upstream lines + https flag).
type hostRenderData struct {
	models.HostConfig
	UpstreamLines []string
	UpstreamHTTPS bool
}

// hostTemplate is the nginx server block template for a managed host.
// It supports three modes: reverse_proxy, static, redirect.
var hostTemplate = template.Must(template.New("host").Funcs(template.FuncMap{
	"upstreamName": upstreamName,
	"sslCertPath":  sslCertPath,
	"sslKeyPath":   sslKeyPath,
	"join":         strings.Join,
	"hasHTTPS": func(ports []models.ListenPort) bool {
		for _, p := range ports {
			if p.HTTPS {
				return true
			}
		}
		return false
	},
	"redirectCode": func(code int) int {
		if code == 302 {
			return 302
		}
		return 301
	},
}).Parse(`# Managed by Flux WAF — do not edit manually
# Domain: {{.Domain}}{{if .Name}} ({{.Name}}){{end}}
# Mode:   {{if .Mode}}{{.Mode}}{{else}}reverse_proxy{{end}}
{{if or (not .Mode) (eq .Mode "reverse_proxy")}}
upstream {{upstreamName .Domain}} {
{{- if eq .LBAlgorithm "least_conn"}}
    least_conn;
{{- else if eq .LBAlgorithm "ip_hash"}}
    ip_hash;
{{- end}}
{{- range .UpstreamLines}}
    server {{.}};
{{- end}}
    keepalive 32;
}
{{end}}
server {
{{- range .ListenPorts}}
{{- if .HTTPS}}
    listen {{.Port}} ssl;
{{- else}}
    listen {{.Port}};
{{- end}}
{{- end}}
{{- if hasHTTPS .ListenPorts}}
    http2 on;
    ssl_certificate     {{sslCertPath .SSLCert}};
    ssl_certificate_key {{sslKeyPath .SSLKey}};
{{- end}}
    server_name {{.Domain}};

    location ^~ /.well-known/acme-challenge/ {
        coraza off;
        root /var/www/certbot;
        default_type text/plain;
        allow all;
    }

    coraza {{if eq .WAFMode "Off"}}off{{else}}on{{end}};
    coraza_rules_file /etc/nginx/coraza/coraza.conf;

    include /etc/nginx/snippets/hide-backend-headers.conf;

    location = /favicon.ico {
        access_log off;
        add_header Cache-Control "public, max-age=604800" always;
        return 204;
    }

    # Custom error pages (shared)
    error_page 400          /errors/400.html;
    error_page 401          /errors/401.html;
    error_page 403          /errors/403.html;
    error_page 404          /errors/404.html;
    error_page 429          /errors/429.html;
    error_page 500          /errors/500.html;
    error_page 502 503 504  /errors/502.html;

    # Subrequest internal untuk error_page — jangan jalankan CRS di sini.
    # Tanpa ini, GET ke /errors/*.html bisa ter-audit sebagai GET+body (920170) dan
    # menambah anomaly score / noise saat respons utama sudah 403/502 dari WAF/upstream.
    location ^~ /errors/ {
        internal;
        coraza off;
        root             /etc/nginx;
        add_header       Cache-Control "no-store" always;
        add_header       X-Request-ID  $request_id always;
        add_header       X-Flux-Block-Reason $flux_block_reason_display always;
        sub_filter       '__REQUEST_ID__' $request_id;
        sub_filter       '__FLUX_BLOCK_REASON__' $flux_block_reason_display;
        sub_filter_once  on;
    }
{{if eq .Mode "redirect"}}
    location / {
        return {{redirectCode .RedirectCode}} {{.RedirectURL}};
    }
{{else if eq .Mode "static"}}
    root {{.StaticRoot}};
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
{{else}}
{{- range .ExcludePaths}}
    location {{.}} {
        coraza off;
        proxy_pass {{if $.UpstreamHTTPS}}https{{else}}http{{end}}://{{upstreamName $.Domain}};
{{- if $.UpstreamHTTPS}}
        proxy_ssl_server_name on;
{{- if $.ProxySSLName}}
        proxy_ssl_name {{$.ProxySSLName}};
{{- end}}
{{- if $.ProxySSLVerifyOff}}
        proxy_ssl_verify off;
{{- end}}
{{- end}}
    }
{{- end}}

    location / {
        proxy_intercept_errors on;
        proxy_pass         {{if .UpstreamHTTPS}}https{{else}}http{{end}}://{{upstreamName .Domain}};
        proxy_http_version 1.1;
{{- if .UpstreamHTTPS}}
        proxy_ssl_server_name on;
{{- if .ProxySSLName}}
        proxy_ssl_name {{.ProxySSLName}};
{{- end}}
{{- if .ProxySSLVerifyOff}}
        proxy_ssl_verify off;
{{- end}}
{{- end}}
        proxy_set_header   Connection      "";
        proxy_set_header   Host              $http_host;
        proxy_set_header   X-Forwarded-Host  $http_host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   X-Request-ID    $request_id;
    }
{{end}}
}
`))

// effectivePorts returns the listen ports to use, falling back to [{80, false}]
// for legacy HostConfig entries that pre-date the ListenPorts field.
func effectivePorts(h models.HostConfig) []models.ListenPort {
	if len(h.ListenPorts) > 0 {
		return h.ListenPorts
	}
	// Legacy: derive from old SSLEnabled flag
	ports := []models.ListenPort{{Port: 80, HTTPS: false}}
	if h.SSLEnabled {
		ports = append(ports, models.ListenPort{Port: 443, HTTPS: true})
	}
	return ports
}

// WriteHostConf renders the nginx config for a HostConfig and writes it to
// /etc/nginx/conf.d/<domain>.conf.
func WriteHostConf(h models.HostConfig) error {
	// Fill effective ports
	h.ListenPorts = effectivePorts(h)

	// Default mode
	if h.Mode == "" {
		h.Mode = "reverse_proxy"
	}

	// Validate mode-specific requirements
	switch h.Mode {
	case "reverse_proxy":
		if len(h.UpstreamServers) == 0 {
			return fmt.Errorf("host %q has no upstream servers", h.Domain)
		}
	case "static":
		if h.StaticRoot == "" {
			return fmt.Errorf("host %q: static mode requires static_root", h.Domain)
		}
	case "redirect":
		if h.RedirectURL == "" {
			return fmt.Errorf("host %q: redirect mode requires redirect_url", h.Domain)
		}
	}

	// Derive SSLEnabled from ports for template logic
	for _, p := range h.ListenPorts {
		if p.HTTPS {
			h.SSLEnabled = true
			break
		}
	}

	// Jika BoltDB menyimpan path cert kustom (cust_*.crt) tapi file hilang — misal git clone
	// baru tanpa ./ssl_certs lama — pakai default localhost.* dari cont-init agar nginx -t lolos.
	if h.SSLCert != "" && !tlsPEMFileOK(h.SSLCert) {
		h.SSLCert = ""
	}
	if h.SSLKey != "" && !tlsPEMFileOK(h.SSLKey) {
		h.SSLKey = ""
	}

	h.ProxySSLName = strings.TrimSpace(h.ProxySSLName)

	data := hostRenderData{HostConfig: h}
	if h.Mode == "" || h.Mode == "reverse_proxy" {
		lines, upHTTPS, err := normalizeUpstreamServers(h.UpstreamServers)
		if err != nil {
			return fmt.Errorf("host %q: %w", h.Domain, err)
		}
		data.UpstreamLines = lines
		data.UpstreamHTTPS = upHTTPS
	}

	path := filepath.Join(confDir, h.Domain+".conf")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return hostTemplate.Execute(f, data)
}

// DeleteHostConf removes the nginx config file for the given domain.
func DeleteHostConf(domain string) error {
	path := filepath.Join(confDir, domain+".conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReloadNginx sends SIGHUP to the nginx master process.
// Uses /usr/sbin/nginx directly to avoid PATH issues inside s6-overlay.
func ReloadNginx() error {
	bin := "/usr/sbin/nginx"
	if p, err := exec.LookPath("nginx"); err == nil {
		bin = p
	}
	out, err := exec.Command(bin, "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx reload: %w — %s", err, out)
	}
	return nil
}

// SyncAllConfigs is the pre-flight sync: iterates all HostConfigs in BoltDB
// and writes their conf files. Called once at startup before serving traffic.
func SyncAllConfigs(db *bolt.DB) error {
	hosts, err := store.ListHosts(db)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		if err := WriteHostConf(h); err != nil {
			return fmt.Errorf("sync host %q: %w", h.Domain, err)
		}
	}
	return nil
}
