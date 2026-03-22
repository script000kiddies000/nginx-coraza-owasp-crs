package nginx

import (
	"fmt"
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

// upstreamName converts a domain like "example.com" to "flux_example_com"
// for use as an nginx upstream block name.
func upstreamName(domain string) string {
	safe := strings.NewReplacer(".", "_", "-", "_", ":", "_").Replace(domain)
	return "flux_" + safe
}

// hostTemplate is the nginx server block template for a managed host.
var hostTemplate = template.Must(template.New("host").Funcs(template.FuncMap{
	"upstreamName": upstreamName,
	"join":         strings.Join,
}).Parse(`# Managed by Flux WAF — do not edit manually
# Domain: {{.Domain}}

upstream {{upstreamName .Domain}} {
{{- if eq .LBAlgorithm "least_conn"}}
    least_conn;
{{- else if eq .LBAlgorithm "ip_hash"}}
    ip_hash;
{{- end}}
{{- range .UpstreamServers}}
    server {{.}};
{{- end}}
    keepalive 32;
}

server {
    listen 80;
{{- if .SSLEnabled}}
    listen 443 ssl;
    http2 on;
    ssl_certificate     {{.SSLCert}};
    ssl_certificate_key {{.SSLKey}};
{{- end}}
    server_name {{.Domain}};

    coraza {{if eq .WAFMode "Off"}}off{{else}}on{{end}};
    coraza_rules_file /etc/nginx/coraza/coraza.conf;

    include /etc/nginx/snippets/hide-backend-headers.conf;

{{- range .ExcludePaths}}
    location {{.}} { coraza off; proxy_pass http://{{upstreamName $.Domain}}; }
{{- end}}

    location / {
        proxy_pass         http://{{upstreamName .Domain}};
        proxy_http_version 1.1;
        proxy_set_header   Connection      "";
        proxy_set_header   Host            $http_host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_set_header   X-Request-ID    $request_id;
    }
}
`))

// WriteHostConf renders the nginx config for a HostConfig and writes it to
// /etc/nginx/conf.d/<domain>.conf.
func WriteHostConf(h models.HostConfig) error {
	if len(h.UpstreamServers) == 0 {
		return fmt.Errorf("host %q has no upstream servers", h.Domain)
	}
	path := filepath.Join(confDir, h.Domain+".conf")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	return hostTemplate.Execute(f, h)
}

// DeleteHostConf removes the nginx config file for the given domain.
func DeleteHostConf(domain string) error {
	path := filepath.Join(confDir, domain+".conf")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReloadNginx sends SIGHUP to the nginx master process via `nginx -s reload`.
func ReloadNginx() error {
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
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
