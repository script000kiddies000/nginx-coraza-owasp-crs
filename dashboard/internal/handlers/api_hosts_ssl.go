package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── Hosts ─────────────────────────────────────────────────────────────────────

func (app *App) APIGetHosts(w http.ResponseWriter, r *http.Request) {
	hosts, _ := store.ListHosts(app.DB)
	if hosts == nil {
		hosts = []models.HostConfig{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// APISaveHost handles POST /api/hosts — add or update a host, write nginx conf, reload.
func (app *App) APISaveHost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		models.HostConfig
		PreviousDomain string `json:"previous_domain,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	h := body.HostConfig
	prev := strings.TrimSpace(body.PreviousDomain)

	h.Domain = strings.TrimSpace(h.Domain)
	if h.Domain == "" {
		jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}

	if h.Mode == "" {
		h.Mode = "reverse_proxy"
	}
	switch h.Mode {
	case "reverse_proxy", "static", "redirect":
	default:
		jsonError(w, "mode must be reverse_proxy, static, or redirect", http.StatusBadRequest)
		return
	}

	var validPorts []models.ListenPort
	for _, lp := range h.ListenPorts {
		if lp.Port > 0 && lp.Port <= 65535 {
			validPorts = append(validPorts, lp)
		}
	}
	if len(validPorts) == 0 {
		validPorts = []models.ListenPort{{Port: 80, HTTPS: false}}
	}
	h.ListenPorts = validPorts

	h.SSLEnabled = false
	for _, lp := range h.ListenPorts {
		if lp.HTTPS {
			h.SSLEnabled = true
			break
		}
	}

	switch h.Mode {
	case "reverse_proxy":
		var clean []string
		for _, s := range h.UpstreamServers {
			if s = strings.TrimSpace(s); s != "" {
				clean = append(clean, s)
			}
		}
		if len(clean) == 0 {
			jsonError(w, "at least one upstream server is required", http.StatusBadRequest)
			return
		}
		h.UpstreamServers = clean
		if h.LBAlgorithm == "" || len(clean) == 1 {
			h.LBAlgorithm = "round_robin"
		}
		switch h.LBAlgorithm {
		case "round_robin", "least_conn", "ip_hash":
		default:
			h.LBAlgorithm = "round_robin"
		}

	case "static":
		src := strings.ToLower(strings.TrimSpace(h.StaticSource))
		if src == "dashboard" {
			h.StaticSource = "dashboard"
			h.StaticRoot = nginx.DashboardStaticRoot(h.Domain)
		} else {
			h.StaticSource = "manual"
			h.StaticRoot = strings.TrimSpace(h.StaticRoot)
			if h.StaticRoot == "" {
				jsonError(w, "static_root is required for manual static mode (or set static_source to dashboard)", http.StatusBadRequest)
				return
			}
		}
		h.UpstreamServers = nil

	case "redirect":
		h.RedirectURL = strings.TrimSpace(h.RedirectURL)
		if h.RedirectURL == "" {
			jsonError(w, "redirect_url is required for redirect mode", http.StatusBadRequest)
			return
		}
		if h.RedirectCode != 301 && h.RedirectCode != 302 {
			h.RedirectCode = 301
		}
		h.UpstreamServers = nil
	}

	if h.WAFMode == "" {
		h.WAFMode = "On"
	}
	switch h.WAFMode {
	case "On", "Off", "DetectionOnly":
	default:
		jsonError(w, "waf_mode must be On, Off, or DetectionOnly", http.StatusBadRequest)
		return
	}

	if h.SSLEnabled {
		if err := resolveHostSSL(app.DB, &h); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		h.SSLCert = ""
		h.SSLKey = ""
		h.SSLCertID = ""
	}

	if prev != "" && prev != h.Domain {
		if _, err := store.GetHost(app.DB, prev); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				jsonError(w, "previous host not found: "+prev, http.StatusBadRequest)
				return
			}
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := store.GetHost(app.DB, h.Domain); err == nil {
			jsonError(w, "domain already exists: "+h.Domain, http.StatusConflict)
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := store.DeleteHost(app.DB, prev); err != nil {
			jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := nginx.DeleteHostConf(prev); err != nil {
			log.Printf("[hosts] rename: delete old conf %q: %v", prev, err)
		}
	}

	if err := store.SaveHost(app.DB, h); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if h.Enabled {
		if err := nginx.WriteHostConf(app.DB, h); err != nil {
			jsonError(w, "nginx conf: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := nginx.ReloadNginx(); err != nil {
			log.Printf("[hosts] nginx reload warning: %v", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

// APIDeleteHost handles DELETE /api/hosts/{domain} — remove host from DB + nginx conf.
func (app *App) APIDeleteHost(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}
	if err := store.DeleteHost(app.DB, domain); err != nil {
		jsonError(w, "db: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.DeleteHostConf(domain); err != nil {
		log.Printf("[hosts] delete conf %q: %v", domain, err)
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[hosts] nginx reload after delete: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"ok":true}`)
}

func sslCertDir() string {
	if p := os.Getenv("FLUX_SSL_DIR"); p != "" {
		return p
	}
	return "/etc/nginx/ssl_certs"
}

var reSSLBaseName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func sanitizeSSLBaseName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "localhost"
	}
	if !reSSLBaseName.MatchString(s) {
		return "localhost"
	}
	return s
}

type sslPair struct {
	Name    string `json:"name"`
	CRTPath string `json:"crt_path,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
	HasCRT  bool   `json:"has_crt"`
	HasKey  bool   `json:"has_key"`
	ModTime string `json:"mod_time,omitempty"`
}

// APIGetSSL lists available cert/key pairs in /etc/nginx/ssl_certs.
func (app *App) APIGetSSL(w http.ResponseWriter, r *http.Request) {
	dir := sslCertDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dir":   dir,
				"pairs": []sslPair{},
			})
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type pairParts struct {
		hasCRT bool
		hasKey bool
	}
	parts := map[string]*pairParts{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".crt") {
			base := strings.TrimSuffix(name, ".crt")
			p := parts[base]
			if p == nil {
				p = &pairParts{}
				parts[base] = p
			}
			p.hasCRT = true
		} else if strings.HasSuffix(name, ".key") {
			base := strings.TrimSuffix(name, ".key")
			p := parts[base]
			if p == nil {
				p = &pairParts{}
				parts[base] = p
			}
			p.hasKey = true
		}
	}

	bases := make([]string, 0, len(parts))
	for b := range parts {
		bases = append(bases, b)
	}
	sort.Strings(bases)

	pairs := make([]sslPair, 0, len(bases))
	for _, base := range bases {
		p := parts[base]
		crtPath := filepath.Join(dir, base+".crt")
		keyPath := filepath.Join(dir, base+".key")

		pair := sslPair{
			Name:   base,
			HasCRT: p.hasCRT,
			HasKey: p.hasKey,
		}
		if p.hasCRT {
			pair.CRTPath = crtPath
		}
		if p.hasKey {
			pair.KeyPath = keyPath
		}
		if p.hasCRT {
			if st, err := os.Stat(crtPath); err == nil {
				pair.ModTime = st.ModTime().UTC().Format(time.RFC3339)
			}
		}
		pairs = append(pairs, pair)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"dir":   dir,
		"pairs": pairs,
	})
}

// APIUploadSSL accepts multipart form fields:
// - name (basename, default "localhost")
// - crt (certificate file)
// - key (private key file)
func (app *App) APIUploadSSL(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, "invalid multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	name := sanitizeSSLBaseName(r.FormValue("name"))
	dir := sslCertDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		jsonError(w, "mkdir ssl dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	crtFile, _, err := r.FormFile("crt")
	if err != nil {
		jsonError(w, "crt file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer crtFile.Close()

	keyFile, _, err := r.FormFile("key")
	if err != nil {
		jsonError(w, "key file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer keyFile.Close()

	crtPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	writeTo := func(path string, src io.Reader, mode os.FileMode) error {
		tmp := path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			return err
		}
		_, cpErr := io.Copy(f, src)
		closeErr := f.Close()
		if cpErr != nil {
			_ = os.Remove(tmp)
			return cpErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if err := os.Chmod(tmp, mode); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, path)
	}

	if err := writeTo(crtPath, crtFile, 0644); err != nil {
		jsonError(w, "write crt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := writeTo(keyPath, keyFile, 0600); err != nil {
		jsonError(w, "write key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	reloadErr := nginx.ReloadNginx()
	w.Header().Set("Content-Type", "application/json")
	if reloadErr != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"name":       name,
			"crt_path":   crtPath,
			"key_path":   keyPath,
			"reload_err": reloadErr.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"name":     name,
		"crt_path": crtPath,
		"key_path": keyPath,
		"reloaded": true,
	})
}
