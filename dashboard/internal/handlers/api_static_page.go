package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

const maxStaticHTMLBytes = 2 << 20 // 2 MiB

func normalizeStaticHostForRead(h models.HostConfig) models.HostConfig {
	if h.Mode != "static" {
		return h
	}
	if strings.EqualFold(strings.TrimSpace(h.StaticSource), "dashboard") {
		h.StaticRoot = nginx.DashboardStaticRoot(h.Domain)
		h.StaticSource = "dashboard"
		return h
	}
	if strings.TrimSpace(h.StaticSource) == "" && strings.TrimSpace(h.StaticRoot) != "" {
		h.StaticSource = "manual"
	}
	return h
}

// APIGetStaticPage returns index.html for a static host.
func (app *App) APIGetStaticPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.TrimSpace(r.PathValue("domain"))
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}
	h, err := store.GetHost(app.DB, domain)
	if err != nil {
		jsonError(w, "host not found", http.StatusNotFound)
		return
	}
	if h.Mode != "static" {
		jsonError(w, "host is not in static mode", http.StatusBadRequest)
		return
	}
	h = normalizeStaticHostForRead(h)
	path, err := nginx.StaticIndexPath(h)
	if err != nil {
		jsonError(w, "invalid static configuration", http.StatusBadRequest)
		return
	}
	src := strings.TrimSpace(h.StaticSource)
	if src == "" {
		src = "manual"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":     true,
				"html":   "",
				"path":   path,
				"root":   nginx.EffectiveStaticRoot(h),
				"source": src,
			})
			return
		}
		jsonError(w, "read file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"html":   string(b),
		"path":   path,
		"root":   nginx.EffectiveStaticRoot(h),
		"source": src,
	})
}

// APIPostStaticPage writes index.html for hosts with static_source=dashboard.
func (app *App) APIPostStaticPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.TrimSpace(r.PathValue("domain"))
	if domain == "" {
		jsonError(w, "domain required", http.StatusBadRequest)
		return
	}
	h, err := store.GetHost(app.DB, domain)
	if err != nil {
		jsonError(w, "host not found", http.StatusNotFound)
		return
	}
	if h.Mode != "static" {
		jsonError(w, "host is not in static mode", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(h.StaticSource), "dashboard") {
		jsonError(w, "saving HTML is only enabled when static_source is dashboard", http.StatusBadRequest)
		return
	}
	var body struct {
		HTML string `json:"html"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxStaticHTMLBytes+1)).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.HTML) > maxStaticHTMLBytes {
		jsonError(w, fmt.Sprintf("html exceeds max size (%d bytes)", maxStaticHTMLBytes), http.StatusBadRequest)
		return
	}
	h.StaticRoot = nginx.DashboardStaticRoot(h.Domain)
	h.StaticSource = "dashboard"
	path, err := nginx.StaticIndexPathMustBeUnderBase(h, nginx.StaticWebRootBase())
	if err != nil {
		jsonError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		jsonError(w, "mkdir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body.HTML), 0644); err != nil {
		jsonError(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		jsonError(w, "rename: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = nginx.ReloadNginx()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "path": path})
}
