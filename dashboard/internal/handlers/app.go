package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/web"
)

type contextKey string

const contextKeyUsername contextKey = "username"

// App holds shared dependencies for all HTTP handlers.
type App struct {
	DB           *bolt.DB
	base         *template.Template // parsed layout.html, cloned per request
	assetVersion string
}

// NewApp initialises the App and pre-parses the master layout template.
func NewApp(db *bolt.DB) (*App, error) {
	base, err := template.New("").ParseFS(web.FS, "template/layout.html", "template/sidebar.html")
	if err != nil {
		return nil, fmt.Errorf("parse layout template: %w", err)
	}
	assetVersion := os.Getenv("FLUX_ASSET_VERSION")
	if assetVersion == "" {
		assetVersion = strconv.FormatInt(time.Now().Unix(), 36)
	}
	if err := nginx.WriteAuditLogFormat(store.GetAuditLogFormatConfig(db).Format); err != nil {
		log.Printf("[app] audit log format conf: %v", err)
	}
	return &App{DB: db, base: base, assetVersion: assetVersion}, nil
}

// render clones the base layout, adds the named page template, and executes
// the "layout" template into the ResponseWriter.
// page is the filename under web/template/pages/ WITHOUT the .html extension.
func (app *App) render(w http.ResponseWriter, r *http.Request, page string, data models.PageData) {
	if data.Username == "" {
		data.Username = usernameFromCtx(r)
	}
	if data.AssetVersion == "" {
		data.AssetVersion = app.assetVersion
	}

	t, err := app.base.Clone()
	if err != nil {
		http.Error(w, "template clone error", http.StatusInternalServerError)
		return
	}
	if _, err = t.ParseFS(web.FS, "template/pages/"+page+".html"); err != nil {
		http.Error(w, fmt.Sprintf("template %q: %v", page, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-cache, max-age=0, must-revalidate")
	if err = t.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("[render] %s: %v", page, err)
	}
}

// renderLogin renders the standalone login page (no sidebar layout).
func (app *App) renderLogin(w http.ResponseWriter, errMsg string) {
	t, err := template.New("").ParseFS(web.FS, "template/pages/login.html")
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	data := struct{ Error string }{Error: errMsg}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-cache, max-age=0, must-revalidate")
	if err = t.ExecuteTemplate(w, "login", data); err != nil {
		log.Printf("[renderLogin] %v", err)
	}
}

// jsonOK writes a JSON 200 response with the given payload.
// payload nil → {"ok":true}; map → keys merged with "ok":true; other values → marshalled and merged with "ok":true.
func jsonOK(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if payload == nil {
		_, _ = w.Write([]byte(`{"ok":true}`))
		return
	}
	switch p := payload.(type) {
	case map[string]any:
		out := make(map[string]any, len(p)+1)
		out["ok"] = true
		for k, v := range p {
			out[k] = v
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		b, err := json.Marshal(payload)
		if err != nil {
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		var obj map[string]any
		if err := json.Unmarshal(b, &obj); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
		obj["ok"] = true
		_ = json.NewEncoder(w).Encode(obj)
	}
}

// jsonError writes a JSON error response.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"ok":false,"error":%q}`, msg)
}

// usernameFromCtx extracts the authenticated username injected by RequireAuth.
func usernameFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(contextKeyUsername).(string)
	return v
}

// withUsername injects the username into the request context.
func withUsername(r *http.Request, username string) *http.Request {
	ctx := context.WithValue(r.Context(), contextKeyUsername, username)
	return r.WithContext(ctx)
}

// requireAdmin responds with 403 JSON unless the current user has role "admin".
func (app *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u, err := store.GetUser(app.DB, usernameFromCtx(r))
	if err != nil || u.Role != "admin" {
		jsonError(w, "admin privileges required", http.StatusForbidden)
		return false
	}
	return true
}

// RequireAuth wraps a handler and redirects to /login if no valid session exists.
func (app *App) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("flux_session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		username, err := store.GetSession(app.DB, cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, withUsername(r, username))
	}
}
