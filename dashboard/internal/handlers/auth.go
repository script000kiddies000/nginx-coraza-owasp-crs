package handlers

import (
	"net/http"

	"flux-waf/internal/store"
)

// PageLogin renders the standalone login page.
func (app *App) PageLogin(w http.ResponseWriter, r *http.Request) {
	// If already has a valid session, skip to dashboard.
	if c, err := r.Cookie("flux_session"); err == nil {
		if _, err2 := store.GetSession(app.DB, c.Value); err2 == nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	app.renderLogin(w, r.URL.Query().Get("error"))
}

// APILogin handles POST /api/login — validates credentials, creates session cookie.
func (app *App) APILogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=bad_request", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if _, err := store.ValidatePassword(app.DB, username, password); err != nil {
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
		return
	}

	token, err := store.CreateSession(app.DB, username)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "flux_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// APILogout deletes the session and clears the cookie.
func (app *App) APILogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("flux_session"); err == nil {
		_ = store.DeleteSession(app.DB, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "flux_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
