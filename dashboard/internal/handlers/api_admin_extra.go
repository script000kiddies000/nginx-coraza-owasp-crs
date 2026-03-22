package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
)

// ── Users (admin) ─────────────────────────────────────────────────────────────

func (app *App) APIListUsers(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	list, err := store.ListUsers(app.DB)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []models.UserAccount{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

func (app *App) APICreateUser(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	err := store.CreateUserAccount(app.DB, body.Username, body.Password, body.Role)
	if errors.Is(err, store.ErrUserExists) {
		jsonError(w, "username already exists", http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, nil)
}

func (app *App) APIDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	name := r.PathValue("username")
	if name == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}
	if name == usernameFromCtx(r) {
		jsonError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}
	err := store.DeleteUser(app.DB, name)
	if errors.Is(err, store.ErrLastAdmin) {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, nil)
}

func (app *App) APISetUserPassword(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	name := r.PathValue("username")
	if name == "" {
		jsonError(w, "username required", http.StatusBadRequest)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := store.SetUserPassword(app.DB, name, body.Password); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			jsonError(w, "user not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, nil)
}

// ── Custom Coraza rules file ─────────────────────────────────────────────────

func (app *App) APIGetCustomRules(w http.ResponseWriter, r *http.Request) {
	s, err := nginx.ReadUserRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"content": s})
}

func (app *App) APIPostCustomRules(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := nginx.WriteUserRules(body.Content); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[custom-rules] nginx reload: %v", err)
	}
	jsonOK(w, nil)
}

// ── GeoIP country block map ───────────────────────────────────────────────────

func (app *App) APIGetGeoBlock(w http.ResponseWriter, r *http.Request) {
	codes, err := nginx.ReadGeoBlockedISOs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if codes == nil {
		codes = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string][]string{"countries": codes})
}

func (app *App) APIPostGeoBlock(w http.ResponseWriter, r *http.Request) {
	if !app.requireAdmin(w, r) {
		return
	}
	var body struct {
		Countries []string `json:"countries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := nginx.WriteGeoBlockMap(body.Countries); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[geo-block] nginx reload: %v", err)
	}
	jsonOK(w, nil)
}
