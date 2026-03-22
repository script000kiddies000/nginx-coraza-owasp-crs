package main

import (
	"log"
	"net/http"
	"os"

	"flux-waf/internal/handlers"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/workers"
)

func main() {
	dbPath := envOr("FLUX_DB_PATH", "/var/lib/flux-waf/data.db")
	addr := ":" + envOr("FLUX_PORT", "8080")
	adminPass := os.Getenv("FLUX_ADMIN_PASSWORD")

	// ── Database ─────────────────────────────────────────────────────────
	db, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("[flux-waf] open db: %v", err)
	}
	defer db.Close()

	if err := store.InitBuckets(db); err != nil {
		log.Fatalf("[flux-waf] init buckets: %v", err)
	}

	// First-boot: create default admin user if no users exist.
	if err := store.BootstrapAdmin(db, adminPass); err != nil {
		log.Fatalf("[flux-waf] bootstrap admin: %v", err)
	}

	// ── Pre-flight sync ───────────────────────────────────────────────────
	// Regenerate all nginx conf files from DB so configs survive container
	// restarts even if the conf.d volume was wiped.
	if err := nginx.SyncAllConfigs(db); err != nil {
		log.Printf("[flux-waf] nginx sync warning: %v", err)
	}

	waf := store.GetWAFSettings(db)
	if err := nginx.WriteWAFMode(waf.Mode); err != nil {
		log.Printf("[flux-waf] sync WAF mode file: %v", err)
	} else if err := nginx.ReloadNginx(); err != nil {
		log.Printf("[flux-waf] nginx reload after WAF mode sync: %v", err)
	}

	// ── Background workers ────────────────────────────────────────────────
	workers.Start(db)

	// ── HTTP server ───────────────────────────────────────────────────────
	router, err := handlers.NewRouter(db)
	if err != nil {
		log.Fatalf("[flux-waf] init router: %v", err)
	}

	log.Printf("[flux-waf] listening on %s  db=%s", addr, dbPath)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("[flux-waf] server: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
