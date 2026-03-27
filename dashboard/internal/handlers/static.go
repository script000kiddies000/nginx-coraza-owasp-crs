package handlers

import (
	"io/fs"
	"net/http"
	"strings"

	"flux-waf/web"
)

// publicFS returns the web/public subtree from the embedded FS,
// used to serve /public/* static assets.
func publicFS() fs.FS {
	sub, err := fs.Sub(web.FS, "public")
	if err != nil {
		panic(err)
	}
	return sub
}

// publicHandler serves /public/* with long-lived browser cache.
// Cache busting is handled by query version in layout (AssetVersion).
func publicHandler(assetVersion string) http.Handler {
	base := http.StripPrefix("/public/", http.FileServer(http.FS(publicFS())))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cache static assets aggressively.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		etag := `W/"` + assetVersion + ":" + strings.TrimSpace(r.URL.Path) + `"`
		w.Header().Set("ETag", etag)
		if inm := strings.TrimSpace(r.Header.Get("If-None-Match")); inm != "" && inm == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		base.ServeHTTP(w, r)
	})
}
