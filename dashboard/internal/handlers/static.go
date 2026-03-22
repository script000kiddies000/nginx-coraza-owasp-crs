package handlers

import (
	"io/fs"

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
