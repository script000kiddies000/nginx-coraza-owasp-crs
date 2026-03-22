package web

import "embed"

// FS exposes the web/template and web/public directories to the Go binary
// via go:embed. All files are baked into the binary at build time — no
// "file not found" errors at runtime inside Docker.
//
//go:embed template public
var FS embed.FS
