package nginx

import (
	"os"
	"time"
)

// FileMeta is lightweight stat info for dashboard status APIs.
type FileMeta struct {
	Path    string `json:"path"`
	ModTime string `json:"mod_time,omitempty"`
	Size    int64  `json:"size"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// StatConfigFile returns metadata for a single path (e.g. vpatch.rules).
func StatConfigFile(path string) FileMeta {
	m := FileMeta{Path: path}
	st, err := os.Stat(path)
	if err != nil {
		m.Error = err.Error()
		return m
	}
	m.OK = true
	m.Size = st.Size()
	m.ModTime = st.ModTime().UTC().Format(time.RFC3339)
	return m
}
