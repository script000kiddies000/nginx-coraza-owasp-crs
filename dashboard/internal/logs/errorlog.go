package logs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
)

// DefaultNginxErrorLog is the standard Nginx error log path in this container.
const DefaultNginxErrorLog = "/var/log/nginx/error.log"

var (
	reErrLevel = regexp.MustCompile(`^\s*\[([a-zA-Z]+)\]\s*(.*)$`)
)

type NginxEventLogLine struct {
	Level string `json:"level"`
	Line  string `json:"line"`
	// Raw keeps original message for debugging.
	Raw string `json:"raw"`
}

// ReadNginxErrorLogTail reads up to maxLines most recent lines from error log.
// Implementation: read up to a fixed tail chunk from EOF, then keep last lines.
func ReadNginxErrorLogTail(path string, maxLines int) ([]NginxEventLogLine, error) {
	if path == "" {
		path = DefaultNginxErrorLog
	}
	if maxLines <= 0 {
		maxLines = 200
	}
	if maxLines > 2000 {
		maxLines = 2000
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []NginxEventLogLine{}, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := st.Size()
	// Keep tail chunk small enough for UI polling.
	const maxChunk = int64(6 << 20) // 6 MiB
	start := int64(0)
	if size > maxChunk {
		start = size - maxChunk
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(data, []byte("\n"))
	// Convert to tail lines (newest last).
	out := make([]NginxEventLogLine, 0, maxLines)
	for i := len(lines) - 1; i >= 0 && len(out) < maxLines; i-- {
		rawLine := bytes.TrimSpace(lines[i])
		if len(rawLine) == 0 {
			continue
		}
		raw := string(rawLine)
		level := ""
		line := raw
		if m := reErrLevel.FindStringSubmatch(raw); len(m) == 3 {
			level = m[1]
			line = m[2]
		}
		out = append(out, NginxEventLogLine{Level: level, Line: line, Raw: raw})
	}

	// We built newest -> oldest, reverse to oldest -> newest for nicer rendering.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// SafeJSON marshals logs lines to JSON (helper for debugging).
func SafeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

