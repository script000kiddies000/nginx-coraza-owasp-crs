package logs

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// DefaultAccessJSONLog is nginx flux_json access log inside the container.
const DefaultAccessJSONLog = "/var/log/nginx/access_json.log"

// ReadAccessJSONTail reads up to maxEntries most recent JSON lines from the end of the file.
// If the file is missing, returns empty slice without error.
func ReadAccessJSONTail(path string, maxEntries int) ([]map[string]any, error) {
	if path == "" {
		path = DefaultAccessJSONLog
	}
	if maxEntries <= 0 {
		maxEntries = 100
	}
	if maxEntries > 2000 {
		maxEntries = 2000
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	const maxChunk = int64(4 << 20) // 4 MiB from EOF
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
	out := make([]map[string]any, 0, maxEntries)
	// Walk from bottom: newest lines are at end of file
	for i := len(lines) - 1; i >= 0 && len(out) < maxEntries; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}
