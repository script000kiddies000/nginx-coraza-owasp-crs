package logs

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
)

// ReadAccessJSONRecent reads up to maxLines JSON log entries from the end of the file,
// scanning at most maxBytes from EOF. Newest entries appear first in the returned slice.
func ReadAccessJSONRecent(path string, maxBytes int64, maxLines int) ([]map[string]any, error) {
	if path == "" {
		path = DefaultAccessJSONLog
	}
	if maxLines <= 0 {
		maxLines = 10000
	}
	if maxLines > 100000 {
		maxLines = 100000
	}
	if maxBytes <= 0 {
		maxBytes = 32 << 20 // 32 MiB
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	start := int64(0)
	if size > maxBytes {
		start = size - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(data, []byte("\n"))
	out := make([]map[string]any, 0, maxLines)
	for i := len(lines) - 1; i >= 0 && len(out) < maxLines; i-- {
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
