package workers

import (
	"fmt"
	"strings"
)

// hostFromAuditMap pulls hostname from flat Coraza/ModSecurity JSON or nested request headers.
func hostFromAuditMap(m map[string]any) string {
	if h := stringField(m, "host", "hostname", "http_host", "server_name", "http_host_header", "request_hostname"); h != "" {
		return strings.TrimSpace(h)
	}
	if h := headersHostFromMap(m, "transaction", "request", "headers"); h != "" {
		return h
	}
	if h := headersHostFromMap(m, "request", "headers"); h != "" {
		return h
	}
	return ""
}

func headersHostFromMap(m map[string]any, path ...string) string {
	cur := any(m)
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	hdrs, ok := cur.(map[string]any)
	if !ok {
		return ""
	}
	for key, val := range hdrs {
		if strings.EqualFold(key, "host") {
			return normalizeHostHeader(val)
		}
	}
	return ""
}

func normalizeHostHeader(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		if len(t) > 0 {
			return strings.TrimSpace(fmt.Sprint(t[0]))
		}
	case []string:
		if len(t) > 0 {
			return strings.TrimSpace(t[0])
		}
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" || s == "<nil>" {
		return ""
	}
	return s
}
