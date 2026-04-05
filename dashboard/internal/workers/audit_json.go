package workers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/models"
)

// securityEventFromCorazaTransactionJSON maps Coraza SecAuditLogFormat JSON (transaction + messages).
// Contoh root: {"transaction":{...},"messages":[{"message":"...","data":{"id":9900007,...}}]}
func securityEventFromCorazaTransactionJSON(m map[string]any) (models.SecurityEvent, bool) {
	tx, ok := m["transaction"].(map[string]any)
	if !ok {
		return models.SecurityEvent{}, false
	}

	ev := models.SecurityEvent{
		Time: normalizeCorazaTimestamp(tx),
	}

	if v, ok := tx["client_ip"].(string); ok {
		ev.ClientIP = strings.TrimSpace(v)
	}

	if req, ok := tx["request"].(map[string]any); ok {
		if uri, ok := req["uri"].(string); ok {
			ev.URI = uri
		}
	}

	if h := hostFromAuditMap(m); h != "" {
		ev.Host = h
	}

	msgs, ok := m["messages"].([]any)
	if !ok || len(msgs) == 0 {
		return models.SecurityEvent{}, false
	}
	first, ok := msgs[0].(map[string]any)
	if !ok {
		return models.SecurityEvent{}, false
	}

	if msg, ok := first["message"].(string); ok {
		ev.Message = msg
	}

	if data, ok := first["data"].(map[string]any); ok {
		ev.RuleID = ruleIDFromData(data)
		ev.Severity = severityFromData(data)
	}

	if ev.Message == "" && ev.RuleID == "" {
		return models.SecurityEvent{}, false
	}

	ev.Action = actionFromCorazaTransaction(tx, m)

	return ev, true
}

func ruleIDFromData(data map[string]any) string {
	switch v := data["id"].(type) {
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case json.Number:
		return string(v)
	case string:
		return v
	default:
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

func severityFromData(data map[string]any) string {
	switch v := data["severity"].(type) {
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case string:
		return v
	default:
		return ""
	}
}

func actionFromCorazaTransaction(tx map[string]any, root map[string]any) string {
	if resp, ok := tx["response"].(map[string]any); ok {
		if st, ok := resp["status"].(float64); ok && st >= 400 {
			return "blocked"
		}
	}
	if v, ok := tx["is_interrupted"].(bool); ok && v {
		return "blocked"
	}
	// sibling of transaction in some builds
	if v, ok := root["is_interrupted"].(bool); ok && v {
		return "blocked"
	}
	return "blocked"
}

func normalizeCorazaTimestamp(tx map[string]any) string {
	if v, ok := tx["timestamp"].(string); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return time.Now().UTC().Format(time.RFC3339)
		}
		// "2026/04/05 13:54:57"
		if t, err := time.ParseInLocation("2006/01/02 15:04:05", v, time.UTC); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
		return v
	}
	return time.Now().UTC().Format(time.RFC3339)
}
