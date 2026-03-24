package workers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"flux-waf/internal/models"
	"flux-waf/internal/nginx"
	"flux-waf/internal/store"
	"flux-waf/internal/threatintel"
)

const (
	accessJSONLog = "/var/log/nginx/access_json.log"
	corazaAuditLog = "/var/log/nginx/coraza_audit.log"
)

var (
	reAuditID     = regexp.MustCompile(`\[id "([^"]+)"\]`)
	reAuditMsg    = regexp.MustCompile(`\[msg "([^"]*)"\]`)
	reAuditClient = regexp.MustCompile(`\[client ([^\]]+)\]`)
	reAuditURI    = regexp.MustCompile(`\[uri "([^"]*)"\]`)
)

// Start launches all background goroutines. Called once from main().
func Start(db *bolt.DB) {
	go sessionCleaner(db)
	go logTailer(db)
	go auditTailer(db)
	go threatIntelSync(db)
}

// sessionCleaner runs every hour and removes expired sessions from BoltDB.
func sessionCleaner(db *bolt.DB) {
	for range time.Tick(time.Hour) {
		store.CleanExpiredSessions(db)
		log.Println("[workers] expired sessions cleaned")
	}
}

// logTailer tails /var/log/nginx/access_json.log every second using byte-offset
// polling (pure Go, no external dependencies). Parses JSON entries and updates
// hourly stats in BoltDB.
//
// Full implementation: Fase 3. Currently only parses and counts requests.
func logTailer(db *bolt.DB) {
	var offset int64

	for range time.Tick(time.Second) {
		f, err := os.Open(accessJSONLog)
		if err != nil {
			continue // file not yet created by nginx
		}

		info, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}

		// If file was rotated (shrunk), reset offset.
		if info.Size() < offset {
			offset = 0
		}

		if info.Size() == offset {
			f.Close()
			continue
		}

		if _, err := f.Seek(offset, 0); err != nil {
			f.Close()
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			processLogEntry(db, entry)
		}
		offset, _ = f.Seek(0, 1) // current position after scanning
		f.Close()
	}
}

// auditTailer tails coraza_audit.log (Serial or occasional JSON lines) and stores
// compact events in BoltDB for the Security Events UI.
func auditTailer(db *bolt.DB) {
	var offset int64

	for range time.Tick(time.Second) {
		f, err := os.Open(corazaAuditLog)
		if err != nil {
			continue
		}

		info, err := f.Stat()
		if err != nil {
			f.Close()
			continue
		}

		if info.Size() < offset {
			offset = 0
		}
		if info.Size() == offset {
			f.Close()
			continue
		}

		if _, err := f.Seek(offset, 0); err != nil {
			f.Close()
			continue
		}

		scanner := bufio.NewScanner(f)
		// Serial audit entries can be long single lines
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if ev, ok := parseAuditLine(line); ok {
				if err := store.AppendSecurityEvent(db, ev); err != nil {
					log.Printf("[workers] append security event: %v", err)
				}
				if strings.Contains(strings.ToLower(ev.Message), "dlp") {
					dlpEv := models.DLPEvent{
						Time:     ev.Time,
						Type:     "dlp",
						ClientIP: ev.ClientIP,
						URI:      ev.URI,
						Action:   ev.Action,
						Message:  ev.Message,
					}
					if err := store.AppendDLPEvent(db, dlpEv); err != nil {
						log.Printf("[workers] append dlp event: %v", err)
					}
				}
			}
		}
		offset, _ = f.Seek(0, 1)
		f.Close()
	}
}

func parseAuditLine(line string) (models.SecurityEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return models.SecurityEvent{}, false
	}

	now := time.Now().UTC().Format(time.RFC3339)

	if strings.HasPrefix(line, "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return models.SecurityEvent{}, false
		}
		ev := models.SecurityEvent{Time: now}
		if v, ok := m["timestamp"].(string); ok && v != "" {
			ev.Time = v
		}
		ev.ClientIP = stringField(m, "client_ip", "clientip", "ip")
		ev.RuleID = stringField(m, "ruleid", "rule_id", "id")
		ev.Message = stringField(m, "message", "msg")
		ev.Action = stringField(m, "action", "disruptive_action")
		ev.URI = stringField(m, "uri", "request_uri", "url")
		if ev.RuleID != "" || ev.Message != "" {
			return ev, true
		}
		return models.SecurityEvent{}, false
	}

	if !strings.Contains(line, "[id \"") &&
		!strings.Contains(strings.ToLower(line), "modsecurity") &&
		!strings.Contains(strings.ToLower(line), "coraza") {
		return models.SecurityEvent{}, false
	}

	ev := models.SecurityEvent{Time: now}
	if m := reAuditClient.FindStringSubmatch(line); len(m) > 1 {
		ev.ClientIP = strings.TrimSpace(m[1])
	}
	if m := reAuditID.FindStringSubmatch(line); len(m) > 1 {
		ev.RuleID = m[1]
	}
	if m := reAuditMsg.FindStringSubmatch(line); len(m) > 1 {
		ev.Message = m[1]
	}
	if m := reAuditURI.FindStringSubmatch(line); len(m) > 1 {
		ev.URI = m[1]
	}
	if strings.Contains(strings.ToLower(line), "denied") || strings.Contains(strings.ToLower(line), "blocked") {
		ev.Action = "blocked"
	}
	if ev.RuleID == "" && ev.Message == "" {
		return models.SecurityEvent{}, false
	}
	if ev.URI == "" {
		if len(line) > 400 {
			ev.URI = line[:400] + "…"
		} else {
			ev.URI = line
		}
	}
	return ev, true
}

func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s := fmt.Sprint(v)
			if s != "" && s != "<nil>" {
				return s
			}
		}
	}
	return ""
}

// processLogEntry updates hourly stats from a single parsed access_json.log entry.
func processLogEntry(db *bolt.DB, entry map[string]any) {
	ts, _ := entry["time"].(string)
	if len(ts) < 13 {
		return
	}
	// hour key: "2026-03-22-14" from ISO timestamp "2026-03-22T14:05:00+00:00"
	hour := ts[:10] + "-" + ts[11:13]

	status, _ := entry["status"].(float64)

	stat := store.GetHourlyStat(db, hour)
	stat.TotalRequests++
	if int(status) >= 400 {
		stat.BlockedCount++
	} else {
		stat.AllowedCount++
	}
	_ = store.SaveHourlyStat(db, models.HourlyStats{
		Hour:          hour,
		TotalRequests: stat.TotalRequests,
		BlockedCount:  stat.BlockedCount,
		AllowedCount:  stat.AllowedCount,
	})
}

// threatIntelSync syncs threat intelligence feeds every 24 hours.
// Full implementation: Fase 5.
func threatIntelSync(db *bolt.DB) {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		time.Sleep(time.Until(next))

		cfg := store.GetThreatIntelConfig(db)
		if cfg.Enabled {
			ipPath := threatintel.DefaultIPRulesPath
			if p := os.Getenv("FLUX_THREAT_INTEL_IP_RULES"); p != "" {
				ipPath = p
			}
			jsonPath := threatintel.DefaultJSONPath
			if p := os.Getenv("FLUX_THREAT_INTEL_JSON"); p != "" {
				jsonPath = p
			}
			res, err := threatintel.SyncFeeds(cfg, jsonPath, ipPath)
			if err != nil {
				log.Printf("[workers] threat intel sync failed: %v", err)
				continue
			}
			if err := nginx.ReloadNginx(); err != nil {
				log.Printf("[workers] threat intel nginx reload failed: %v", err)
				continue
			}
			cfg.LastSync = res.LastSync
			cfg.IPCount = res.IPCount
			if err := store.SaveThreatIntelConfig(db, cfg); err != nil {
				log.Printf("[workers] save threat intel config failed: %v", err)
				continue
			}
			log.Printf("[workers] threat intel synced at midnight, total deny: %d", res.IPCount)
		}
	}
}
