package monitor

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"flux-waf/internal/models"
)

// DefaultNginxStatusURL is where stub_status is exposed (see conf.d/default.conf :81).
const DefaultNginxStatusURL = "http://127.0.0.1:81/nginx_status"

var (
	reActive  = regexp.MustCompile(`Active connections:\s*(\d+)`)
	reRWWait  = regexp.MustCompile(`Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)`)
)

// NginxStatusURL returns FLUX_NGINX_STATUS_URL or the default.
func NginxStatusURL() string {
	if u := os.Getenv("FLUX_NGINX_STATUS_URL"); u != "" {
		return u
	}
	return DefaultNginxStatusURL
}

// FetchNginxStatus GETs stub_status and parses the plain-text body.
func FetchNginxStatus(client *http.Client) (models.NginxStatus, error) {
	var zero models.NginxStatus
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, NginxStatusURL(), nil)
	if err != nil {
		return zero, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, fmt.Errorf("nginx status request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return zero, err
	}
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("nginx status: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	s, err := parseStubStatus(string(body))
	if err != nil {
		return s, err
	}

	// Best-effort: process table + distribution (Linux via /proc).
	entries, master, worker, cache, other := collectNginxProcessEntries()
	s.Processes = entries
	s.MasterProcesses = master
	s.WorkerProcesses = worker
	s.CacheProcesses = cache
	s.OtherProcesses = other

	// Best-effort: configuration and build modules.
	s.Configuration = collectNginxConfiguration()
	s.Modules = collectNginxModules()

	return s, nil
}

func parseStubStatus(body string) (models.NginxStatus, error) {
	var s models.NginxStatus
	if m := reActive.FindStringSubmatch(body); len(m) == 2 {
		s.ActiveConnections, _ = strconv.Atoi(m[1])
	}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if strings.Contains(line, "accepts handled requests") && i+1 < len(lines) {
			next := strings.TrimSpace(lines[i+1])
			_, _ = fmt.Sscanf(next, "%d %d %d", &s.Accepts, &s.Handled, &s.Requests)
			break
		}
	}
	if m := reRWWait.FindStringSubmatch(body); len(m) == 4 {
		s.Reading, _ = strconv.Atoi(m[1])
		s.Writing, _ = strconv.Atoi(m[2])
		s.Waiting, _ = strconv.Atoi(m[3])
	}
	return s, nil
}

// NginxReachable returns true if stub_status responds with 200.
func NginxReachable(client *http.Client) bool {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Get(NginxStatusURL())
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
