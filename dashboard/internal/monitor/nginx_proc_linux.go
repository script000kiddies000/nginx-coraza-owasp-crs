//go:build linux

package monitor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// collectNginxProcessCounts is best-effort: it inspects /proc/<pid>/cmdline
// and categorizes nginx processes by their cmdline suffix.
//
// For example:
//   nginx: master process
//   nginx: worker process
//   nginx: cache manager process
func collectNginxProcessCounts() (master, worker, cache, other int) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, 0, 0
	}

	for _, ent := range procEntries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}

		// cmdline is null-separated.
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(b) == 0 {
			continue
		}
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		if cmdline == "" || !strings.Contains(cmdline, "nginx:") {
			continue
		}

		switch {
		case strings.Contains(cmdline, "nginx: master process"):
			master++
		case strings.Contains(cmdline, "nginx: worker process"):
			worker++
		case strings.Contains(cmdline, "nginx: cache manager process"):
			cache++
		case strings.Contains(cmdline, "nginx:"):
			other++
		}
	}
	return master, worker, cache, other
}

