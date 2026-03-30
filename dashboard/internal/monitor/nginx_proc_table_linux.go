//go:build linux

package monitor

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"flux-waf/internal/models"
)

type cpuPrevSample struct {
	jiffies uint64
	ts      time.Time
}

var (
	cpuPrevMu sync.Mutex
	cpuPrevByPID = map[int]cpuPrevSample{}
)

var reNginxProc = regexp.MustCompile(`nginx:\s*(master process|worker process|cache manager process)`)

func nginxRoleFromCmdline(cmdline string) string {
	if strings.Contains(cmdline, "nginx: master process") {
		return "master"
	}
	if strings.Contains(cmdline, "nginx: worker process") {
		return "worker"
	}
	if strings.Contains(cmdline, "nginx: cache manager process") {
		return "cache"
	}
	return "other"
}

func readCmdline(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty cmdline")
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	return s, nil
}

func parseProcStatJiffies(pid int) (uint64, error) {
	// /proc/<pid>/stat format: we need utime (14) + stime (15) fields.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close <= open {
		return 0, fmt.Errorf("unexpected stat format")
	}
	after := strings.TrimSpace(s[close+1:])
	fields := strings.Fields(after)
	// afterFields[0] = state -> overall field 3
	utimeIdx := 14 - 3
	stimeIdx := 15 - 3
	if len(fields) <= stimeIdx {
		return 0, fmt.Errorf("stat too short")
	}
	ut, err := strconv.ParseUint(fields[utimeIdx], 10, 64)
	if err != nil {
		return 0, err
	}
	st, err := strconv.ParseUint(fields[stimeIdx], 10, 64)
	if err != nil {
		return 0, err
	}
	return ut + st, nil
}

func parseProcRSSKB(pid int) (int, error) {
	// /proc/<pid>/statm: size resident shared ...
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0, fmt.Errorf("statm too short")
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	pageSize := uint64(os.Getpagesize())
	rssBytes := residentPages * pageSize
	return int(rssBytes / 1024), nil
}

func collectNginxProcessEntries() ([]models.NginxProcessEntry, int, int, int, int) {
	entries := make([]models.NginxProcessEntry, 0, 4)

	// Clock ticks per second (USER_HZ). Using a safe default avoids CGO/sysconf issues.
	// This is an approximation; good enough for a lightweight dashboard.
	const hz = 100.0

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return entries, 0, 0, 0, 0
	}

	var master, worker, cache, other int
	now := time.Now()

	for _, ent := range procEntries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}

		cmdline, err := readCmdline(pid)
		if err != nil || cmdline == "" {
			continue
		}
		if !strings.Contains(cmdline, "nginx:") {
			continue
		}
		if !reNginxProc.MatchString(cmdline) && !strings.Contains(cmdline, "nginx: ") {
			continue
		}

		role := nginxRoleFromCmdline(cmdline)

		// CPU% (best-effort) with server-side previous sampling.
		jiffies, err := parseProcStatJiffies(pid)
		if err != nil {
			// still show RSS/command even if CPU fails
			jiffies = 0
		}
		rssKB, _ := parseProcRSSKB(pid)

		var cpuPct float64
		cpuPrevMu.Lock()
		prev, ok := cpuPrevByPID[pid]
		cpuPrevByPID[pid] = cpuPrevSample{jiffies: jiffies, ts: now}
		cpuPrevMu.Unlock()

		if ok && prev.ts.Before(now) && prev.jiffies > 0 && jiffies >= prev.jiffies {
			deltaJ := jiffies - prev.jiffies
			deltaT := now.Sub(prev.ts).Seconds()
			if deltaT > 0 {
				// percent = process seconds / wall seconds * 100
				procSeconds := float64(deltaJ) / hz
				cpuPct = (procSeconds / deltaT) * 100.0
			}
		}

		e := models.NginxProcessEntry{
			PID:         pid,
			Role:        role,
			CPUPercent:  cpuPct,
			RSSKB:       rssKB,
			Command:     cmdline,
		}
		entries = append(entries, e)

		switch role {
		case "master":
			master++
		case "worker":
			worker++
		case "cache":
			cache++
		default:
			other++
		}
	}

	return entries, master, worker, cache, other
}

