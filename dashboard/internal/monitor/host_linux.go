//go:build linux

package monitor

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"flux-waf/internal/models"
)

// CollectServerHealthWithNginx fills ServerHealth from /proc and root filesystem.
func CollectServerHealthWithNginx() models.ServerHealth {
	h := models.ServerHealth{
		NginxDaemonUp: NginxReachable(nil),
	}

	if u, err := readUptimeSeconds(); err == nil {
		h.UptimeSeconds = u
	}
	if total, avail, err := readMeminfo(); err == nil && total > 0 {
		h.MemoryTotalGB = float64(total) / (1024 * 1024 * 1024)
		used := total - avail
		if used < 0 {
			used = 0
		}
		h.MemoryUsedGB = float64(used) / (1024 * 1024 * 1024)
	}
	if pct, err := cpuUsagePercent(180 * time.Millisecond); err == nil {
		h.CPUUsagePercent = pct
	}
	if total, used, err := diskUsageRoot(); err == nil && total > 0 {
		h.DiskTotalGB = float64(total) / (1024 * 1024 * 1024)
		h.DiskUsedGB = float64(used) / (1024 * 1024 * 1024)
	}
	return h
}

func readUptimeSeconds() (uint64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("uptime: empty")
	}
	sec, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return uint64(sec), nil
}

// readMeminfo returns MemTotal and MemAvailable (kB). Falls back to MemFree if MemAvailable missing.
func readMeminfo() (totalKb, availKb uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var memTotal, memAvail, memFree uint64
	var hasAvail bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			_, _ = fmt.Sscanf(line, "MemTotal: %d kB", &memTotal)
		case strings.HasPrefix(line, "MemAvailable:"):
			_, _ = fmt.Sscanf(line, "MemAvailable: %d kB", &memAvail)
			hasAvail = true
		case strings.HasPrefix(line, "MemFree:"):
			_, _ = fmt.Sscanf(line, "MemFree: %d kB", &memFree)
		}
	}
	if memTotal == 0 {
		return 0, 0, fmt.Errorf("meminfo: no MemTotal")
	}
	if hasAvail {
		return memTotal, memAvail, nil
	}
	return memTotal, memFree, nil
}

type cpuJiffies struct {
	idle, total uint64
}

func readCPUJiffies() (cpuJiffies, error) {
	var z cpuJiffies
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return z, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return z, fmt.Errorf("stat empty")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return z, fmt.Errorf("stat: no cpu line")
	}
	var nums []uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		nums = append(nums, v)
	}
	if len(nums) < 4 {
		return z, fmt.Errorf("stat: short cpu fields")
	}
	idle := nums[3]
	if len(nums) > 4 {
		idle += nums[4] // iowait
	}
	var total uint64
	for _, n := range nums {
		total += n
	}
	return cpuJiffies{idle: idle, total: total}, nil
}

func cpuUsagePercent(samplePause time.Duration) (float64, error) {
	a, err := readCPUJiffies()
	if err != nil {
		return 0, err
	}
	time.Sleep(samplePause)
	b, err := readCPUJiffies()
	if err != nil {
		return 0, err
	}
	idleDelta := float64(b.idle) - float64(a.idle)
	totalDelta := float64(b.total) - float64(a.total)
	if totalDelta <= 0 {
		return 0, nil
	}
	pct := 100 * (1 - idleDelta/totalDelta)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

func diskUsageRoot() (totalBytes, usedBytes uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize)
	total := st.Blocks * bs
	avail := st.Bavail * bs
	if total < avail {
		return 0, 0, fmt.Errorf("statfs: nonsense")
	}
	used := total - avail
	return total, used, nil
}
