//go:build linux

package monitor

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
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
		CPUCores:      runtime.NumCPU(),
	}
	h.Hostname = readHostname()
	h.OSName = readOSName()
	h.KernelVersion = readKernelVersion()
	h.PrimaryIP = readPrimaryIPv4()

	if u, err := readUptimeSeconds(); err == nil {
		h.UptimeSeconds = u
	}
	if total, avail, swapTotal, swapFree, err := readMeminfo(); err == nil && total > 0 {
		h.MemoryTotalGB = float64(total) / (1024 * 1024 * 1024)
		used := total - avail
		if used < 0 {
			used = 0
		}
		h.MemoryUsedGB = float64(used) / (1024 * 1024 * 1024)
		if swapTotal > 0 {
			h.SwapTotalGB = float64(swapTotal) / (1024 * 1024 * 1024)
			swapUsed := swapTotal - swapFree
			if swapUsed < 0 {
				swapUsed = 0
			}
			h.SwapUsedGB = float64(swapUsed) / (1024 * 1024 * 1024)
		}
	}
	if pct, err := cpuUsagePercent(180 * time.Millisecond); err == nil {
		h.CPUUsagePercent = pct
	}
	if total, used, err := diskUsageRoot(); err == nil && total > 0 {
		h.DiskTotalGB = float64(total) / (1024 * 1024 * 1024)
		h.DiskUsedGB = float64(used) / (1024 * 1024 * 1024)
	}
	if rx, tx, err := readNetBytes(); err == nil {
		h.NetworkRxBytes = rx
		h.NetworkTxBytes = tx
	}
	if rd, wr, err := readDiskIOBytes(); err == nil {
		h.DiskReadBytes = rd
		h.DiskWriteBytes = wr
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

// readMeminfo returns memory and swap counters (kB).
func readMeminfo() (totalKb, availKb, swapTotalKb, swapFreeKb uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer f.Close()

	var memTotal, memAvail, memFree, swapTotal, swapFree uint64
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
		case strings.HasPrefix(line, "SwapTotal:"):
			_, _ = fmt.Sscanf(line, "SwapTotal: %d kB", &swapTotal)
		case strings.HasPrefix(line, "SwapFree:"):
			_, _ = fmt.Sscanf(line, "SwapFree: %d kB", &swapFree)
		}
	}
	if memTotal == 0 {
		return 0, 0, 0, 0, fmt.Errorf("meminfo: no MemTotal")
	}
	if hasAvail {
		return memTotal, memAvail, swapTotal, swapFree, nil
	}
	return memTotal, memFree, swapTotal, swapFree, nil
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

func readHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(h)
}

func readOSName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readPrimaryIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 != nil && !v4.IsLoopback() {
				return v4.String()
			}
		}
	}
	return ""
}

func readNetBytes() (uint64, uint64, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var rx, tx uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rxv, _ := strconv.ParseUint(fields[0], 10, 64)
		txv, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += rxv
		tx += txv
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return rx, tx, nil
}

func readDiskIOBytes() (uint64, uint64, error) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var readBytes, writeBytes uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		sectorsRead, errR := strconv.ParseUint(fields[5], 10, 64)
		sectorsWritten, errW := strconv.ParseUint(fields[9], 10, 64)
		if errR != nil || errW != nil {
			continue
		}
		readBytes += sectorsRead * 512
		writeBytes += sectorsWritten * 512
	}
	if err := sc.Err(); err != nil {
		return 0, 0, err
	}
	return readBytes, writeBytes, nil
}
