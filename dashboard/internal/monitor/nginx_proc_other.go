//go:build !linux

package monitor

func collectNginxProcessCounts() (master, worker, cache, other int) {
	// Best-effort only; on non-linux we don't have /proc.
	return 0, 0, 0, 0
}

