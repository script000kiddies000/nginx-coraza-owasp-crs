//go:build !linux

package monitor

func collectNginxConfiguration() map[string]string {
	return map[string]string{
		"error_log":          "—",
		"pid":                 "—",
		"user":                "—",
		"worker_processes":   "—",
		"worker_cpu_affinity": "—",
		"worker_connections": "—",
	}
}

func collectNginxModules() []string {
	return []string{"stub_status"}
}

