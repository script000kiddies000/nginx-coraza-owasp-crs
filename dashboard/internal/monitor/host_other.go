//go:build !linux

package monitor

import (
	"os"
	"runtime"

	"flux-waf/internal/models"
)

// CollectServerHealthWithNginx on non-Linux only checks nginx stub_status reachability.
func CollectServerHealthWithNginx() models.ServerHealth {
	hostname, _ := os.Hostname()
	return models.ServerHealth{
		NginxDaemonUp: NginxReachable(nil),
		Hostname:      hostname,
		OSName:        runtime.GOOS,
		CPUCores:      runtime.NumCPU(),
	}
}
