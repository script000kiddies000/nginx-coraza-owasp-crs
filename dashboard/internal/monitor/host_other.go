//go:build !linux

package monitor

import "flux-waf/internal/models"

// CollectServerHealthWithNginx on non-Linux only checks nginx stub_status reachability.
func CollectServerHealthWithNginx() models.ServerHealth {
	return models.ServerHealth{
		NginxDaemonUp: NginxReachable(nil),
	}
}
