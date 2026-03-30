//go:build !linux

package monitor

import "flux-waf/internal/models"

func collectNginxProcessEntries() ([]models.NginxProcessEntry, int, int, int, int) {
	return nil, 0, 0, 0, 0
}

