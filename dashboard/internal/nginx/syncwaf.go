package nginx

import "flux-waf/internal/models"

// ApplyWAFConfig writes SecRuleEngine mode, CRS tune file, and reloads nginx.
func ApplyWAFConfig(w models.WAFSettings) error {
	if err := WriteWAFMode(w.Mode); err != nil {
		return err
	}
	if err := WriteCRSTune(w.ParanoiaLevel, w.AnomalyInbound); err != nil {
		return err
	}
	return ReloadNginx()
}
