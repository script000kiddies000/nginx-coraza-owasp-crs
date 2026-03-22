package nginx

import (
	"fmt"
	"os"
)

// CRSTuneConfPath overrides CRS tx.* after crs-setup, before REQUEST-901 (mounted rw).
const CRSTuneConfPath = "/etc/nginx/coraza/custom/flux_crs_tune.conf"

// WriteCRSTune writes SecAction rules that set paranoia level and inbound anomaly threshold.
// Outbound threshold is left to crs-setup.conf defaults unless extended later.
func WriteCRSTune(paranoiaLevel, inboundAnomaly int) error {
	pl := paranoiaLevel
	if pl < 1 {
		pl = 1
	}
	if pl > 4 {
		pl = 4
	}
	in := inboundAnomaly
	if in < 1 {
		in = 5
	}
	if in > 999 {
		in = 999
	}
	content := fmt.Sprintf(`# Managed by Flux WAF Dashboard — do not edit manually
# Applied before REQUEST-901; overrides OWASP CRS defaults from crs-setup.conf
SecAction "id:9009100,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d"
SecAction "id:9009101,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=%d"
`, pl, pl, in)
	return os.WriteFile(CRSTuneConfPath, []byte(content), 0o644)
}
