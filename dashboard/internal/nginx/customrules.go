package nginx

import (
	"os"
)

// UserRulesPath is included from coraza.conf (volume: config/coraza/custom).
const UserRulesPath = "/etc/nginx/coraza/custom/flux_user_rules.conf"

// ReadUserRules returns file contents or empty if missing.
func ReadUserRules() (string, error) {
	b, err := os.ReadFile(UserRulesPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// WriteUserRules overwrites custom Coraza rules and should be followed by ReloadNginx.
func WriteUserRules(content string) error {
	return os.WriteFile(UserRulesPath, []byte(content), 0o644)
}
