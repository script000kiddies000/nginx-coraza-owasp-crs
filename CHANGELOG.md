# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
This project does not currently enforce Semantic Versioning.

## Unreleased

### Added
- **GeoIP2 Country Blocking** — `ngx_http_geoip2_module` (MaxMind GeoLite2) dikompilasi sebagai dynamic module. Block terjadi sebelum WAF via `if ($geoip2_blocked_country)`. Country list di `config/geoip/geoip-blocked-countries.conf`. Database `.mmdb` didownload dengan `config/geoip/download-geolite2.sh <LICENSE_KEY>` (butuh akun MaxMind gratis). Butuh rebuild image Docker.
- **Request ID / Correlation ID** — `$request_id` (built-in Nginx) di-inject ke: `access.log` via `log_format main`, response header `X-Request-ID`, `proxy_set_header X-Request-ID` ke backend, dan semua error page via `sub_filter '__REQUEST_ID__'`. ID yang tampil di halaman error sekarang identik dengan ID di log Nginx.
- **Custom Error Pages** — `config/errors/403.html`, `429.html`, `502.html` dengan Flux WAF branding (dark theme, SVG icon, shared `error.css`). Halaman 429 memiliki countdown 30s + auto-reload. Semua halaman generate Reference ID (hex) untuk tracing. Nginx menyertakan `X-Request-ID` header di response error.
- **`listen 443 ssl http2` → `http2 on`** — fix deprecation warning pada Nginx 1.25.1+.
- **Threat Intel IP Blocking** — `scripts/sync_threat_intel.py` fetches Spamhaus DROP/EDROP, Emerging Threats, dan AbuseIPDB (optional, butuh API key). Output ke `config/threat-intel/ip_rules.conf` (Nginx `deny` directives), di-include di `http {}` block. Block terjadi sebelum WAF/backend. Config via `config/threat-intel/threat_intel.json`.
- **Basic Custom WAF Rules** — `config/coraza/custom/basic-rules.conf`: direct-block rules untuk SQLi (UNION SELECT, EXEC), XSS (script tag, javascript URI), Path Traversal, dan RCE (shell expansion, backtick). Berjalan sebelum CRS scoring sebagai lapis pertama.
- **DLP / Data Guard Rules** — `config/coraza/custom/dlp-rules.conf`: block pengiriman data sensitif lewat request body. Pattern: Credit Card (Visa/MC/Amex/Discover), SSN, API Key/Bearer Token, AWS Access Key (`AKIA...`), PEM Private Key. Log-only (tidak block) untuk Password field dan JWT token karena rentan false-positive pada request auth yang legitimate.
- **`proxy_set_header Host $http_host`** — fix 400 Bad Request pada aplikasi yang melakukan CSRF validation dengan membandingkan `Host` vs `Origin` header (contoh: ezXSS). `$host` strips port, `$http_host` mempertahankan port.
- JA3 allow/deny using `nginx-ssl-fingerprint` variables + Nginx `map`/`include` snippets.
- HTTPS test mode with self-signed certificate auto-generation on container start.
- Debug header `X-Wafx-JA3` on TLS vhost for JA3 visibility (intended for non-production use).
- Benchmark endpoint `GET /bench` on dedicated port (no WAF, no backend) for raw Nginx throughput tests.
- WordPress reverse-proxy hardening snippet + rate-limit zone for `/wp-login.php`.
- Virtual patching support via `config/coraza/custom/vpatch.rules` included from `config/coraza/coraza.conf`.
- Security headers on TLS vhost (HSTS and common browser hardening headers).
- Static assets bypass (disable Coraza) for common asset paths/extensions to reduce overhead and prevent upstream timeouts on multi-asset pages.
- Custom Coraza rule to skip response body inspection for all `application/json` responses (keeps request-side WAF, reduces latency for large JSON APIs).

### Changed
- Upstream proxy configured with keepalive + `proxy_http_version 1.1` + `Connection ""`.
- Increased `worker_connections` for higher concurrency.
- README updated with ports/endpoints, build specifications, benchmark notes, deploy section, and troubleshooting for `unknown severity: HIGH`.
- Added root `.gitignore` to ignore `.cursor/`, `blueprint*`, `logs/`, and `extract_wafx_nginx/`.
- entrypoint no longer rewires `access.log` / `error.log` to stdout/stderr so that Nginx logs are written as regular files under `logs/`.

### Fixed
- Avoided Coraza parse failures by using supported severities (e.g. mapping `HIGH` labeling into `msg`/`tag` while using `severity:'CRITICAL'`).
- Ensured `crs-setup.conf` is present by copying from `crs-setup.conf.example` at container start when missing.

