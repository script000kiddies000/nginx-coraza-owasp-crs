R# Changelog

All notable changes to this project will be documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
This project does not currently enforce Semantic Versioning.

## Unreleased

### Added
- JA3 allow/deny using `nginx-ssl-fingerprint` variables + Nginx `map`/`include` snippets.
- HTTPS test mode with self-signed certificate auto-generation on container start.
- Debug header `X-Wafx-JA3` on TLS vhost for JA3 visibility (intended for non-production use).
- Benchmark endpoint `GET /bench` on dedicated port (no WAF, no backend) for raw Nginx throughput tests.
- WordPress reverse-proxy hardening snippet + rate-limit zone for `/wp-login.php`.
- Virtual patching support via `config/coraza/custom/vpatch.rules` included from `config/coraza/coraza.conf`.
- Security headers on TLS vhost (HSTS and common browser hardening headers).
- Static assets bypass (disable Coraza) for common asset paths/extensions to reduce overhead and prevent upstream timeouts on multi-asset pages.

### Changed
- Upstream proxy configured with keepalive + `proxy_http_version 1.1` + `Connection ""`.
- Increased `worker_connections` for higher concurrency.
- README updated with ports/endpoints, build specifications, benchmark notes, deploy section, and troubleshooting for `unknown severity: HIGH`.
- Added root `.gitignore` to ignore `.cursor/`, `blueprint*`, `logs/`, and `extract_wafx_nginx/`.

### Fixed
- Avoided Coraza parse failures by using supported severities (e.g. mapping `HIGH` labeling into `msg`/`tag` while using `severity:'CRITICAL'`).
- Ensured `crs-setup.conf` is present by copying from `crs-setup.conf.example` at container start when missing.

