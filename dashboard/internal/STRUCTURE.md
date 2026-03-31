# Internal Package Structure

This directory is organized by domain to keep handlers and logic maintainable for open-source collaboration.

## Handlers (`internal/handlers`)

- `api.go`: shared lightweight endpoints (`me`, `stats`, traffic stub) and tiny helpers.
- `api_waf.go`: core WAF settings and simple WAF-related APIs.
- `api_hosts_ssl.go`: host CRUD + SSL upload/list APIs.
- `api_threatintel.go`: threat-intel config, feeds, status, sync.
- `api_logs.go`: security/access/event log APIs.
- `api_reports.go`: attack report APIs + download helpers.
- `api_system.go`: system/monitoring endpoints (nginx status, server health, malware stubs).
- `engines_bot.go`: advanced bot engine APIs.
- `engines_ja3.go`: JA3/JA4 engine APIs.
- `engines_vpatch_dlp.go`: virtual patching + DLP engine APIs.
- `engines_wp_iprep.go`: WordPress security + IP reputation APIs.
- `routes.go`: HTTP route registration only.
- `pages.go`: SSR page handlers only.

## Logs (`internal/logs`)

- `analytics.go`: dashboard analytics main flow (aggregation + timeseries).
- `analytics_helpers.go`: analytics helper functions (sorting, parsing, normalization).
- `accessjson.go`, `errorlog.go`, `readrecent.go`: source-specific log readers.

## Conventions

- Keep files grouped by single domain concern.
- Avoid new monolithic files; add new API by placing function in the nearest domain file.
- Keep route definitions centralized in `routes.go`.
- Keep behavior changes separate from structure-only refactors where possible.
