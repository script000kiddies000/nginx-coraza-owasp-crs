# Nginx + Coraza WAF + OWASP CRS v4 (Docker)

WAF stack berbasis **Nginx custom build** + **Coraza WAF** + **OWASP CRS v4** dalam satu container Docker, dengan dashboard Flux WAF.

## Highlights

- Coraza WAF + OWASP CRS v4
- JA3/JA4 TLS fingerprint filtering (`nginx-ssl-fingerprint`)
- GeoIP2 country blocking (`ngx_http_geoip2_module`)
- Auto-bootstrap GeoLite MMDB saat startup (fallback mirror)
- Threat intel IP blocking (Spamhaus / ET / AbuseIPDB)
- DLP rules + basic direct-block rules (SQLi, XSS, traversal, RCE)
- Custom error pages + `X-Request-ID` correlation
- Attack Map Globe 3D (renderer `globe.gl` + fallback canvas)

## Ports

- `8080` -> Nginx HTTP (`:80`)
- `8443` -> Nginx HTTPS (`:443`)
- `8081` -> Benchmark endpoint (`:81`, no WAF/backend)
- `9080` -> Flux WAF dashboard (`:8080`)

## Quick Start

```bash
docker compose build
docker compose up -d
docker compose ps
```

Check logs:

```bash
docker compose logs -f waf
```

## Core Request Flow

1. Threat intel IP deny
2. GeoIP2 country block
3. JA3/JA4 filter (TLS only)
4. Coraza custom rules + CRS
5. Upstream proxy / static response

## GeoIP MMDB Auto-Download

Saat startup, container akan memastikan file ini tersedia:

- `/etc/nginx/geoip/GeoLite2-Country.mmdb` (mandatory)
- `/etc/nginx/geoip/GeoLite2-City.mmdb` (optional)
- `/etc/nginx/geoip/GeoLite2-ASN.mmdb` (optional)

Source mirror:

- `https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb`
- Fallback `raw.githubusercontent.com`

Jika environment tanpa internet, sediakan manual file ini di host:

- `config/geoip/GeoLite2-Country.mmdb`

## Useful Commands

Validate Nginx config:

```bash
docker exec nginx-coroza-crs nginx -t
```

Reload Nginx:

```bash
docker exec nginx-coroza-crs nginx -s reload
```

Recreate setelah ubah mount/config:

```bash
docker compose up -d --build
```

## Smoke Tests

Normal request:

```bash
curl http://localhost:8080/
```

Simple SQLi test (expected `403`):

```bash
curl "http://localhost:8080/?id=1'+OR+1=1--"
```

HTTPS check:

```bash
curl -k -I https://localhost:8443/
```

Benchmark (raw Nginx):

```bash
ab -n 20000 -c 100 http://localhost:8081/bench
```

## Project Structure (Important Paths)

```text
config/nginx.conf                 # Global nginx config + modules
config/conf.d/default.conf        # Main vhost config
config/coraza/coraza.conf         # Coraza engine + CRS include
config/coraza/custom/             # custom rules (vpatch/basic/dlp)
config/geoip/                     # GeoIP files + block map
config/threat-intel/              # threat intel config + generated denies
s6/cont-init.d/01-setup.sh        # startup bootstrap (cert, mmdb, placeholders)
dashboard/                        # Flux WAF dashboard source
```

## Troubleshooting

### `MMDB_open(...GeoLite2-Country.mmdb) failed`

Penyebab: file MMDB mandatory belum ada.

Solusi:

```bash
docker compose down
docker compose up -d --build
docker compose logs -f waf
```

Jika tetap gagal, isi manual `config/geoip/GeoLite2-Country.mmdb`.

### WAF tidak memblokir

- Pastikan `SecRuleEngine On` di `config/coraza/coraza.conf`
- Cek rule load error: `docker compose logs -f waf`

### `duplicate rule id`

Pastikan `coraza_rules_file` tidak di-load ganda pada level `http {}` dan `server {}`.

## Notes

- Repo ini memakai **s6-overlay** sebagai init/process supervisor.
- Untuk production, ganti cert self-signed dengan cert valid (mis. Let's Encrypt).
- Lihat `CHANGELOG.md` untuk detail perubahan terbaru.
