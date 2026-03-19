# Nginx + Coraza WAF + OWASP CRS v4 — Docker

Web Application Firewall (WAF) berbasis **Nginx (custom build)** + **Coraza WAF** + **OWASP CRS v4**, dikemas dalam Docker.

Fitur tambahan di repo ini:
- **JA3/JA4 TLS fingerprint allow/deny** (via `nginx-ssl-fingerprint`)
- **GeoIP2 country blocking** (MaxMind GeoLite2, `ngx_http_geoip2_module`)
- **Threat Intel IP blocking** (Spamhaus DROP/EDROP, Emerging Threats, AbuseIPDB)
- **DLP rules** — block credit card, AWS key, PEM private key, SSN, API token
- **Basic WAF rules** — SQLi, XSS, Path Traversal, RCE (direct-block sebelum CRS)
- **vPatch rules** (virtual patching CVE) via Coraza `Include`
- **Custom error pages** (400/401/403/404/429/500/502) dengan branding + Request ID
- **Request ID** di log, header `X-Request-ID`, dan error page (traceable)
- **WordPress reverse-proxy hardening snippet**
- **HTTPS test mode** (self-signed cert auto-generated saat container start)
- **Benchmark endpoint** tanpa WAF/backend (`/bench`)

## Arsitektur

```
CLIENT REQUEST (HTTP / HTTPS)
       │
       ▼
┌──────────────────────────────────────────────┐
│           NGINX 1.27.4 (custom build)        │
│                                              │
│  [Layer 1] Network — Threat Intel IP Block   │
│  └── ip_rules.conf (Spamhaus DROP/EDROP,     │
│      Emerging Threats, AbuseIPDB)            │
│      → deny (TCP close, no response)         │
│                                              │
│  [Layer 2] GeoIP2 Country Block              │
│  └── ngx_http_geoip2_module + GeoLite2       │
│      $geoip2_blocked_country → 403           │
│                                              │
│  [Layer 3] TLS Fingerprint (HTTPS only)      │
│  └── JA3/JA4 via nginx-ssl-fingerprint       │
│      map $http_ssl_ja3_hash → 403            │
│                                              │
│  [Layer 4] Coraza WAF                        │
│  ├── Phase 1: Headers                        │
│  │   ├── WordPress hardening snippet         │
│  │   ├── vPatch rules (CVE custom)           │
│  │   └── DLP: AWS Key, PEM Private Key       │
│  ├── Phase 2: Request Body                   │
│  │   ├── Basic rules (SQLi/XSS/LFI/RCE)     │
│  │   ├── DLP (Credit Card, SSN, API token)   │
│  │   └── OWASP CRS v4 (Anomaly Score ≥5→403)│
│  └── Phase 3: Proxy to upstream              │
│      proxy_set_header X-Request-ID           │
│      (keepalive upstream enabled)            │
│                                              │
│  [Layer 5] Custom Error Pages                │
│  └── 400/401/403/404/429/500/502             │
│      sub_filter → inject $request_id        │
│                                              │
│  [Audit] Coraza Audit Log (JSON)             │
│  └── /var/log/nginx/coraza_audit.log         │
│      access.log → includes $request_id      │
└──────────────────────────────────────────────┘
       │
       ▼
 UPSTREAM / BACKEND (app/server lain)
 Header: X-Request-ID diteruskan ke backend

 BENCHMARK (no WAF, no backend):
   http://localhost:8081/bench → 200 "OK\n"
```

## Build Specifications

Build ini melakukan kompilasi Nginx dari source untuk menggabungkan:
- **Coraza WAF** (via `coraza-nginx` dynamic module + `libcoraza.so`)
- **JA3/JA4 TLS fingerprint** (via `nginx-ssl-fingerprint`, patch OpenSSL + Nginx)

Versi/komponen utama (lihat `Dockerfile`):
- **Base builder**: `golang:1.25-bookworm`
- **Nginx**: `1.27.4` (source build)
- **OpenSSL**: `3.4.0` (source tarball, di-patch untuk fingerprinting)
- **Runtime base**: `debian:bookworm-slim`
- **OWASP CRS**: di-clone saat build (mount juga tersedia via `config/coraza/crs`)

## Port & Endpoint

- **HTTP reverse proxy**: `http://localhost:8080/` → container `:80`
- **HTTPS reverse proxy**: `https://localhost:8443/` → container `:443` (self-signed)
- **Benchmark murni Nginx**: `http://localhost:8081/bench` → container `:81` (tanpa WAF/backend)

## Static assets (bypass WAF)

Untuk menghindari overhead WAF pada file statik (CSS/JS/icon/font) dan mencegah timeout saat browser
melakukan banyak request paralel, `default.conf` menambahkan `location` yang mematikan Coraza untuk:

- Path khusus: `/flasgger_static/`
- Ekstensi umum: `css, js, map, png, jpg, gif, svg, ico, woff/woff2, ttf, eot`

Jika kamu punya banyak vhost, sebaiknya jadikan ini template dan sesuaikan path static per-aplikasi.

## Response inspection (JSON vs non-JSON)

Coraza diset dengan `SecResponseBodyAccess On` dan limit global 512 KB, tetapi ada rule
custom yang **mematikan inspeksi response body untuk semua respons dengan
`Content-Type: application/json`**. Tujuannya:

- Mengurangi overhead WAF untuk API JSON besar
- Tetap mempertahankan inspeksi response untuk konten lain (HTML, dll)

Request-side WAF (phase 1/2) tetap aktif untuk semua request.

## Cara Build & Jalankan

```powershell
# 1. Masuk ke direktori project
cd "nginx-coroza-crs-docker"

# 2. Build image (membutuhkan internet — clone libcoraza, coraza-nginx, OWASP CRS, nginx-ssl-fingerprint)
#    Build time: ~10-20 menit (kompilasi nginx dari source + build libcoraza)
docker compose build

# 3. Jalankan container
docker compose up -d

# 4. Verifikasi container running
docker ps
```

## Test WAF

### Request Normal (harus 200 OK)
```bash
curl http://localhost:8080/
```

### SQL Injection (harus 403 Forbidden)
```bash
curl "http://localhost:8080/?id=1'+OR+1=1--"
# Output: 403 Forbidden
```

### XSS Attack (harus 403 Forbidden)
```bash
curl "http://localhost:8080/?q=<script>alert(1)</script>"
# Output: 403 Forbidden
```

### Path Traversal (harus 403 Forbidden)
```bash
curl "http://localhost:8080/?file=../../etc/passwd"
# Output: 403 Forbidden
```

### Remote Command Execution (harus 403 Forbidden)
```bash
curl "http://localhost:8080/?cmd=;cat+/etc/passwd"
# Output: 403 Forbidden
```

## Test HTTPS + JA3

> JA3 hanya tersedia di TLS. Pastikan test ke port **8443**.

```bash
curl -k -I https://localhost:8443/
```

Untuk debugging (sementara), server TLS menambahkan header `X-Wafx-JA3`.

Script test:

```bash
python3 scripts/test_ja3.py --insecure https://localhost:8443/
```

## Benchmark

- Tanpa WAF/backend:

```bash
ab -n 20000 -c 100 http://localhost:8081/bench
```

- Dengan WAF+backend (contoh SQLi diblok):

```bash
ab -n 20000 -c 100 "http://localhost:8080/?id=1'%20OR%20'1'='1"
```

## Melihat Log

### Access + Error log (stdout/stderr Docker)
```bash
docker logs nginx-coraza-crs
docker logs -f nginx-coraza-crs
```

### Coraza Audit Log (JSON — hanya request yang diblokir)
```bash
docker exec nginx-coraza-crs tail -f /var/log/nginx/coraza_audit.log
```

## Struktur File

```
nginx-coroza-crs-docker/
├── Dockerfile                    # 3-stage build: libcoraza → nginx (+ geoip2) → production
├── docker-compose.yml            # Port 8080:80, 8443:443, 8081:81 + volume mounts
├── entrypoint.sh                 # Self-signed cert, crs-setup.conf, ip_rules fallback
├── logs/                         # Nginx access/error + Coraza audit log (host mount)
├── scripts/
│   ├── test_ja3.py               # Uji JA3 fingerprint via HTTPS
│   └── sync_threat_intel.py      # Sync IP blocklist dari Spamhaus/ET/AbuseIPDB
└── config/
    ├── nginx.conf                # load_module geoip2 + coraza, log_format (request_id)
    ├── conf.d/
    │   └── default.conf          # Virtual host: GeoIP → JA3 → WAF → proxy
    ├── snippets/
    │   ├── wafx-ja3-map.conf     # JA3 hash blocklist (map)
    │   ├── wafx-ja3-enforce.conf # JA3 enforcement (if → 403)
    │   ├── wafx-wordpress-security.conf
    │   └── static-assets-bypass.conf
    ├── errors/                   # Custom error pages (400/401/403/404/429/500/502)
    │   ├── error.css
    │   ├── 403.html  429.html  502.html  ...
    ├── geoip/
    │   ├── download-geolite2.sh          # Download GeoLite2-Country.mmdb (butuh lisensi)
    │   ├── geoip-blocked-countries.conf  # Map ISO code → $geoip2_blocked_country
    │   └── GeoLite2-Country.mmdb         # ← tidak di-commit, download manual
    ├── threat-intel/
    │   ├── threat_intel.json     # Konfigurasi feed (Spamhaus, ET, AbuseIPDB)
    │   └── ip_rules.conf         # Output deny rules (di-generate oleh sync script)
    └── coraza/
        ├── coraza.conf           # Coraza engine settings + OWASP CRS loader
        ├── crs/                  # OWASP CRS v4 (mounted)
        └── custom/
            ├── vpatch.rules      # Virtual patch rules (CVE)
            ├── basic-rules.conf  # SQLi, XSS, Path Traversal, RCE direct-block
            ├── dlp-rules.conf    # DLP: Credit Card, SSN, AWS Key, PEM, API token
            └── response-json-skip.conf
```

> **CRS Rules** (`/etc/nginx/coraza/crs/`) di-clone langsung ke dalam Docker image
> saat build, tidak perlu
> ada di repo lokal.

## Kustomisasi

### Ganti ke mode DetectionOnly (log tanpa blokir)
Edit `config/coraza/coraza.conf`:
```
SecRuleEngine DetectionOnly
```
Lalu reload: `docker exec nginx-coraza-crs nginx -s reload`

### Tambah backend / proxy_pass
Edit `config/conf.d/default.conf`, uncomment bagian proxy_pass:
```nginx
location / {
    proxy_pass http://your-backend:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Tambah virtual host baru
Buat file baru di `config/conf.d/mysite.conf`:
```nginx
server {
    listen 80;
    server_name mysite.example.com;

    coraza on;
    coraza_rules_file /etc/nginx/coraza/coraza.conf;

    location / {
        proxy_pass http://mysite-backend:8000;
    }
}
```

### Tuning Paranoia Level (lebih strict)
Edit `config/coraza/coraza.conf` — tambahkan sebelum `Include crs-setup.conf`:
```nginx
SecAction \
    "id:900000,phase:1,pass,t:none,nolog,\
    setvar:tx.paranoia_level=2,\
    setvar:tx.blocking_paranoia_level=2"
```

## Deploy (VPS) singkat

Rekomendasi minimum:
- Pastikan DNS domain mengarah ke IP VPS.
- Buka port 80/443 di firewall.
- Ganti self-signed cert dengan cert valid (Let's Encrypt) dan set `ssl_certificate`/`ssl_certificate_key` di vhost.

Contoh alur:

```bash
git clone <repo-ini>
cd nginx-coroza-crs-docker
docker compose up -d --build
docker logs -f nginx-coraza-crs
```

Update config tanpa rebuild image:

```bash
docker compose up -d
docker exec nginx-coraza-crs nginx -t
docker exec nginx-coraza-crs nginx -s reload
```

## Troubleshooting

### Build gagal: "SSL library does not support QUIC"
Pastikan `--with-http_v3_module` **tidak ada** di Dockerfile configure flags.
HTTP/3 butuh OpenSSL 3.2+ — Debian Bookworm hanya punya OpenSSL 3.0.x.

### Error: "duplicate rule id"
Pastikan `coraza_rules_file` hanya ada di **server block** (`conf.d/default.conf`),
**tidak** di http block (`nginx.conf`). Double-load menyebabkan conflict rule ID.

### Error Coraza: `unknown severity: HIGH`
Engine Coraza yang digunakan di Docker ini **hanya menerima severity resmi**
(`EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG` atau angka).
Rule vPatch bawaan WafX menggunakan `severity:'HIGH'` yang valid di engine
mereka, tetapi **tidak dikenal** oleh Coraza di sini. Solusi:

- Ganti `severity:'HIGH'` menjadi `severity:'CRITICAL'` (atau level resmi lain), dan
  simpan label `HIGH` di `msg`/`tag`. Contoh:

```nginx
SecRule ... "...,msg:'[HIGH] ...',tag:'...,SEVERITY_HIGH',severity:'CRITICAL'"
```

### Container start tapi WAF tidak memblokir
Cek `SecRuleEngine` di `config/coraza/coraza.conf` — pastikan nilainya `On`
(bukan `DetectionOnly` atau `Off`).

### Lihat nginx config test result
```bash
docker exec nginx-coraza-crs nginx -t
```

---

## Catatan Bug yang Diselesaikan

| # | Error | Penyebab | Fix |
|---|-------|----------|-----|
| 1 | `libtoolize: not found`, `autoreconf: not found` | `build-essential` tidak include autotools | Tambah `libtool autoconf automake` di apt Stage 1 Dockerfile |
| 2 | `invalid go version '1.25.0': must match format 1.23` | Debian Bookworm apt hanya punya Go 1.19.8, sedangkan `libcoraza` butuh Go 1.25+ | Ganti base image Stage 1 & 2 dari `debian:bookworm-slim` ke `golang:1.25-bookworm` |
| 3 | `invalid audit engine status:        RelevantOnly` | Extra whitespace di `SecAuditEngine        RelevantOnly` pada `coraza.conf` — Coraza parser membaca nilai sebagai `"       RelevantOnly"` | Hapus extra spaces: `SecAuditEngine RelevantOnly` |
| 4 | `open /etc/nginx/coraza/crs/rules/REQUEST-900-...: no such file or directory` | CRS v4 menyertakan file exclusion sebagai `.conf.example`, bukan `.conf` — harus di-copy manual | `cp REQUEST-900-...conf.example REQUEST-900-...conf` dan `cp RESPONSE-999-...conf.example RESPONSE-999-...conf` |
| 5 | Volume mount baru tidak diterapkan setelah edit `docker-compose.yml` | `docker compose restart` hanya restart process, tidak recreate container | Gunakan `docker compose up -d` untuk menerapkan perubahan volume |
| 6 | WAF jalan tapi tidak memblokir serangan (SQLi/XSS/LFI semua 200 OK) | `return 200 "..."` di nginx location block berjalan di **Rewrite Phase**, sebelum Coraza **Access Phase (Phase 2)**. Semua CRS rules adalah `phase:2` sehingga tidak pernah dieksekusi | Ganti `return 200` dengan `try_files` (static) atau `proxy_pass` (backend) agar request melewati full nginx pipeline termasuk Phase 2 |
