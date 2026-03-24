#!/bin/sh
# 01-setup.sh — dijalankan oleh s6-overlay sebelum service start
# Menggantikan logika lama di entrypoint.sh
set -e

# ── Self-signed TLS cert (untuk test HTTPS/JA3) ──────────────────────────────
CERT_DIR="/etc/nginx/ssl_certs"
CERT_CRT="${CERT_DIR}/localhost.crt"
CERT_KEY="${CERT_DIR}/localhost.key"
if [ ! -s "$CERT_CRT" ] || [ ! -s "$CERT_KEY" ]; then
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -days 365 \
        -keyout "$CERT_KEY" \
        -out "$CERT_CRT" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    chown www-data:www-data "$CERT_CRT" "$CERT_KEY" || true
    chmod 600 "$CERT_KEY" || true
    echo "[s6-init] Self-signed cert generated."
fi

# ── Coraza audit log ──────────────────────────────────────────────────────────
touch /var/log/nginx/coraza_audit.log
chown www-data:www-data /var/log/nginx/coraza_audit.log

# ── CRS crs-setup.conf ────────────────────────────────────────────────────────
CRS_SETUP="/etc/nginx/coraza/crs/crs-setup.conf"
CRS_EXAMPLE="/etc/nginx/coraza/crs/crs-setup.conf.example"
if [ ! -s "$CRS_SETUP" ] && [ -s "$CRS_EXAMPLE" ]; then
    cp "$CRS_EXAMPLE" "$CRS_SETUP"
    echo "[s6-init] crs-setup.conf copied from example."
fi

# ── Threat Intel ip_rules.conf ────────────────────────────────────────────────
IP_RULES="/etc/nginx/threat-intel/ip_rules.conf"
if [ ! -f "$IP_RULES" ]; then
    mkdir -p "$(dirname "$IP_RULES")"
    printf '# Threat Intel IP Rules\n# Run: python3 scripts/sync_threat_intel.py\n' > "$IP_RULES"
    echo "[s6-init] ip_rules.conf placeholder created."
fi

# ── Flux WAF data directory ───────────────────────────────────────────────────
mkdir -p /var/lib/flux-waf

# ── Flux WAF SSL certs directory ─────────────────────────────────────────────
mkdir -p /etc/nginx/ssl_certs 2>/dev/null || true
chown www-data:www-data /etc/nginx/ssl_certs 2>/dev/null || true

# ACME webroot (Let's Encrypt HTTP-01)
mkdir -p /var/www/certbot/.well-known/acme-challenge
chown -R www-data:www-data /var/www/certbot 2>/dev/null || true

# ── GeoIP2 MMDB bootstrap (auto-download fallback) ───────────────────────────
GEOIP_DIR="/etc/nginx/geoip"
COUNTRY_DB="${GEOIP_DIR}/GeoLite2-Country.mmdb"
CITY_DB="${GEOIP_DIR}/GeoLite2-City.mmdb"
ASN_DB="${GEOIP_DIR}/GeoLite2-ASN.mmdb"

mkdir -p "$GEOIP_DIR"

download_mmdb_if_missing() {
    dest_file="$1"
    name="$2"
    shift 2

    if [ -s "$dest_file" ]; then
        echo "[s6-init] ${name} already exists."
        return 0
    fi

    for url in "$@"; do
        [ -n "$url" ] || continue
        echo "[s6-init] Downloading ${name} from: $url"
        if curl -fsSL --retry 3 --connect-timeout 8 --max-time 90 "$url" -o "${dest_file}.tmp"; then
            if [ -s "${dest_file}.tmp" ]; then
                mv "${dest_file}.tmp" "$dest_file"
                chmod 644 "$dest_file" 2>/dev/null || true
                echo "[s6-init] ${name} downloaded."
                return 0
            fi
        fi
        rm -f "${dest_file}.tmp"
    done

    echo "[s6-init] WARN: ${name} is missing and download failed."
    return 1
}

download_mmdb_if_missing "$COUNTRY_DB" "GeoLite2-Country.mmdb" \
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" \
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"

# Optional DBs (currently not required by nginx.conf, but useful for future features).
download_mmdb_if_missing "$CITY_DB" "GeoLite2-City.mmdb" \
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb" \
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb" || true

download_mmdb_if_missing "$ASN_DB" "GeoLite2-ASN.mmdb" \
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb" \
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb" || true

# Country DB is mandatory by nginx.conf (geoip2 directive).
if [ ! -s "$COUNTRY_DB" ]; then
    echo "[s6-init] ERROR: GeoLite2-Country.mmdb not found."
    echo "[s6-init] Please check internet access or place file manually at: $COUNTRY_DB"
    exit 1
fi

echo "[s6-init] Setup complete."
