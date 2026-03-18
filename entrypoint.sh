#!/bin/sh
# entrypoint.sh — dijalankan saat container start
#
set -e

# Generate self-signed cert untuk test HTTPS/JA3 (jika belum ada)
CERT_DIR="/etc/nginx/certs"
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
fi

# Pastikan coraza_audit.log ada dan writable oleh www-data
touch /var/log/nginx/coraza_audit.log
chown www-data:www-data /var/log/nginx/coraza_audit.log

# Pastikan CRS setup config tersedia (sering hilang saat CRS folder di-mount dari host)
CRS_SETUP="/etc/nginx/coraza/crs/crs-setup.conf"
CRS_SETUP_EXAMPLE="/etc/nginx/coraza/crs/crs-setup.conf.example"
if [ ! -s "$CRS_SETUP" ] && [ -s "$CRS_SETUP_EXAMPLE" ]; then
  cp "$CRS_SETUP_EXAMPLE" "$CRS_SETUP"
fi

# Pastikan ip_rules.conf ada agar nginx tidak gagal saat include (file boleh kosong)
IP_RULES="/etc/nginx/threat-intel/ip_rules.conf"
if [ ! -f "$IP_RULES" ]; then
    mkdir -p "$(dirname "$IP_RULES")"
    printf '# Threat Intel IP Rules\n# Run: python3 scripts/sync_threat_intel.py\n' > "$IP_RULES"
fi

# Test konfigurasi nginx sebelum start
nginx -t

exec nginx -g "daemon off;"
