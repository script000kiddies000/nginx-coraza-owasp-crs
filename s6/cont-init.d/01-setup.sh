#!/bin/sh
# 01-setup.sh — dijalankan oleh s6-overlay sebelum service start
# Menggantikan logika lama di entrypoint.sh
set -e

# ── Self-signed TLS cert (untuk test HTTPS/JA3) ──────────────────────────────
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
# Directory dibuat di Dockerfile, di sini hanya pastikan ada (ro mount dari host)
mkdir -p /etc/nginx/ssl_certs 2>/dev/null || true

echo "[s6-init] Setup complete."
