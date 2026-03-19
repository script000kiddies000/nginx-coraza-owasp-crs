#!/bin/bash
# ==============================================================================
# download-geolite2.sh — Download MaxMind GeoLite2-Country database
#
# Jalankan dari host (bukan dalam container):
#   bash config/geoip/download-geolite2.sh <LICENSE_KEY>
#
# Cara dapat license key (gratis):
#   1. Daftar akun di https://www.maxmind.com/en/geolite2/signup
#   2. Login → Account → Manage License Keys → Generate new key
#   3. Copy key-nya, paste sebagai argumen script ini
#
# Output: config/geoip/GeoLite2-Country.mmdb
# ==============================================================================

set -e

LICENSE_KEY="${1:-}"
DEST_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST_FILE="$DEST_DIR/GeoLite2-Country.mmdb"
TMP_DIR="$(mktemp -d)"

if [ -z "$LICENSE_KEY" ]; then
  echo "Usage: bash $0 <MAXMIND_LICENSE_KEY>"
  echo ""
  echo "Cara dapat license key gratis:"
  echo "  1. Daftar di https://www.maxmind.com/en/geolite2/signup"
  echo "  2. Login -> Account -> Manage License Keys -> Generate new key"
  exit 1
fi

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"

echo "[*] Downloading GeoLite2-Country.mmdb ..."
curl -fsSL "$URL" -o "$TMP_DIR/geolite2.tar.gz"

echo "[*] Extracting ..."
tar -xzf "$TMP_DIR/geolite2.tar.gz" -C "$TMP_DIR"

MMDB_FILE="$(find "$TMP_DIR" -name "GeoLite2-Country.mmdb" | head -1)"
if [ -z "$MMDB_FILE" ]; then
  echo "[!] GeoLite2-Country.mmdb not found in archive."
  rm -rf "$TMP_DIR"
  exit 1
fi

cp "$MMDB_FILE" "$DEST_FILE"
rm -rf "$TMP_DIR"

echo "[✓] Saved to: $DEST_FILE"
echo "[*] Run: docker compose up -d --build  (first time, needs rebuild)"
echo "    or:  docker exec nginx-coroza-crs nginx -s reload  (if already running)"
