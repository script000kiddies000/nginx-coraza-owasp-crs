#!/bin/sh
# 02-nginx-test.sh — validasi konfigurasi Nginx sebelum service start
set -e
echo "[s6-init] Testing Nginx configuration..."
nginx -t
echo "[s6-init] Nginx config OK."
