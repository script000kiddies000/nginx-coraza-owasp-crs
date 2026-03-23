# ==============================================================================
# STAGE 1: Build libcoraza (Go → C shared library)
#
# libcoraza adalah wrapper C-callable di atas engine WAF Coraza (Go).
# Harus dibangun PERTAMA karena coraza-nginx module membutuhkan
# libcoraza.so + header C-nya saat kompilasi nginx.
# ==============================================================================
# golang:1.25-bookworm sudah bundled Go 1.25 — apt golang (1.19) terlalu lama
# libcoraza go.mod mensyaratkan go 1.25.0 minimum
FROM golang:1.25-bookworm AS builder-coraza

RUN apt-get update && apt-get install -y \
    build-essential git curl \
    libtool autoconf automake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build urutan resmi dari README coraza-nginx:
#   ./build.sh  → generate autotools (autoreconf)
#   ./configure → detect Go, set prefix=/usr/local
#   make        → go build -buildmode=c-shared → libcoraza.so
#   make install → copy ke /usr/local/lib + /usr/local/include
RUN git clone --depth 1 https://github.com/corazawaf/libcoraza.git && \
    cd libcoraza && \
    ./build.sh && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# ==============================================================================
# STAGE 2: Build Nginx 1.27.4 dari source
#
# Versions (sesuai phuslu support matrix: nginx-1.27 + openssl-3.4 ✅):
#   - Nginx 1.27.4
#   - OpenSSL 3.4 branch (clone dari GitHub — phuslu patch butuh source tree)
#   - nginx-ssl-fingerprint (phuslu) → JA3/JA4, STATIC, butuh patch manual
#   - coraza-nginx → WAF engine, DYNAMIC module
#
# PROSES PATCH (wajib sebelum build, sesuai README phuslu):
#   1. patch -p1 -d openssl-3.4 < nginx-ssl-fingerprint/patches/openssl.openssl-3.4.patch
#   2. patch -p1 -d nginx-1.27.4 < nginx-ssl-fingerprint/patches/nginx-1.27.patch
#
# Ref: https://github.com/phuslu/nginx-ssl-fingerprint
# ==============================================================================
FROM golang:1.25-bookworm AS builder-nginx

# TODO (aktifkan saat test masing-masing modul):
#   libgd-dev     → Image filter module
#   libxslt-dev   → XSLT filter module
#   libxml2-dev   → dependency xslt
RUN apt-get update && apt-get install -y \
    build-essential libpcre3-dev zlib1g-dev libssl-dev git wget patch \
    libmaxminddb-dev \
    && rm -rf /var/lib/apt/lists/*

# Ambil libcoraza.so + header dari stage 1
COPY --from=builder-coraza /usr/local/lib     /usr/local/lib
COPY --from=builder-coraza /usr/local/include /usr/local/include
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/libcoraza.conf && ldconfig

WORKDIR /build

# OpenSSL 3.4.0 — tarball dari openssl.org (bukan git clone branch!)
# phuslu last update Feb 2025, openssl-3.4.0 release Oct 2024 → versi yang digunakan saat patch dibuat
# git clone --depth=1 openssl-3.4 branch = HEAD terbaru (March 2026) → patch GAGAL karena code sudah berubah
RUN wget -q https://www.openssl.org/source/openssl-3.4.0.tar.gz && \
    tar xzf openssl-3.4.0.tar.gz && \
    mv openssl-3.4.0 openssl-3.4

# Nginx 1.27.4 — versi terbaru di 1.27.x, sesuai support matrix phuslu
RUN wget -q https://nginx.org/download/nginx-1.27.4.tar.gz && \
    tar xzf nginx-1.27.4.tar.gz

# nginx-ssl-fingerprint (phuslu): JA3/JA4 TLS fingerprint
# Wajib patch nginx + openssl source sebelum build
RUN git clone --depth=1 https://github.com/phuslu/nginx-ssl-fingerprint.git

# Patch 1: tambahkan ClientHello capture ke OpenSSL 3.4 source
RUN patch -p1 -d openssl-3.4 < nginx-ssl-fingerprint/patches/openssl.openssl-3.4.patch

# Patch 2: tambahkan fp_ja3_* fields ke ngx_ssl_connection_t di nginx 1.27
RUN patch -p1 -d nginx-1.27.4 < nginx-ssl-fingerprint/patches/nginx-1.27.patch

# ngx_http_geoip2_module: GeoIP2 MaxMind dynamic module
RUN git clone --depth 1 https://github.com/leev/ngx_http_geoip2_module.git

# coraza-nginx: nginx dynamic module yang menghubungkan nginx → libcoraza
RUN git clone --depth 1 https://github.com/corazawaf/coraza-nginx.git

# OWASP CRS v4 — latest main branch
RUN git clone --depth 1 \
    https://github.com/coreruleset/coreruleset.git /build/crs

WORKDIR /build/nginx-1.27.4

# Configure flags aktif:
#   --with-openssl=../openssl-3.4     → custom OpenSSL yang sudah di-patch phuslu
#   --with-http_ssl_module            → HTTPS
#   --with-http_v2_module             → HTTP/2
#   --with-http_realip_module         → real IP dari proxy/CDN
#   --with-http_sub_module            → response body substitution
#   --with-http_stub_status_module    → /nginx_status endpoint (dibaca Go dashboard)
#   --add-module=../nginx-ssl-fingerprint   → JA3/JA4 STATIC (nginx sudah di-patch)
#   --add-dynamic-module=../coraza-nginx    → Coraza WAF DYNAMIC module
#
# TODO — aktifkan satu per satu setelah build dasar sukses:
#   --with-http_v3_module                   → HTTP/3 QUIC (OpenSSL 3.4 sudah support)
#   --with-http_geoip_module=dynamic        → GeoIP (butuh libgeoip-dev + libgeoip1)
#   --with-http_image_filter_module=dynamic → Image filter (butuh libgd-dev + libgd3)
#   --with-http_xslt_filter_module=dynamic  → XSLT (butuh libxslt-dev + libxslt1.1)
#   --with-stream                           → TCP/UDP stream proxy
#   --with-stream_ssl_module                → TLS di stream
#   --with-stream_geoip_module=dynamic      → GeoIP di stream
RUN ./configure \
      --prefix=/usr/share/nginx \
      --sbin-path=/usr/sbin/nginx \
      --conf-path=/etc/nginx/nginx.conf \
      --error-log-path=/var/log/nginx/error.log \
      --http-log-path=/var/log/nginx/access.log \
      --pid-path=/run/nginx.pid \
      --user=www-data \
      --group=www-data \
      --with-openssl=../openssl-3.4 \
      --with-http_ssl_module \
      --with-http_v2_module \
      --with-http_realip_module \
      --with-http_sub_module \
      --with-http_stub_status_module \
      --add-module=../nginx-ssl-fingerprint \
      --add-dynamic-module=../ngx_http_geoip2_module \
      --add-dynamic-module=../coraza-nginx && \
    make -j$(nproc) && \
    make install

# Kecilkan ukuran binary
# TODO: tambahkan modul lain ke strip setelah diaktifkan:
#   /usr/share/nginx/modules/ngx_http_geoip_module.so
#   /usr/share/nginx/modules/ngx_http_image_filter_module.so
#   /usr/share/nginx/modules/ngx_http_xslt_filter_module.so
#   /usr/share/nginx/modules/ngx_stream_geoip_module.so
RUN strip /usr/sbin/nginx \
          /usr/share/nginx/modules/ngx_http_geoip2_module.so \
          /usr/share/nginx/modules/ngx_http_coraza_module.so

# ==============================================================================
# STAGE 3: Build Flux WAF Dashboard (Go binary)
#
# Menggunakan golang:1.25-bookworm yang sama dengan stage builder-coraza dan
# builder-nginx agar Go module version tidak konflik antar stage.
# Binary di-compile sebagai static binary (CGO_ENABLED=0) agar berjalan di
# debian:bookworm-slim tanpa C runtime dependency.
# ==============================================================================
FROM golang:1.25-bookworm AS builder-dashboard

WORKDIR /build
COPY dashboard/ .
# go mod tidy: download deps + buat go.sum jika belum ada
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /flux-waf ./cmd/flux-waf/

# ==============================================================================
# STAGE 4: Production image — hanya runtime, TIDAK ada compiler / Go / git
#
# Process manager: s6-overlay v3 (https://github.com/just-containers/s6-overlay)
# s6 mengawasi nginx sebagai supervised longrun service.
# Init scripts di /etc/cont-init.d/ dijalankan satu kali sebelum service start.
# ==============================================================================
FROM debian:bookworm-slim

ARG S6_OVERLAY_VERSION=3.2.0.0

# Runtime dependencies saja (tidak ada -dev packages)
# libssl3         → tidak wajib untuk nginx (OpenSSL di-static-link), tapi dibutuhkan tools lain
# openssl         → untuk generate self-signed cert saat test HTTPS/JA3
# libmaxminddb0   → runtime lib untuk ngx_http_geoip2_module.so
# curl + xz-utils → dipakai saat install s6-overlay tarball
# TODO: aktifkan runtime libs saat modulnya aktif:
#   libgd3     → ngx_http_image_filter_module.so
#   libxslt1.1 → ngx_http_xslt_filter_module.so
#   libxml2    → dependency libxslt1.1
RUN apt-get update && apt-get install -y \
    libpcre3 zlib1g libssl3 ca-certificates openssl libmaxminddb0 \
    curl xz-utils \
    && ARCH=$(uname -m) \
    && curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
       | tar xJf - -C / \
    && curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${ARCH}.tar.xz" \
       | tar xJf - -C / \
    && rm -rf /var/lib/apt/lists/*

# Pastikan www-data user ada
RUN id -u www-data &>/dev/null || useradd -r -s /bin/false www-data

# ── Nginx binary + dynamic modules ──────────────────────────────────────────
COPY --from=builder-nginx /usr/sbin/nginx          /usr/sbin/nginx
COPY --from=builder-nginx /usr/share/nginx         /usr/share/nginx

# ── libcoraza.so — WAJIB ada di /usr/local/lib ──────────────────────────────
# nginx worker me-dlopen() file ini saat startup, bukan saat link time.
COPY --from=builder-coraza /usr/local/lib/libcoraza.so \
                            /usr/local/lib/libcoraza.so

# ── OWASP CRS v4 rules (baked into image) ───────────────────────────────────
COPY --from=builder-nginx /build/crs /etc/nginx/coraza/crs

# ── mime.types dari nginx install ───────────────────────────────────────────
COPY --from=builder-nginx /etc/nginx/mime.types /etc/nginx/mime.types

# Register path agar dynamic linker menemukan libcoraza.so + modules
RUN echo "/usr/local/lib"           > /etc/ld.so.conf.d/coraza.conf && \
    echo "/usr/share/nginx/modules" >> /etc/ld.so.conf.d/coraza.conf && \
    ldconfig

# Symlink modules/ agar directive "load_module modules/ngx_http_coraza_module.so"
# di nginx.conf bekerja (relatif terhadap /etc/nginx/)
RUN ln -sf /usr/share/nginx/modules /etc/nginx/modules

# Direktori yang dibutuhkan nginx + flux-waf
RUN mkdir -p \
    /var/log/nginx \
    /etc/nginx/conf.d \
    /etc/nginx/snippets \
    /etc/nginx/coraza/custom \
    /etc/nginx/certs \
    /etc/nginx/ssl_certs \
    /var/cache/nginx \
    /var/lib/flux-waf \
    /run

# Permissions
RUN chown -R www-data:www-data /var/log/nginx /var/cache/nginx /run /etc/nginx/certs /etc/nginx/ssl_certs
RUN chmod -R u+rwX,g+rwX /etc/nginx/coraza/custom /etc/nginx/snippets

# ── Flux WAF Dashboard binary ─────────────────────────────────────────────────
COPY --from=builder-dashboard /flux-waf /usr/local/bin/flux-waf

# ── s6-overlay: cont-init.d (dijalankan sekali saat startup, berurutan) ──────
COPY s6/cont-init.d/01-setup.sh      /etc/cont-init.d/01-setup.sh
COPY s6/cont-init.d/02-nginx-test.sh /etc/cont-init.d/02-nginx-test.sh
RUN chmod +x /etc/cont-init.d/01-setup.sh /etc/cont-init.d/02-nginx-test.sh

# ── s6-overlay: services.d/nginx ─────────────────────────────────────────────
COPY s6/services.d/nginx/run    /etc/services.d/nginx/run
COPY s6/services.d/nginx/finish /etc/services.d/nginx/finish
RUN chmod +x /etc/services.d/nginx/run /etc/services.d/nginx/finish

# ── s6-overlay: services.d/flux-waf (dashboard, depends on nginx) ────────────
COPY s6/services.d/flux-waf/run    /etc/services.d/flux-waf/run
COPY s6/services.d/flux-waf/finish /etc/services.d/flux-waf/finish
RUN chmod +x /etc/services.d/flux-waf/run /etc/services.d/flux-waf/finish

EXPOSE 80 443 8080

# s6-overlay PID 1 init — menggantikan entrypoint.sh
ENTRYPOINT ["/init"]
