# Mode debug: hanya Coraza + OWASP CRS

Dokumen ini menjelaskan **modul Nginx mana yang dinonaktifkan** dan **fitur apa saja yang di-comment** agar isolasi pemblokiran hampir sepenuhnya berasal dari **Coraza** dan **OWASP CRS**. Tujuannya: debugging rule CRS tanpa interferensi lapisan Nginx lain (GeoIP, threat intel, hardening WordPress, bypass asset, dll.).

**Tag pencarian di repo:** `DEBUG CRS ONLY`

---

## Modul Nginx: yang tetap aktif vs yang di-comment

| Modul | File | Status mode debug | Catatan |
|--------|------|-------------------|---------|
| **ngx_http_coraza_module** | `config/nginx.conf` | **Aktif** (`load_module ...ngx_http_coraza_module.so`) | Wajib untuk Coraza/CRS. |
| **ngx_http_geoip2_module** | `config/nginx.conf` | **Di-comment** | Tanpa ini, directive `geoip2 { ... }` tidak boleh di-uncomment tanpa mengaktifkan kembali `load_module`. |

Modul lain (mis. `ngx_http_ssl_fingerprint` untuk JA3/JA4) tidak tercantum eksplisit di `config/nginx.conf` pada workspace ini; variabel `$http_ssl_ja3_hash` / `$http_ssl_ja4_hash` diasumsikan disediakan build image jika fitur JA3/JA4 dipakai.

---

## Ringkasan file yang diubah (untuk revert)

| File | Peran |
|------|--------|
| `config/nginx.conf` | Global `http {}`: GeoIP, map JA3/JA4, block reason, threat intel, rate limit WP, log JSON. |
| `dashboard/internal/nginx/generator.go` | Template server block hasil generate: header hardening, static bypass, header/sub_filter error page. |
| `dashboard/internal/nginx/wpsnippet.go` | Generator `flux-wp-managed.conf`: seluruh output directive di-comment. |
| `config/snippets/flux-early-deny.conf` | Early `return 403` sebelum Coraza. |
| `config/snippets/wafx-ja3-enforce.conf` | `return 403` berdasarkan map JA3/JA4. |
| `config/snippets/flux-wp-managed.conf` | Snippet WP managed (deny, limit_req, dll.) — seluruh isi aktif di-comment. |
| `config/snippets/wafx-wordpress-security.conf` | Snippet WP contoh WafX — seluruh blok deny/rate-limit di-comment. |

**Yang tidak disentuh (tetap ada):**

- `config/coraza/coraza.conf` dan seluruh rantai **OWASP CRS** + custom Coraza (`vpatch`, `basic-rules`, `dlp-rules`, dll.) — ini sengaja tetap bisa memblok.
- Di template `generator.go`: `location ^~ /.well-known/acme-challenge/` dengan `coraza off` (Let's Encrypt).
- `location ^~ /errors/` dengan `coraza off` (halaman error internal); hanya **header/sub_filter** “block reason” yang di-comment.

---

## Detail per file

### 1. `config/nginx.conf`

**Di-comment (mode debug):**

1. **`load_module modules/ngx_http_geoip2_module.so;`**
   - **Efek:** GeoIP2 tidak termuat; jangan aktifkan kembali blok `geoip2 { ... }` tanpa uncomment baris ini (Nginx akan gagal `nginx -t`).

2. **`log_format flux_json` + `access_log ... flux_json`**
   - **Efek:** Log JSON paralel (`/var/log/nginx/access_json.log`) tidak ditulis.
   - **Alasan:** Format memakai variabel `$geoip2_*`, `$wafx_ja3_blocked`, `$wafx_ja4_blocked` yang bergantung fitur yang juga dimatikan.

3. **Rate limit WordPress (global):**
   - `limit_req_zone ... zone=wafx_wp_login`
   - `map $uri $flux_wp_login_key` + `limit_req_zone ... zone=flux_wp_login`
   - **Efek:** Zone untuk `limit_req` di snippet WP tidak terdefinisi jika snippet WP di-uncomment nanti — **urutan revert:** uncomment zone di `nginx.conf` dulu, baru snippet yang memanggil `limit_req zone=...`.

4. **Blok berikut (satu kesatuan untuk early block & observability):**
   - `geoip2 /etc/nginx/geoip/GeoLite2-Country.mmdb { ... }`
   - `include /etc/nginx/geoip/geoip-blocked-countries.conf;` → mendefinisikan `$geoip2_blocked_country`
   - `include /etc/nginx/snippets/wafx-ja3-map.conf;` → `$wafx_ja3_blocked`
   - `include /etc/nginx/snippets/wafx-ja4-map.conf;` → `$wafx_ja4_blocked`
   - `include /etc/nginx/snippets/flux-403-block-reason.conf;` → `$flux_early_block_msg`, `$flux_block_reason_display`
   - `include /etc/nginx/threat-intel/ip_rules.conf;` → `deny` berbasis IP (sering log: *access forbidden by rule*)

**Cara mengaktifkan kembali (urutan disarankan):**

1. Uncomment `load_module ... geoip2 ...` jika pakai GeoIP.
2. Uncomment `geoip2 { ... }` dan `include ... geoip-blocked-countries.conf` (pastikan `.mmdb` ada).
3. Uncomment `wafx-ja3-map.conf` dan `wafx-ja4-map.conf` jika dipakai.
4. Uncomment `flux-403-block-reason.conf` **setelah** map JA3/JA4 dan GeoIP (file ini punya komentar urutan include).
5. Uncomment `ip_rules.conf` jika threat intel ingin aktif.
6. Uncomment `flux_json` **hanya jika** variabel di langkah 3–5 sudah konsisten (atau sederhanakan format log).
7. Uncomment zone `limit_req` + `map $flux_wp_login_key` sebelum mengaktifkan kembali snippet WP yang memakai `limit_req`.

---

### 2. `dashboard/internal/nginx/generator.go` (template string `hostTemplate`)

**Di-comment dalam output server block:**

1. **`include /etc/nginx/snippets/hide-backend-headers.conf;`**
   - **Fitur:** Sembunyikan header fingerprint backend (`X-Powered-By`, `Server` dari upstream, dll.) dan inject `Server: Flux WAF`.
   - **Bukan sumber 403**; hanya hardening header.

2. **Di `location ^~ /errors/`:**
   - `add_header X-Flux-Block-Reason $flux_block_reason_display always;`
   - `sub_filter '__FLUX_BLOCK_REASON__' $flux_block_reason_display;`
   - **Efek:** Halaman error 403 tetap bisa ditampilkan, tapi placeholder alasan blok tidak terisi dari map Flux (bergantikan `flux-403-block-reason.conf` yang juga di-comment di global).

3. **Seluruh `location ~* \.(?:css|js|...)$` yang memakai `static-assets-bypass.conf`**
   - **Fitur asli:** `coraza off` + cache header + proxy ke upstream untuk asset statis.
   - **Mode debug:** Traffic asset lewat `location /` utama sehingga **Coraza/CRS tetap menilai** request file statis (berguna untuk uji false positive CRS pada path/ekstensi).

**Cara mengaktifkan kembali:**

- Uncomment baris-baris yang berprefiks `# DEBUG CRS ONLY` di template, lalu **rebuild dashboard** (jika binary dipakai) atau jalankan dari source, lalu **regenerate** semua host config dan `nginx -t` + reload.

---

### 3. `dashboard/internal/nginx/wpsnippet.go`

**Perilaku saat ini:** Setiap directive yang sebelumnya ditulis aktif sekarang ditulis sebagai **baris yang di-comment** (prefix `#`), ditandai dengan baris:

`# DEBUG CRS ONLY: semua directive WordPress hardening di-comment sementara.`

**Fitur yang tidak aktif di output file snippet (meskipun opsi dashboard ON):**

- `proxy_hide_header X-Powered-By;`
- `limit_req zone=flux_wp_login ...` (butuh zone di `nginx.conf`)
- `location = /xmlrpc.php` → `deny` + `return 444`
- `location ~* /(wp-config.php|...)` → `deny` + `return 404`
- `location ~* /wp-content/uploads/.*\.php$` → `deny` + `return 403`
- `if` author enumeration → `return 403`
- `if` user-agent scanner → `return 403`
- `location` strip `?ver=` pada css/js

**Cara mengaktifkan kembali:**

- Kembalikan `b.WriteString(...)` ke bentuk **tanpa** `#` di depan untuk setiap blok (atau hapus mode debug dan generate ulang snippet).
- Pastikan `limit_req_zone` di `nginx.conf` sudah aktif sebelum mengaktifkan rate limit login.

---

### 4. Snippet: `config/snippets/flux-early-deny.conf`

**Isi asli (konsep):** `if ($flux_early_block_msg) { return 403; }`

**Mode debug:** Seluruh `if` di-comment.

**Dependensi:** `flux-403-block-reason.conf` + map JA3/JA4 + GeoIP (untuk pesan prioritas). Tanpa include global tersebut, variabel `$flux_early_block_msg` kosong.

**Include:** Harus ada di `server {}` jika ingin dipakai (cek `conf.d` / template host).

---

### 5. Snippet: `config/snippets/wafx-ja3-enforce.conf`

**Isi asli:** `if ($wafx_ja3_blocked) return 403;` dan sama untuk JA4.

**Mode debug:** Di-comment.

**Dependensi:** `wafx-ja3-map.conf` / `wafx-ja4-map.conf` di `http {}` dan modul/build yang menyediakan hash TLS.

---

### 6. Snippet: `config/snippets/flux-wp-managed.conf` dan `wafx-wordpress-security.conf`

Seluruh directive operasional (deny, return, limit_req, if) di-comment; hanya komentar dokumentasi yang tersisa.

**Cara mengaktifkan kembali:** Uncomment isi file sesuai kebutuhan, atau generate ulang dari dashboard setelah revert `wpsnippet.go`.

---

## Yang masih bisa menghasilkan 403 / 4xx di luar CRS (disengaja tidak diubah)

Untuk transparansi debugging:

- **Backend / upstream** bisa mengembalikan 403/401 — bukan Coraza.
- **`ExcludePaths` di host config:** `location` dengan `coraza off` + proxy — tidak memblok, tapi melewati WAF.
- **CRS + custom rules** di `config/coraza/` tetap bisa memblok (ini yang ingin diuji).
- **`error_page 403`** memicu subrequest internal ke `/errors/403.html` — bukan pemblokiran tambahan, hanya presentasi error.

---

## Checklist setelah mengaktifkan kembali fitur

1. Uncomment bagian yang diinginkan di `config/nginx.conf` (perhatikan urutan GeoIP → map → flux-403).
2. Revert bagian template di `generator.go` / `wpsnippet.go` jika perlu output aktif.
3. Regenerate konfigurasi host (`WriteHostConf` / sync dashboard / deploy pipeline proyek).
4. `nginx -t`
5. Reload Nginx
6. Verifikasi: request yang sebelumnya di-block Nginx murni (mis. IP di `ip_rules.conf`) akan kembali muncul sebagai 403 **tanpa** baris audit Coraza jika pemblok tetap di lapisan Nginx.

---

## Versi dokumen

- Dibuat untuk workspace **nginx-coroza-crs-docker** dengan penanda `DEBUG CRS ONLY` pada patch terkait.
- Jika struktur repo berubah, cari string `DEBUG CRS ONLY` di seluruh repo untuk daftar patch terkini.
