function hostsApp() {
    return {
      hosts: [],
      tlsCerts: [],
      assetVersion: '',
      loading: true,
      showModal: false,
      modalTab: 'general',
      isEdit: false,
      saving: false,
      error: '',
      form: {},

      // Delete modal state
      showDeleteModal: false,
      deleteTarget: '',
      deleteError: '',
      deleting: false,

      // Detail modal state
      showDetailModal: false,
      detailHost: {},
      modalTabs: [
        { id: 'general', label: 'General' },
        { id: 'tls_realip', label: 'Advanced' },
        { id: 'virtual_patching', label: 'Virtual Patching' },
        { id: 'bot_threshold', label: 'Bot Threshold' },
        { id: 'geoip', label: 'GeoIP' },
        { id: 'dlp', label: 'DLP' },
        { id: 'wordpress_security', label: 'WordPress' },
      ],
      securityModes: [
        { id: 'inherit', label: 'Inherit Global', activeClass: 'border-sky-500/40 bg-sky-500/10 text-sky-300' },
        { id: 'override', label: 'Override (Custom)', activeClass: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' },
        { id: 'disabled', label: 'Disabled', activeClass: 'border-gray-500/40 bg-gray-500/10 text-gray-300' },
      ],

      /* Template HTML statis: /public/static-templates/{minimal,maintenance,landing}.html (dimuat on-demand) */

      get activeTlsCerts() {
        return (this.tlsCerts || []).filter(c => (c.status || '').toLowerCase() === 'active');
      },

      blank() {
        return {
          domain: '',
          original_domain: '',
          name: '',
          mode: 'reverse_proxy',
          listen_ports: [{ port: 80, https: false, _key: 'lp-new-80' }],
          show_advanced_upstream_tls: false,
          upstream_servers: [''],
          lb_algorithm: 'round_robin',
          static_root: '',
          static_source: 'dashboard',
          static_page_html: '',
          static_page_error: '',
          static_page_msg: '',
          static_page_saving: false,
          static_legacy_manual: false,
          redirect_url: '',
          redirect_code: 301,
          waf_mode: 'On',
          ssl_cert_id: '',
          proxy_ssl_verify_off: false,
          proxy_ssl_name: '',
          // Advanced server transport / performance toggles (default off)
          listen_ipv6: false,
          redirect_http_to_https: false,
          hsts_enabled: false,
          gzip_enabled: false,
          brotli_enabled: false,
          enabled: true,
          security_overrides: {
            virtual_patching: { mode: 'inherit', custom: { profile: 'balanced', notes: '' } },
            bot_threshold: { mode: 'inherit', custom: { threshold: 0, login_rpm: 0 } },
            geoip: { mode: 'inherit', custom: { blocked_countries: '' } },
            dlp: { mode: 'inherit', custom: { inspect_request_body: true, inspect_response_body: false } },
            wordpress_security: { mode: 'inherit', custom: { profile: 'balanced', login_path: '/wp-login.php' } },
            real_ip: { mode: 'inherit', custom: { header: 'X-Forwarded-For', header_custom: '', trusted_proxies: '' } },
          }
        };
      },

      normalizeOverrideMode(v) {
        const m = String(v || '').trim().toLowerCase();
        return (m === 'override' || m === 'disabled') ? m : 'inherit';
      },

      normalizeSecurityOverrides(raw) {
        const o = raw || {};
        return {
          virtual_patching: {
            mode: this.normalizeOverrideMode(o?.virtual_patching?.mode),
            custom: (o?.virtual_patching?.custom && typeof o.virtual_patching.custom === 'object') ? o.virtual_patching.custom : { profile: 'balanced', notes: '' }
          },
          bot_threshold: {
            mode: this.normalizeOverrideMode(o?.bot_threshold?.mode),
            custom: (o?.bot_threshold?.custom && typeof o.bot_threshold.custom === 'object') ? o.bot_threshold.custom : { threshold: 0, login_rpm: 0 }
          },
          geoip: {
            mode: this.normalizeOverrideMode(o?.geoip?.mode),
            custom: (o?.geoip?.custom && typeof o.geoip.custom === 'object') ? o.geoip.custom : { blocked_countries: '' }
          },
          dlp: {
            mode: this.normalizeOverrideMode(o?.dlp?.mode),
            custom: (o?.dlp?.custom && typeof o.dlp.custom === 'object') ? o.dlp.custom : { inspect_request_body: true, inspect_response_body: false }
          },
          wordpress_security: {
            mode: this.normalizeOverrideMode(o?.wordpress_security?.mode),
            custom: (o?.wordpress_security?.custom && typeof o.wordpress_security.custom === 'object') ? o.wordpress_security.custom : { profile: 'balanced', login_path: '/wp-login.php' }
          },
          real_ip: {
            mode: this.normalizeOverrideMode(o?.real_ip?.mode),
            custom: (o?.real_ip?.custom && typeof o.real_ip.custom === 'object')
              ? {
                  header: o.real_ip.custom.header ?? 'X-Forwarded-For',
                  header_custom: o.real_ip.custom.header_custom ?? '',
                  trusted_proxies: o.real_ip.custom.trusted_proxies ?? '',
                }
              : { header: 'X-Forwarded-For', header_custom: '', trusted_proxies: '' }
          },
        };
      },

      securityModeOf(tabId) {
        if (tabId === 'virtual_patching') return this.form?.security_overrides?.virtual_patching?.mode || 'inherit';
        if (tabId === 'bot_threshold') return this.form?.security_overrides?.bot_threshold?.mode || 'inherit';
        if (tabId === 'geoip') return this.form?.security_overrides?.geoip?.mode || 'inherit';
        if (tabId === 'dlp') return this.form?.security_overrides?.dlp?.mode || 'inherit';
        if (tabId === 'wordpress_security') return this.form?.security_overrides?.wordpress_security?.mode || 'inherit';
        return 'inherit';
      },

      securityModeLabel(mode) {
        if (mode === 'override') return 'custom';
        if (mode === 'disabled') return 'off';
        return 'inherit';
      },

      securityBadgeClass(mode) {
        if (mode === 'override') return 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10';
        if (mode === 'disabled') return 'border-gray-600 text-gray-400 bg-gray-800/60';
        return 'border-sky-500/40 text-sky-300 bg-sky-500/10';
      },

      setSecurityMode(featureKey, mode) {
        if (!this.form.security_overrides) this.form.security_overrides = this.normalizeSecurityOverrides({});
        if (!this.form.security_overrides[featureKey]) this.form.security_overrides[featureKey] = { mode: 'inherit' };
        this.form.security_overrides[featureKey].mode = this.normalizeOverrideMode(mode);
      },

      hasHttpsPort() {
        return (this.form.listen_ports || []).some(p => p.https);
      },

      modeName(mode) {
        return { reverse_proxy: 'Reverse Proxy', static: 'Static Files', redirect: 'Redirect' }[mode] || mode;
      },

      // Domain extraction helper (handles legacy host JSON key casing).
      domainOf(hostLike) {
        const d = hostLike?.domain ?? hostLike?.Domain ?? hostLike?.id ?? hostLike?.ID ?? '';
        return (d || '').toString().trim();
      },

      normalizeListenPorts(maybeArr) {
        if (!Array.isArray(maybeArr)) return [];
        const rows = maybeArr
          .map(p => ({
            port: Number(p.port ?? p.Port ?? 0),
            https: !!(p.https ?? p.HTTPS ?? p.ssl ?? p.SSL),
            _key: p._key ? String(p._key) : '',
          }))
          .filter(p => p.port > 0);
        return rows.map((p, i) => ({
          port: p.port,
          https: p.https,
          _key: p._key || ('lp-' + Date.now() + '-' + i + '-' + Math.random().toString(36).slice(2, 9)),
        }));
      },

      // Normalizes possible legacy host fields so Edit/Delete can work.
      normalizeHost(raw) {
        const h = raw || {};
        const listen_ports = this.normalizeListenPorts(h.listen_ports ?? h.ListenPorts ?? h.listenPorts ?? []);
        const upstreamRaw = h.upstream_servers ?? h.UpstreamServers ?? h.upstreamServers ?? [];
        const upstream_servers = Array.isArray(upstreamRaw)
          ? upstreamRaw
          : (upstreamRaw ? [String(upstreamRaw)] : []);

        const enabledRaw = h.enabled ?? h.Enabled;
        const enabled = (typeof enabledRaw === 'boolean') ? enabledRaw : !!(enabledRaw ?? true);

        return {
          ...h,
          domain: this.domainOf(h),
          name: h.name ?? h.Name ?? '',
          enabled,
          listen_ports: listen_ports.length ? listen_ports : [{ port: 80, https: false, _key: 'lp-def-80' }],
          mode: h.mode ?? h.Mode ?? 'reverse_proxy',
          upstream_servers: upstream_servers.length ? upstream_servers : [''],
          lb_algorithm: h.lb_algorithm ?? h.LBAlgorithm ?? h.lbAlgorithm ?? 'round_robin',
          static_root: (() => {
            const mode = h.mode ?? h.Mode ?? '';
            if (mode === 'static') {
              return '/var/www/html/' + this.sanitizeDomainDir(this.domainOf(h));
            }
            return h.static_root ?? h.StaticRoot ?? h.staticRoot ?? '';
          })(),
          static_source: (h.mode ?? h.Mode ?? '') === 'static' ? 'dashboard' : String(h.static_source ?? h.StaticSource ?? '').trim().toLowerCase() || '',
          redirect_url: h.redirect_url ?? h.RedirectURL ?? h.redirectUrl ?? '',
          redirect_code: Number(h.redirect_code ?? h.RedirectCode ?? h.redirectCode ?? 301),
          waf_mode: h.waf_mode ?? h.WAFMode ?? h.wafMode ?? 'On',
          ssl_cert_id: h.ssl_cert_id ?? h.SSLCertID ?? h.sslCertID ?? h.ssl_cert ?? '',
          ssl_enabled: !!(h.ssl_enabled ?? h.SSLEnabled ?? h.sslEnabled ?? false),
          proxy_ssl_verify_off: !!(h.proxy_ssl_verify_off ?? h.ProxySSLVerifyOff ?? false),
          proxy_ssl_name: String(h.proxy_ssl_name ?? h.ProxySSLName ?? '').trim(),
          listen_ipv6: !!(h.listen_ipv6 ?? h.ListenIPv6 ?? h.listenIpv6 ?? false),
          redirect_http_to_https: !!(h.redirect_http_to_https ?? h.RedirectHTTPToHTTPS ?? h.redirectHttpToHttps ?? false),
          hsts_enabled: !!(h.hsts_enabled ?? h.HSTSEnabled ?? h.hstsEnabled ?? false),
          gzip_enabled: !!(h.gzip_enabled ?? h.GzipEnabled ?? h.gzipEnabled ?? false),
          brotli_enabled: !!(h.brotli_enabled ?? h.BrotliEnabled ?? h.brotliEnabled ?? false),
          security_overrides: this.normalizeSecurityOverrides(h.security_overrides ?? h.SecurityOverrides ?? {}),
        };
      },

      get detailPretty() {
        try {
          return JSON.stringify(this.detailHost || {}, null, 2);
        } catch (e) {
          return String(this.detailHost || '');
        }
      },

      get detailHasHttps() {
        return (this.detailHost?.listen_ports || []).some(p => p.https);
      },

      get detailTargetText() {
        const h = this.detailHost || {};
        if (h.mode === 'redirect') {
          const u = (h.redirect_url || '').trim();
          return u ? ('→ ' + u) : '—';
        }
        if (h.mode === 'static') {
          const r = (h.static_root || '').trim();
          return r ? r : '—';
        }
        const up = (h.upstream_servers || []).filter(Boolean);
        return up.length ? up.join(', ') : '—';
      },

      get detailLBText() {
        const h = this.detailHost || {};
        if (h.mode !== 'reverse_proxy' || !(h.upstream_servers || []).length || h.upstream_servers.length < 2) return '';
        const a = h.lb_algorithm || 'round_robin';
        if (a === 'least_conn') return 'Least connections';
        if (a === 'ip_hash') return 'IP hash';
        return 'Round robin';
      },

      get detailCertLine() {
        const h = this.detailHost || {};
        if (!this.detailHasHttps) return '—';
        const line = this.certSummary(h);
        if (line) return line;
        if (h.ssl_cert_id) return h.ssl_cert_id;
        return 'Belum memilih sertifikat';
      },

      tlsOptionLabel(c) {
        const src = c.source === 'letsencrypt' ? 'LE' : 'custom';
        return c.domain + ' (' + src + ')';
      },

      certSummary(host) {
        if (!host.ssl_enabled) return '';
        const c = (this.tlsCerts || []).find(x => x.id === host.ssl_cert_id);
        if (!c) return host.ssl_cert_id || '';
        return c.domain + ' · ' + (c.source === 'letsencrypt' ? 'LE' : 'custom');
      },

      refreshIcons() {
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      setHostMode(m) {
        this.form.mode = m.id;
        if (m.id !== 'reverse_proxy') this.form.show_advanced_upstream_tls = false;
        if (m.id === 'static') {
          this.form.static_source = 'dashboard';
          this.form.static_root = this.dashboardStaticRoot();
        }
        this.$nextTick(async () => {
          if (window.lucide) lucide.createIcons();
          if (this.form.mode === 'static') await this.loadStaticPage();
        });
      },

      sanitizeDomainDir(domain) {
        const d = (domain || '').toLowerCase().trim();
        let out = '';
        for (let i = 0; i < d.length; i++) {
          const ch = d[i];
          if (/[a-z0-9.-]/.test(ch)) out += ch;
          else out += '_';
        }
        return out || 'host';
      },

      dashboardStaticRoot() {
        return '/var/www/html/' + this.sanitizeDomainDir(this.form.domain);
      },

      async loadStaticPage() {
        this.form.static_page_error = '';
        this.form.static_legacy_manual = false;
        if (this.form.mode !== 'static') return;
        const dom = (this.form.domain || '').trim();
        if (!dom) {
          this.form.static_page_html = '';
          return;
        }
        try {
          const r = await fetch('/api/hosts/' + encodeURIComponent(dom) + '/static-page');
          const d = await r.json().catch(() => ({}));
          if (!r.ok) {
            this.form.static_page_html = '';
            if (r.status === 404 && !this.isEdit) {
              this.form.static_page_error = '';
              return;
            }
            this.form.static_page_error = d.error || ('HTTP ' + r.status);
            return;
          }
          this.form.static_page_html = d.html != null ? d.html : '';
          this.form.static_legacy_manual = String(d.source || '').toLowerCase() === 'manual';
        } catch (e) {
          this.form.static_page_error = 'Gagal memuat index.html';
        }
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      async saveStaticPage() {
        this.form.static_page_error = '';
        this.form.static_page_msg = '';
        const dom = (this.form.domain || '').trim();
        if (!dom) {
          this.form.static_page_error = 'Domain wajib diisi.';
          return;
        }
        if (this.form.mode !== 'static') return;
        this.form.static_page_saving = true;
        try {
          const r = await fetch('/api/hosts/' + encodeURIComponent(dom) + '/static-page', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ html: this.form.static_page_html != null ? this.form.static_page_html : '' }),
          });
          const d = await r.json().catch(() => ({}));
          if (!r.ok || !d.ok) {
            this.form.static_page_error = d.error || ('HTTP ' + r.status);
            this.form.static_page_saving = false;
            return;
          }
          this.form.static_page_msg = 'index.html tersimpan.';
        } catch (e) {
          this.form.static_page_error = 'Gagal menyimpan.';
        }
        this.form.static_page_saving = false;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      async applyStaticTemplate(key) {
        const allowed = ['minimal', 'maintenance', 'landing'];
        if (!allowed.includes(key)) return;
        this.form.static_page_msg = '';
        this.form.static_page_error = '';
        const q = this.assetVersion ? ('?v=' + encodeURIComponent(this.assetVersion)) : '';
        const url = '/public/static-templates/' + key + '.html' + q;
        try {
          const r = await fetch(url);
          if (!r.ok) {
            this.form.static_page_error = 'Gagal memuat template.';
            return;
          }
          this.form.static_page_html = await r.text();
        } catch (e) {
          this.form.static_page_error = 'Gagal memuat template.';
        }
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      addPort() {
        this.form.listen_ports.push({
          port: '',
          https: false,
          _key: 'lp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
        });
        this.refreshIcons();
      },

      removePort(idx) {
        if (this.form.listen_ports.length > 1) {
          this.form.listen_ports.splice(idx, 1);
          this.refreshIcons();
        }
      },

      addUpstream() {
        this.form.upstream_servers.push('');
        this.refreshIcons();
      },

      removeUpstream(idx) {
        if (this.form.upstream_servers.length > 1) {
          this.form.upstream_servers.splice(idx, 1);
          this.refreshIcons();
        }
      },

      async init() {
        this.assetVersion = (this.$el && this.$el.dataset && this.$el.dataset.assetVersion) ? String(this.$el.dataset.assetVersion) : '';
        await Promise.all([this.fetchHosts(), this.fetchTls()]);
      },

      async fetchTls() {
        try {
          const r = await fetch('/api/tls/certificates');
          const d = await r.json();
          this.tlsCerts = Array.isArray(d.certificates) ? d.certificates : [];
        } catch (e) { this.tlsCerts = []; }
      },

      async fetchHosts() {
        this.loading = true;
        try {
          const r = await fetch('/api/hosts');
          const d = await r.json();
          this.hosts = Array.isArray(d) ? d : [];
        } catch (e) { this.hosts = []; }
        this.loading = false;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      openAdd() {
        this.fetchTls();
        this.form = this.blank();
        this.modalTab = 'general';
        this.isEdit = false;
        this.error = '';
        this.showModal = true;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      openEdit(host) {
        this.fetchTls();
        const nh = this.normalizeHost(host);
        if (!nh.domain) {
          // Legacy/invalid host data: domain dibutuhkan untuk edit/update via API.
          this.form = { ...this.blank(), ...nh, original_domain: nh.domain || '' };
          this.isEdit = true;
          this.error = 'Invalid host data: domain missing.';
          this.showModal = true;
          this.$nextTick(async () => {
            if (window.lucide) lucide.createIcons();
            if (this.form.mode === 'static') await this.loadStaticPage();
          });
          return;
        }
        this.form = {
          ...this.blank(),
          ...nh,
          original_domain: nh.domain,
          listen_ports: (nh.listen_ports && nh.listen_ports.length > 0)
            ? nh.listen_ports.map(p => ({ ...p }))
            : [{ port: 80, https: false, _key: 'lp-fallback' }],
          upstream_servers: (nh.upstream_servers && nh.upstream_servers.length > 0)
            ? [...nh.upstream_servers]
            : [''],
          ssl_cert_id: nh.ssl_cert_id || '',
          redirect_code: nh.redirect_code || 301,
          security_overrides: this.normalizeSecurityOverrides(nh.security_overrides || {}),
          static_page_html: '',
          static_page_error: '',
          static_page_msg: '',
          static_page_saving: false,
        };
        if ((this.form.proxy_ssl_verify_off || (this.form.proxy_ssl_name || '').trim()) && this.form.mode === 'reverse_proxy') {
          this.form.show_advanced_upstream_tls = true;
        }

        const realIPMode = this.form?.security_overrides?.real_ip?.mode || 'inherit';
        const needsTLSRealIP = (this.form.mode === 'reverse_proxy') && (
          this.form.proxy_ssl_verify_off ||
          (this.form.proxy_ssl_name || '').trim() ||
          (realIPMode !== 'inherit')
        );
        this.modalTab = needsTLSRealIP ? 'tls_realip' : 'general';
        this.isEdit = true;
        this.error = '';
        this.showModal = true;
        this.$nextTick(async () => {
          if (window.lucide) lucide.createIcons();
          if (this.form.mode === 'static') await this.loadStaticPage();
        });
      },

      async save() {
        this.error = '';

        if (!this.form.domain.trim()) { this.error = 'Domain is required.'; return; }

        // Transport rules: Redirect/HSTS require both ports 80 and 443.
        if (this.form.redirect_http_to_https || this.form.hsts_enabled) {
          if (!Array.isArray(this.form.listen_ports)) this.form.listen_ports = [];

          const has80 = this.form.listen_ports.some(p => Number(p.port) === 80 && !p.https);
          if (!has80) {
            this.form.listen_ports.push({
              port: 80,
              https: false,
              _key: 'lp-force-80-' + Date.now(),
            });
          }

          const has443 = this.form.listen_ports.some(p => Number(p.port) === 443 && !!p.https);
          if (!has443) {
            this.form.listen_ports.push({
              port: 443,
              https: true,
              _key: 'lp-force-443-' + Date.now(),
            });
          }

          // If HTTPS is enabled via port 443 but no cert chosen, try to auto-pick one.
          if (!(this.form.ssl_cert_id || '').trim() && this.activeTlsCerts && this.activeTlsCerts.length > 0) {
            this.form.ssl_cert_id = this.activeTlsCerts[0].id;
          }
        }

        const ports = (this.form.listen_ports || []).filter(p => p.port);
        if (ports.length === 0) { this.error = 'At least one listening port is required.'; return; }

        if (this.hasHttpsPort() && !(this.form.ssl_cert_id || '').trim()) {
          this.error = 'HTTPS port requires a TLS certificate. Select one or add on the SSL page.';
          return;
        }

        if (this.form.mode === 'reverse_proxy') {
          const servers = this.form.upstream_servers.map(s => s.trim()).filter(s => s);
          if (servers.length === 0) { this.error = 'At least one upstream server is required.'; return; }
        } else if (this.form.mode === 'static') {
          this.form.static_source = 'dashboard';
          this.form.static_root = this.dashboardStaticRoot();
        } else if (this.form.mode === 'redirect') {
          if (!this.form.redirect_url.trim()) { this.error = 'Redirect URL is required.'; return; }
        }

        const dom = this.form.domain.trim();
        const orig = (this.form.original_domain || '').toString().trim();
        const {
          original_domain,
          show_advanced_upstream_tls,
          static_page_html,
          static_page_error,
          static_page_msg,
          static_page_saving,
          static_legacy_manual,
          ...rest
        } = this.form;
        const payload = {
          ...rest,
          domain: dom,
          listen_ports: ports.map(p => ({
            port: parseInt(p.port, 10),
            https: p.https
          })),
          upstream_servers: this.form.mode === 'reverse_proxy'
            ? this.form.upstream_servers.map(s => s.trim()).filter(s => s)
            : [],
          ssl_enabled: this.hasHttpsPort(),
          enabled: (this.form.enabled !== undefined) ? !!this.form.enabled : true,
          security_overrides: this.normalizeSecurityOverrides(this.form.security_overrides || {}),
          previous_domain: (this.isEdit && orig && orig !== dom) ? orig : '',
        };

        this.saving = true;
        try {
          const r = await fetch('/api/hosts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          const d = await r.json();
          if (!d.ok) { this.error = d.error || 'Save failed.'; this.saving = false; return; }

          const wasNewStatic = !this.isEdit && this.form.mode === 'static';
          if (wasNewStatic) {
            this.isEdit = true;
            this.form.original_domain = dom;
            this.form.static_page_msg = 'Host tersimpan. Anda bisa menyimpan index.html sekarang.';
            this.form.static_page_error = '';
            await this.fetchHosts();
            await this.loadStaticPage();
            this.saving = false;
            this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
            return;
          }

          this.showModal = false;
          await this.fetchHosts();
        } catch (e) { this.error = 'Network error. Try again.'; }
        this.saving = false;
      },

      // Open custom delete confirm modal
      confirmDelete(hostLikeOrDomain) {
        this.deleteTarget = this.domainOf(hostLikeOrDomain);
        this.deleteError = this.deleteTarget ? '' : 'Invalid host data: domain missing.';
        this.deleting = false;
        this.showDeleteModal = true;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      async openDetail(host) {
        await this.fetchTls();
        this.detailHost = this.normalizeHost(host);
        this.showDetailModal = true;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      },

      // Actual delete after confirmation
      async doDelete() {
        if (!this.deleteTarget) {
          this.deleteError = 'Invalid host data: domain missing.';
          return;
        }
        this.deleting = true;
        this.deleteError = '';
        try {
          const r = await fetch('/api/hosts/' + encodeURIComponent(this.deleteTarget), { method: 'DELETE' });
          const d = await r.json();
          if (!d.ok) {
            this.deleteError = d.error || 'Delete failed.';
            this.deleting = false;
            return;
          }
          this.showDeleteModal = false;
          this.deleteTarget = '';
          await this.fetchHosts();
          this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
        } catch (e) {
          this.deleteError = 'Network error. Please try again.';
        }
        this.deleting = false;
      }
    }
  }
