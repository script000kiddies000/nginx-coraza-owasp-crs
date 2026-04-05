function wpApp() {
  const ruleRows = [
    { field: 'block_xmlrpc', title: 'Block XML-RPC', desc: 'Deny all access to /xmlrpc.php — exploited for DDoS amplification and brute-force.' },
    { field: 'block_author_enum', title: 'Block author enumeration', desc: 'Return 403 for /?author=N — prevents username harvesting.' },
    { field: 'block_scanner_ua', title: 'Block scanner user agents', desc: 'Deny requests from WPScan, sqlmap, nikto, nmap, masscan, ZmEu, w3af, dirbuster, nuclei.' },
    { field: 'block_uploads_php', title: 'Protect upload directory', desc: 'Block PHP execution inside wp-content/uploads/ — prevents webshell upload exploitation.' },
    { field: 'block_sensitive_files', title: 'Protect sensitive files', desc: 'Block access to wp-config.php, .env, .htaccess, .git.' },
    { field: '_wp_version_privacy', title: 'Hide WordPress version', desc: 'Strip X-Powered-By header and remove ?ver= query strings from assets.', dual: true },
    { field: 'rate_limit_login', title: 'Rate-limit login page', desc: 'Limit requests to /wp-login.php per IP (uses zone flux_wp_login in nginx.conf).' },
    { field: 'remind_file_edit', title: 'Remind: disable file editor', desc: 'Adds a comment in the snippet — set DISALLOW_FILE_EDIT in wp-config.php (not enforced by nginx).' },
  ];

  const boolKeys = ['block_xmlrpc','block_sensitive_files','block_uploads_php','block_author_enum','block_scanner_ua','strip_asset_version','hide_powered_by','rate_limit_login','remind_file_edit'];

  return {
    loaded: false,
    saving: false,
    msgOk: '',
    msgErr: '',
    form: {},
    ruleRows,

    wpVersionValue() {
      const h = !!this.form.hide_powered_by;
      const v = !!this.form.strip_asset_version;
      return (h || v) ? 'on' : 'off';
    },
    setWpVersion(v) {
      const on = v === 'on';
      this.form.hide_powered_by = on;
      this.form.strip_asset_version = on;
    },

    normalize(d) {
      const c = { ...d };
      boolKeys.forEach(k => {
        c[k] = Object.prototype.hasOwnProperty.call(d, k) ? !!d[k] : true;
      });
      c.last_written = d.last_written || '';
      return c;
    },

    async load() {
      try {
        const d = await fetch('/api/wp-security/config').then(r => r.json());
        this.form = this.normalize(d);
        this.loaded = true;
      } catch (e) { this.msgErr = e.message || String(e); }
    },

    async save() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      try {
        const payload = {};
        boolKeys.forEach(k => { payload[k] = !!this.form[k]; });
        const r = await fetch('/api/wp-security/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Snippet ditulis: ' + (j.snippet_path || 'ok');
        if (j.config) this.form = this.normalize(j.config);
        await this.load();
      } catch (e) { this.msgErr = e.message || String(e); }
      finally { this.saving = false; }
    }
  };
}
