function botApp() {
  return {
    saving: false,
    msgOk: '',
    msgErr: '',
    form: {},
    whitelistText: '',
    blocked: [],
    status: { blocked_count: 0 },
    parseWL(s) {
      return String(s || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
    },
    wlToText(a) { return Array.isArray(a) ? a.join('\n') : ''; },
    async init() {
      await this.refreshBlocked();
      await this.loadConfig();
      const st = await fetch('/api/advbot/status').then(r => r.json());
      this.status = st;
      this.form = st.config || {};
      this.whitelistText = this.wlToText(this.form.whitelist_ips);
    },
    async loadConfig() {
      const c = await fetch('/api/advbot/config').then(r => r.json());
      this.form = c;
      this.whitelistText = this.wlToText(c.whitelist_ips);
    },
    async refreshBlocked() {
      const d = await fetch('/api/advbot/blocked').then(r => r.json());
      this.blocked = d.entries || [];
    },
    async save() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      const body = { ...this.form, whitelist_ips: this.parseWL(this.whitelistText) };
      try {
        const r = await fetch('/api/advbot/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Tersimpan.';
        await this.init();
      } catch (e) { this.msgErr = e.message || String(e); }
      finally { this.saving = false; }
    },
    async unblock(ip) {
      this.msgErr = '';
      try {
        const r = await fetch('/api/advbot/unblock', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip })
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Unblock: ' + ip;
        await this.refreshBlocked();
      } catch (e) { this.msgErr = e.message || String(e); }
    }
  };
}
