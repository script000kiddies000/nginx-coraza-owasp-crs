function vpatchApp() {
  return {
    loaded: false,
    saving: false,
    msgOk: '',
    msgErr: '',
    entries: [],
    search: '',
    form: { enabled: false, aggressive: false, notes: '', last_reload: '' },
    meta: {},
    async load() {
      this.msgErr = '';
      try {
        const [cfg, st] = await Promise.all([
          fetch('/api/vpatch/config').then(r => r.json()),
          fetch('/api/vpatch/status').then(r => r.json())
        ]);
        this.form = { ...this.form, ...cfg };
        this.meta = st.rules_file || {};
        this.entries = Array.isArray(st.entries) ? st.entries : [];
        this.loaded = true;
      } catch (e) {
        this.msgErr = e.message || String(e);
      }
    },
    get filteredEntries() {
      const q = String(this.search || '').toLowerCase().trim();
      if (!q) return this.entries;
      return this.entries.filter(e => {
        const fields = [
          e.cve, e.title, e.severity, e.raw_rx
        ].map(x => String(x || '').toLowerCase()).join(' | ');
        return fields.includes(q);
      });
    },
    sevBadgeClass(sev) {
      const s = String(sev || '').toUpperCase();
      if (s === 'CRITICAL') return 'text-rose-300 border-rose-400/30 bg-rose-500/10';
      if (s === 'HIGH') return 'text-amber-300 border-amber-400/30 bg-amber-500/10';
      if (s === 'MEDIUM') return 'text-yellow-300 border-yellow-400/30 bg-yellow-500/10';
      if (s === 'LOW') return 'text-emerald-300 border-emerald-400/30 bg-emerald-500/10';
      return 'text-gray-300 border-gray-500/30 bg-gray-500/10';
    },
    async apply() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      try {
        const r = await fetch('/api/vpatch/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.form)
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Disimpan dan nginx reload.';
        await this.load();
      } catch (e) { this.msgErr = e.message || String(e); }
      finally { this.saving = false; }
    },
    async reloadOnly() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      try {
        const r = await fetch('/api/vpatch/reload', { method: 'POST' });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Nginx reload.';
        await this.load();
      } catch (e) { this.msgErr = e.message || String(e); }
      finally { this.saving = false; }
    }
  };
}
