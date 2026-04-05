function dlpApp() {
  return {
    builtinPatterns: [
      { name: 'DLP: Credit Card Number', rawPattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\\b', severity: 'CRITICAL', auditOnly: false },
      { name: 'DLP: Social Security Number', rawPattern: '\\b(?:[1-8][0-9]{2}|9(?:[0-8][0-9]|9[0-9]))-(?:[1-9][0-9]|0[1-9])-(?:[1-9][0-9]{3}|0[1-9][0-9]{2}|00[1-9][0-9]|000[1-9])\\b', severity: 'CRITICAL', auditOnly: false },
      { name: 'DLP: API Key / Bearer Token', rawPattern: '(?i)(?:api[_\\-]?key|bearer|access[_\\-]?token|secret)[^\\S\\n]*[:=][^\\S\\n]*[A-Za-z0-9\\-_.~+/]{16,64}', severity: 'CRITICAL', auditOnly: false },
      { name: 'DLP: AWS Access Key', rawPattern: 'AKIA[0-9A-Z]{16}', severity: 'CRITICAL', auditOnly: false },
      { name: 'DLP: Private Key (PEM)', rawPattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', severity: 'CRITICAL', auditOnly: false },
      { name: 'DLP: Password field (audit only)', rawPattern: '(?i)\\x22(?:password|passwd|pwd|secret)\\x22\\s*:\\s*\\x22[^\\x22]{4,}\\x22', severity: 'ERROR', auditOnly: true },
      { name: 'DLP: JWT Token (audit only)', rawPattern: 'eyJ[A-Za-z0-9\\-_]{10,}\\.eyJ[A-Za-z0-9\\-_]{10,}\\.[A-Za-z0-9\\-_.+/]{10,}', severity: 'ERROR', auditOnly: true }
    ],
    saving: false,
    msgOk: '',
    msgErr: '',
    form: {},
    customPatterns: [],
    newPattern: '',
    metaInspection: {},
    metaRules: {},
    events: [],
    severityClass(sev) {
      if (sev === 'CRITICAL') return 'text-rose-300 border-rose-400/40 bg-rose-500/10';
      if (sev === 'ERROR') return 'text-amber-300 border-amber-400/40 bg-amber-500/10';
      return 'text-gray-300 border-gray-500/40 bg-gray-500/10';
    },
    parseCustomPatterns(list) {
      const builtins = new Set(this.builtinPatterns.map(x => x.name));
      return (list || []).map(x => String(x || '').trim()).filter(Boolean).filter(x => !builtins.has(x));
    },
    catalogRows() {
      const rows = this.builtinPatterns.map(p => {
        return {
          builtin: true,
          name: p.name,
          rawPattern: p.rawPattern,
          severity: p.severity,
          action: p.auditOnly ? 'PASS + LOG' : (this.form.alert_on_block ? 'BLOCK + LOG' : 'BLOCK + NOLOG')
        };
      });
      return rows.concat(this.customPatterns.map(p => ({
        builtin: false,
        name: `Custom: ${p}`,
        rawPattern: p,
        severity: 'CRITICAL',
        action: this.form.alert_on_block ? 'BLOCK + LOG' : 'BLOCK + NOLOG'
      })));
    },
    async init() {
      await Promise.all([this.loadCfg(), this.loadEvents(), this.loadStatus()]);
    },
    async loadCfg() {
      const c = await fetch('/api/dlp/config').then(r => r.json());
      this.form = c || {};
      if (!Array.isArray(this.form.dlp_patterns)) this.form.dlp_patterns = [];
      this.customPatterns = this.parseCustomPatterns(this.form.dlp_patterns);
    },
    async loadStatus() {
      const s = await fetch('/api/dlp/status').then(r => r.json());
      this.metaInspection = s.inspection_file || {};
      this.metaRules = s.rules_file || {};
    },
    async loadEvents() {
      this.events = await fetch('/api/dlp/events?limit=100').then(r => r.json());
    },
    addPattern() {
      const p = String(this.newPattern || '').trim();
      if (!p) return;
      if (this.customPatterns.includes(p)) return;
      this.customPatterns.push(p);
      this.newPattern = '';
    },
    removePattern(i) {
      this.customPatterns.splice(i, 1);
    },
    async apply() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      const body = {
        ...this.form,
        dlp_patterns: [...this.builtinPatterns.map(x => x.name), ...this.customPatterns]
      };
      try {
        const r = await fetch('/api/dlp/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Data Guard config berhasil disimpan dan diterapkan.';
        await this.init();
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.saving = false;
      }
    },
    async clearEvents() {
      if (!confirm('Hapus semua event DLP di dashboard?')) return;
      try {
        await fetch('/api/dlp/clear-events', { method: 'POST' });
        this.msgOk = 'Event dikosongkan.';
        await this.loadEvents();
      } catch (e) {
        this.msgErr = e.message || String(e);
      }
    }
  };
}
