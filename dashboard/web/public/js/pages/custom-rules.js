function customRulesApp() {
  return {
    checking: true,
    isAdmin: false,
    content: '',
    saving: false,
    msgOk: '',
    msgErr: '',
    async init() {
      try {
        const me = await fetch('/api/me').then(r => r.json());
        this.isAdmin = me.role === 'admin';
      } catch (_) {}
      await this.load();
      this.checking = false;
    },
    async load() {
      this.msgErr = '';
      const r = await fetch('/api/waf/custom-rules');
      if (!r.ok) {
        this.msgErr = await r.text();
        return;
      }
      const d = await r.json();
      this.content = d.content || '';
    },
    async save() {
      if (!this.isAdmin) return;
      this.saving = true;
      this.msgOk = '';
      this.msgErr = '';
      try {
        const r = await fetch('/api/waf/custom-rules', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: this.content })
        });
        const t = await r.text();
        let j = {};
        try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Disimpan. Nginx reload dipicu.';
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.saving = false;
      }
    }
  };
}
