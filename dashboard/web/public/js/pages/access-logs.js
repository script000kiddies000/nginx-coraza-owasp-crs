function accessLogsApp() {
  return {
    loading: true,
    error: '',
    logPath: '',
    entries: [],
    limit: 200,
    statusClass(st) {
      const n = Number(st);
      if (Number.isNaN(n)) return 'text-gray-400 border-gray-700 bg-gray-800';
      if (n >= 500) return 'text-rose-300 border-rose-500/30 bg-rose-500/10';
      if (n >= 400) return 'text-amber-300 border-amber-500/30 bg-amber-500/10';
      return 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10';
    },
    async load() {
      this.loading = true;
      this.error = '';
      try {
        const r = await fetch('/api/logs/access?limit=' + encodeURIComponent(this.limit));
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const data = await r.json();
        this.logPath = data.path || '';
        this.entries = Array.isArray(data.entries) ? data.entries : [];
      } catch (e) {
        this.error = e.message || String(e);
        this.entries = [];
        this.logPath = '';
      } finally {
        this.loading = false;
      }
    }
  };
}
