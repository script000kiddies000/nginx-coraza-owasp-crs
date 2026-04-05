function eventLogsApp() {
  return {
    loading: true,
    error: '',
    path: '',
    count: 0,
    limit: 200,
    source: 'nginx-error',
    levelFilter: 'all',
    search: '',
    lines: [],
    autoRefresh: true,
    autoScroll: true,
    refreshMs: 2000,
    timer: null,
    sev: { emerg: 0, alert: 0, error: 0, warn: 0, notice: 0, info: 0 },

    levelClass(level) {
      const lv = String(level || '').toLowerCase();
      if (lv === 'emerg' || lv === 'alert' || lv === 'crit') return 'text-rose-200 border-rose-500/35 bg-rose-500/14';
      if (lv === 'error') return 'text-rose-200 border-rose-500/35 bg-rose-500/14';
      if (lv === 'warn' || lv === 'warning') return 'text-amber-200 border-amber-500/35 bg-amber-500/14';
      if (lv === 'notice' || lv === 'info') return 'text-emerald-200 border-emerald-500/35 bg-emerald-500/12';
      return 'text-cyan-200 border-cyan-500/35 bg-cyan-500/12';
    },
    summarize() {
      const c = { emerg: 0, alert: 0, error: 0, warn: 0, notice: 0, info: 0 };
      for (const l of this.lines || []) {
        const lv = String(l.level || '').toLowerCase();
        if (lv === 'emerg') c.emerg++;
        else if (lv === 'alert' || lv === 'crit') c.alert++;
        else if (lv === 'error') c.error++;
        else if (lv === 'warn' || lv === 'warning') c.warn++;
        else if (lv === 'notice') c.notice++;
        else c.info++;
      }
      this.sev = c;
    },
    filteredLines() {
      let rows = this.lines || [];
      if (this.levelFilter === 'error') {
        rows = rows.filter((l) => ['error', 'alert', 'emerg', 'crit'].includes(String(l.level || '').toLowerCase()));
      } else if (this.levelFilter === 'warn') {
        rows = rows.filter((l) => ['warn', 'warning'].includes(String(l.level || '').toLowerCase()));
      } else if (this.levelFilter === 'notice') {
        rows = rows.filter((l) => ['notice', 'info'].includes(String(l.level || '').toLowerCase()));
      }
      const q = String(this.search || '').trim().toLowerCase();
      if (!q) return rows;
      return rows.filter((l) => String(l.line || l.raw || '').toLowerCase().includes(q));
    },
    scrollBottom() {
      if (!this.autoScroll) return;
      const pane = document.getElementById('eventLogPane');
      if (pane) pane.scrollTop = pane.scrollHeight;
    },
    async copyShown() {
      const rows = this.filteredLines().map((l) => l.line || l.raw || '');
      if (!rows.length) return;
      try {
        await navigator.clipboard.writeText(rows.join('\n'));
      } catch (_) {}
    },
    async load() {
      this.loading = true;
      this.error = '';
      try {
        const r = await fetch('/api/logs/events?limit=' + encodeURIComponent(this.limit));
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const d = await r.json();
        this.path = d.path || '';
        this.count = d.count || 0;
        this.lines = Array.isArray(d.lines) ? d.lines : [];
        this.summarize();
        requestAnimationFrame(() => this.scrollBottom());
      } catch (e) {
        this.error = e.message || String(e);
        this.lines = [];
      } finally {
        this.loading = false;
      }
    },
    restartTimer() {
      if (this.timer) clearInterval(this.timer);
      if (!this.autoRefresh) return;
      this.timer = setInterval(() => this.load(), this.refreshMs || 2000);
    },
    init() {
      this.load();
      this.restartTimer();
      window.addEventListener('pagehide', () => {
        if (this.timer) clearInterval(this.timer);
      }, { once: true });
    }
  };
}
