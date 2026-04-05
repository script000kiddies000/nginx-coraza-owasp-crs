function atkReportApp() {
  return {
    loading: false,
    period: '24h',
    events: [],
    topRulesData: [],
    topIPsData: [],
    summary: { total: 0, blocked: 0, detected: 0, domains: 0 },

    get topRules() {
      const rows = this.topRulesData.map((x) => ({
        id: x.id || '—',
        n: Number(x.count || 0),
      }));
      const max = rows.length ? rows[0].n : 1;
      return rows.map((r) => ({ ...r, pct: Math.max(4, Math.round((r.n / max) * 100)) }));
    },

    get topIPs() {
      const rows = this.topIPsData.map((x) => ({
        ip: x.ip || '—',
        n: Number(x.count || 0),
      }));
      const max = rows.length ? rows[0].n : 1;
      return rows.map((r) => ({ ...r, pct: Math.max(4, Math.round((r.n / max) * 100)) }));
    },

    async load() {
      this.loading = true;
      try {
        const r = await fetch('/api/attack-report?period=' + encodeURIComponent(this.period));
        const d = await r.json();
        this.summary = d && d.summary ? d.summary : { total: 0, blocked: 0, detected: 0, domains: 0 };
        this.events = Array.isArray(d && d.events) ? d.events : [];
        this.topRulesData = Array.isArray(d && d.top_rules) ? d.top_rules : [];
        this.topIPsData = Array.isArray(d && d.top_ips) ? d.top_ips : [];
      } catch (_) {
        this.summary = { total: 0, blocked: 0, detected: 0, domains: 0 };
        this.events = [];
        this.topRulesData = [];
        this.topIPsData = [];
      } finally {
        this.loading = false;
      }
    },

    init() {
      this.load();
    }
  };
}
