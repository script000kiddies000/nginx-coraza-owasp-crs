function securityLogsPage() {
  return {
    tab: 'events',
    loading: true,
    error: '',
    events: [],
    gLoading: true,
    gError: '',
    groups: [],
    gTotal: 0,
    gPage: 1,
    gTotalPages: 1,
    gPerPage: 20,
    filters: { ip: '', domain: '', port: '', start: '', end: '' },

    init() {
      const h = (window.location.hash || '').toLowerCase();
      if (h === '#logs') this.tab = 'logs';
      else if (h === '#events') this.tab = 'events';
      this.load();
      this.loadGroups();
      this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
    },

    formatDuration(min) {
      const n = Number(min);
      if (Number.isNaN(n) || n < 0) return '—';
      if (n === 0) return '0 menit';
      if (n === 1) return '1 menit';
      return n + ' menit';
    },

    formatDatePart(iso) {
      try {
        const d = new Date(iso);
        return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
      } catch (_) { return iso; }
    },

    formatTimePart(iso) {
      try {
        const d = new Date(iso);
        return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      } catch (_) { return ''; }
    },

    async load() {
      this.loading = true;
      this.error = '';
      try {
        const r = await fetch('/api/security-events');
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        this.events = await r.json();
      } catch (e) {
        this.error = e.message || String(e);
        this.events = [];
      } finally {
        this.loading = false;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      }
    },

    buildGroupQuery() {
      const p = new URLSearchParams();
      p.set('page', String(this.gPage));
      p.set('per_page', String(this.gPerPage));
      if (this.filters.ip) p.set('ip', this.filters.ip);
      if (this.filters.domain) p.set('domain', this.filters.domain);
      if (this.filters.port) p.set('port', this.filters.port);
      if (this.filters.start) {
        const t = new Date(this.filters.start);
        if (!Number.isNaN(t.getTime())) p.set('start', t.toISOString());
      }
      if (this.filters.end) {
        const t = new Date(this.filters.end);
        if (!Number.isNaN(t.getTime())) p.set('end', t.toISOString());
      }
      return p.toString();
    },

    async loadGroups() {
      this.gLoading = true;
      this.gError = '';
      try {
        const r = await fetch('/api/security-events/groups?' + this.buildGroupQuery());
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const data = await r.json();
        this.groups = data.rows || [];
        this.gTotal = data.total || 0;
        this.gPage = data.page || 1;
        this.gTotalPages = data.total_pages || 1;
      } catch (e) {
        this.gError = e.message || String(e);
        this.groups = [];
      } finally {
        this.gLoading = false;
        this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
      }
    }
  };
}
