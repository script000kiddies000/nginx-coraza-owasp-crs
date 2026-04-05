function dashboardApp() {
  const donutColors = ['#22d3ee','#34d399','#a78bfa','#fb923c','#f472b6','#facc15','#60a5fa','#4ade80','#f87171','#94a3b8'];
  const chartBase = {
    chart: { toolbar: { show: false }, animations: { enabled: false }, foreColor: '#6b7280' },
    grid: { borderColor: '#1f2937' },
    tooltip: { theme: 'dark' },
    legend: { labels: { colors: '#6b7280' } },
    dataLabels: { enabled: false },
  };
  return {
    range: '1h',
    analytics: { summary: {}, time_series: {}, user_clients: [], response_status: [], referers: [], vhosts: [] },
    protection: {},
    protectionRows: [],
    _refreshTimer: null,
    _rpsTimer: null,
    _qpsTickTimer: null,
    _charts: {},
    topCards: [],
    geoMode: 'requests',
    worldGeo: null,
    qpsRealtime: Array(30).fill(0),
    qpsTarget: 0,
    qpsSmooth: 0,
    qpsScale: 0,
    liveQps: 0,

    fmtNum(n) { return Number(n || 0).toLocaleString(); },
    fmtRps(v) {
      const n = Math.max(0, Number(v || 0));
      return (n < 10 ? n.toFixed(2) : n.toFixed(1));
    },
    pct(rate) { return ((Number(rate || 0) * 100).toFixed(2)) + '%'; },
    statusRatio(row) {
      const t = this.analytics.summary?.request_count || 0;
      if (!t || !row.count) return '0%';
      return ((row.count / t) * 100).toFixed(1) + '%';
    },
    badgeClass(state) {
      const s = (state || '').toLowerCase();
      if (s === 'active' || s === 'loaded') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25';
      if (s === 'detect') return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25';
      if (s === 'pending' || s === 'inactive' || s === 'off') return 'text-yellow-400/90 bg-yellow-500/10 border-yellow-500/20';
      if (s === 'warn') return 'text-orange-400 bg-orange-500/10 border-orange-500/25';
      return 'text-gray-400 bg-gray-800 border-gray-700';
    },
    countryName(code) {
      const c = String(code || '').trim().toUpperCase();
      if (!c) return 'Unknown';
      try {
        if (typeof Intl !== 'undefined' && Intl.DisplayNames) {
          const dn = new Intl.DisplayNames(['en'], { type: 'region' });
          return dn.of(c) || c;
        }
      } catch (_) {}
      return c;
    },
    geoRows() {
      const rows = this.geoMode === 'blocked'
        ? (this.analytics.geo_blocked || [])
        : (this.analytics.geo_requests || []);
      return Array.isArray(rows) ? rows : [];
    },
    geoTopRows() {
      return this.geoRows().slice(0, 8);
    },
    setGeoMode(mode) {
      this.geoMode = mode === 'blocked' ? 'blocked' : 'requests';
      this.$nextTick(() => this.drawGeoMap());
    },
    async loadWorldGeo() {
      if (this.worldGeo) return this.worldGeo;
      try {
        const r = await fetch('/public/data/world.geojson');
        if (!r.ok) throw new Error('geojson status ' + r.status);
        this.worldGeo = await r.json();
      } catch (e) {
        console.warn('[dashboard] world geojson load failed:', e);
        this.worldGeo = { type: 'FeatureCollection', features: [] };
      }
      return this.worldGeo;
    },
    async drawGeoMap() {
      if (typeof d3 === 'undefined') return;
      const canvas = document.getElementById('geoMap2d');
      if (!canvas || !canvas.isConnected) return;
      const rect = canvas.getBoundingClientRect();
      // Lock render size to canvas box to prevent cumulative growth.
      const w = Math.max(220, Math.floor(rect.width || canvas.clientWidth || 0));
      const h = Math.max(180, Math.floor(rect.height || canvas.clientHeight || 230));
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';

      const ctx = canvas.getContext('2d');
      if (!ctx) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const geo = await this.loadWorldGeo();
      if (!geo || !Array.isArray(geo.features) || !geo.features.length) return;

      const projection = d3.geoNaturalEarth1().fitExtent([[4, 4], [w - 4, h - 4]], geo);
      const path = d3.geoPath(projection, ctx);

      const valMap = new Map();
      for (const r of this.geoRows()) {
        const name = this.countryName(r.label);
        const key = String(name).toLowerCase();
        valMap.set(key, Number(r.count) || 0);
      }
      const alias = {
        'united states of america': 'united states',
        'russian federation': 'russia',
        'czechia': 'czech republic',
        'korea, republic of': 'south korea',
      };

      const values = [];
      for (const f of geo.features) {
        const n = String((f.properties && f.properties.name) || '').toLowerCase();
        const v = valMap.get(n) ?? valMap.get(alias[n] || '') ?? 0;
        values.push(v);
      }
      const maxV = Math.max(1, ...values);
      const color = this.geoMode === 'blocked'
        ? d3.scaleLinear().domain([0, maxV]).range(['#0b1220', '#fb7185'])
        : d3.scaleLinear().domain([0, maxV]).range(['#0b1220', '#22d3ee']);

      geo.features.forEach((f, idx) => {
        const v = values[idx];
        ctx.beginPath();
        path(f);
        ctx.fillStyle = v > 0 ? color(v) : '#0f172a';
        ctx.fill();
        ctx.strokeStyle = 'rgba(148,163,184,0.18)';
        ctx.lineWidth = 0.5;
        ctx.stroke();
      });
    },
    ensureSeries(arr) {
      const src = Array.isArray(arr) ? arr.map((v) => Number(v) || 0) : [];
      if (src.length) return src;
      // Keep chart shape visible even when API data is empty.
      const len = this.range === '30d' ? 30 : this.range === '7d' ? 7 : 24;
      return Array(len).fill(0);
    },
    qpsBarsDisplay() {
      const arr = this.qpsRealtime || [];
      if (!arr.length) return Array(30).fill(6);
      const max = Math.max(0.08, this.qpsScale || 0, ...arr);
      return arr.map((v) => {
        const pct = (Number(v || 0) / max) * 100;
        return Math.max(8, Math.min(96, pct));
      });
    },
    startQpsTicker() {
      if (this._qpsTickTimer) clearInterval(this._qpsTickTimer);
      this._qpsTickTimer = setInterval(() => {
        const target = Math.max(0, Number(this.qpsTarget || 0));
        const prev = Math.max(0, Number(this.qpsSmooth || target));
        const next = prev + (target - prev) * 0.35; // EMA smoothing
        this.qpsSmooth = next;
        this.qpsRealtime.push(next);
        if (this.qpsRealtime.length > 30) this.qpsRealtime.shift();
        const localMax = Math.max(0.2, ...this.qpsRealtime, next);
        this.qpsScale = this.qpsScale > 0 ? (this.qpsScale*0.8 + localMax*0.2) : localMax;
        this.liveQps = next;
      }, 1000);
    },
    async fetchRPS() {
      try {
        const r = await fetch('/api/dashboard/rps');
        if (!r.ok) throw new Error('status ' + r.status);
        const payload = await r.json();
        const v = Math.max(0, Number(payload?.rps || 0));
        this.qpsTarget = v;
      } catch (_) {}
    },
    teardownCharts() {
      for (const k of Object.keys(this._charts)) {
        try { this._charts[k].destroy(); } catch (_) {}
      }
      this._charts = {};
    },
    drawCharts() {
      if (typeof ApexCharts === 'undefined') return;
      const ts = this.analytics.time_series || {};
      const labels = (ts.labels && ts.labels.length) ? ts.labels : this.ensureSeries([]).map((_, i) => String(i + 1));
      const req = this.ensureSeries(ts.requests || []);
      const blk = this.ensureSeries(ts.blocked || []);

      this.teardownCharts();

      const reqEl = document.querySelector('#chartRequests');
      if (reqEl) {
        this._charts.req = new ApexCharts(reqEl, {
          ...chartBase,
          chart: { ...chartBase.chart, type: 'line', height: 208 },
          stroke: { curve: 'smooth', width: 2 },
          colors: ['#34d399'],
          series: [{ name: 'Requests', data: req }],
          xaxis: { categories: labels, labels: { style: { colors: '#6b7280' } } },
          yaxis: { labels: { style: { colors: '#6b7280' } } },
        });
        this._charts.req.render();
      }

      const blkEl = document.querySelector('#chartBlocked');
      if (blkEl) {
        this._charts.blk = new ApexCharts(blkEl, {
          ...chartBase,
          chart: { ...chartBase.chart, type: 'line', height: 208 },
          stroke: { curve: 'smooth', width: 2 },
          colors: ['#fb7185'],
          series: [{ name: 'Blocked', data: blk }],
          xaxis: { categories: labels, labels: { style: { colors: '#6b7280' } } },
          yaxis: { labels: { style: { colors: '#6b7280' } } },
        });
        this._charts.blk.render();
      }

      const uaRows = (this.analytics.user_clients || []);
      const uaEl = document.querySelector('#chartUA');
      if (uaEl) {
        this._charts.ua = new ApexCharts(uaEl, {
          ...chartBase,
          chart: { ...chartBase.chart, type: 'donut', height: 192 },
          labels: (uaRows.length ? uaRows : [{ label: 'No data', count: 1 }]).map((x) => x.label),
          series: (uaRows.length ? uaRows : [{ label: 'No data', count: 1 }]).map((x) => Number(x.count) || 0),
          colors: donutColors,
          legend: { show: false },
          stroke: { width: 0 },
        });
        this._charts.ua.render();
      }

      const stRows = (this.analytics.response_status || []);
      const stEl = document.querySelector('#chartStatus');
      if (stEl) {
        this._charts.st = new ApexCharts(stEl, {
          ...chartBase,
          chart: { ...chartBase.chart, type: 'donut', height: 192 },
          labels: (stRows.length ? stRows : [{ label: 'No data', count: 1 }]).map((x) => x.label),
          series: (stRows.length ? stRows : [{ label: 'No data', count: 1 }]).map((x) => Number(x.count) || 0),
          colors: donutColors,
          legend: { show: false },
          stroke: { width: 0 },
        });
        this._charts.st.render();
      }
    },

    rebuildTopCards() {
      this.topCards = [
        { k: 'ah', l: 'Active hosts', cls: 'text-white', sub: 'Configured vhost', v: () => this.analytics.summary?.active_hosts || 0 },
        { k: 'ui', l: 'Unique IP', cls: 'text-cyan-400', sub: 'Distinct clients', v: () => this.analytics.summary?.unique_ips || 0 },
        { k: 'rc', l: 'Request count', cls: 'text-white', sub: 'Within selected range', v: () => this.analytics.summary?.request_count || 0 },
        { k: 'bc', l: 'Blocked', cls: 'text-rose-400', sub: '4xx security responses', v: () => this.analytics.summary?.blocked_count || 0 },
      ];
    },
    buildProtectionRows() {
      const p = this.protection || {};
      const pick = (k, title, fmt) => {
        const o = p[k] || {};
        return { key: k, title, state: (o.state || '').toLowerCase(), badge: fmt ? fmt(o) : (o.detail || o.state || '—') };
      };
      this.protectionRows = [
        pick('coraza_waf', 'Coraza WAF', (o) => o.state === 'active' ? 'Active' : o.state === 'detect' ? 'Detection only' : 'Off'),
        pick('owasp_crs', 'OWASP CRS v4', (o) => o.state === 'loaded' ? 'Loaded' : 'Off'),
        pick('geoip', 'GeoIP block', (o) => o.state === 'active' ? 'Active' : 'Inactive'),
        pick('threat_intel', 'Threat intel', (o) => o.state === 'active' ? 'Active' : 'Pending'),
        pick('tls_ja', 'TLS fingerprint', () => 'JA3 / JA4'),
        pick('dlp', 'DLP rules', () => 'Active'),
      ];
    },
    async fetchProtection() {
      try {
        const r = await fetch('/api/dashboard/protection');
        if (!r.ok) throw new Error('status ' + r.status);
        this.protection = await r.json();
      } catch (_) {
        this.protection = {};
      }
      this.buildProtectionRows();
    },
    async fetchAnalytics() {
      try {
        const r = await fetch('/api/dashboard/analytics?range=' + encodeURIComponent(this.range));
        if (!r.ok) throw new Error('status ' + r.status);
        const payload = await r.json();
        if (!payload || typeof payload !== 'object' || !payload.time_series) throw new Error('invalid payload');
        this.analytics = payload;
        // realtime RPS is fetched from /api/dashboard/rps
      } catch (e) {
        console.warn('[dashboard] fetchAnalytics failed:', e);
      }
      this.rebuildTopCards();
      this.$nextTick(() => {
        this.drawCharts();
        this.drawGeoMap();
      });
    },
    async setRange(k) {
      this.range = k;
      await this.fetchAnalytics();
    },
    async init() {
      this.rebuildTopCards();
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        this.$nextTick(() => window.lucide.createIcons());
      }
      this.startQpsTicker();
      window.addEventListener('resize', () => this.drawGeoMap());
      await this.fetchProtection();
      await this.fetchAnalytics();
      await this.fetchRPS();
      this._refreshTimer = setInterval(() => {
        this.fetchProtection();
        this.fetchAnalytics();
      }, 30000);
      this._rpsTimer = setInterval(() => this.fetchRPS(), 1000);
      window.addEventListener('pagehide', () => {
        if (this._refreshTimer) clearInterval(this._refreshTimer);
        if (this._rpsTimer) clearInterval(this._rpsTimer);
        if (this._qpsTickTimer) clearInterval(this._qpsTickTimer);
        this.teardownCharts();
      }, { once: true });
    },
  };
}
