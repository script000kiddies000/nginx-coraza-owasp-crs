function nginxMon() {
    return {
      loading: false,
      auto: true,
      error: '',
      data: null,
      server: null,
      timer: null,
      tab: 'request_stats',

      rpsHist: Array(60).fill(0),
      connHist: Array(60).fill(0),
      liveRps: 0,
      chart: null,
      prevRequests: null,
      prevTs: 0,

      fmtNum(v) {
        if (v === undefined || v === null) return '—';
        return Number(v).toLocaleString();
      },
      fmtPct(v) {
        if (v === undefined || v === null || !isFinite(Number(v))) return '—';
        return Number(v).toFixed(2) + '%';
      },
      fmtMB(rssKB) {
        const kb = Number(rssKB || 0);
        if (!isFinite(kb) || kb <= 0) return '—';
        const mb = kb / 1024;
        return mb.toFixed(mb < 10 ? 2 : 1) + ' MB';
      },
      fmtMemUsage(srv) {
        if (!srv || srv.memory_used_gb === 0 && srv.memory_total_gb === 0) return '—';
        if (!isFinite(Number(srv.memory_used_gb))) return '—';
        // WAFx shows MB; we keep GB but format is consistent.
        return Number(srv.memory_used_gb).toFixed(1) + ' GB';
      },
      workerCPUPercent() {
        const ps = this.data?.processes || [];
        let sum = 0;
        for (const p of ps) {
          if ((p?.role || '') === 'worker') sum += Number(p?.cpu_percent || 0);
        }
        return isFinite(sum) ? sum : 0;
      },
      totalRSSKB() {
        const ps = this.data?.processes || [];
        let sum = 0;
        for (const p of ps) sum += Number(p?.rss_kb || 0);
        return isFinite(sum) ? sum : 0;
      },
      fmtProcTotal(d) {
        if (!d) return '—';
        const a = Number(d.master_processes || 0);
        const b = Number(d.worker_processes || 0);
        const c = Number(d.cache_processes || 0);
        const e = Number(d.other_processes || 0);
        const t = a + b + c + e;
        return isFinite(t) ? String(t) : '—';
      },
      cfgRows() {
        const c = this.data?.configuration || {};
        const out = [];
        for (const k in c) {
          if (Object.prototype.hasOwnProperty.call(c, k)) out.push({ k, v: String(c[k]) });
        }
        // stable order: by key
        out.sort((a, b) => a.k.localeCompare(b.k));
        return out;
      },
      procPct(v) {
        const d = this.data || {};
        const total =
          Number(d.master_processes || 0) +
          Number(d.worker_processes || 0) +
          Number(d.cache_processes || 0) +
          Number(d.other_processes || 0);
        if (!total) return 0;
        const n = Number(v || 0);
        if (!isFinite(n)) return 0;
        return Math.max(0, Math.min(100, (n / total) * 100));
      },
      // reserved for future: fine-grained stacked bar without overlap
      procGapPx: 0,
      procPctSafe(v, total) {
        if (!total || !isFinite(total)) return 0;
        if (!isFinite(Number(v))) return 0;
        return Math.max(0, Math.min(100, (Number(v) / total) * 100));
      },
      fmtRps(v) {
        const n = Number(v);
        if (!isFinite(n)) return '—';
        return n.toFixed(2);
      },
      pushSeries(rps, conns) {
        const r = Math.max(0, Number(rps) || 0);
        const c = Math.max(0, Number(conns) || 0);
        this.liveRps = r;
        this.rpsHist.push(r);
        this.connHist.push(c);
        if (this.rpsHist.length > 60) this.rpsHist.shift();
        if (this.connHist.length > 60) this.connHist.shift();
      },
      initChart() {
        if (typeof ApexCharts === 'undefined') return;
        if (!this.$refs?.rpsChart) return;
        if (this.chart) return;
        this.chart = new ApexCharts(this.$refs.rpsChart, {
          chart: {
            type: 'area',
            height: 256,
            toolbar: { show: false },
            zoom: { enabled: false },
            animations: { enabled: true, easing: 'linear', speed: 250 },
            background: 'transparent'
          },
          series: [
            { name: 'RPS', data: this.rpsHist },
            { name: 'Connections', data: this.connHist }
          ],
          colors: ['#22d3ee', '#34d399'],
          stroke: { curve: 'smooth', width: [2.6, 2.2] },
          fill: {
            type: 'gradient',
            gradient: {
              shadeIntensity: 0.35,
              opacityFrom: 0.30,
              opacityTo: 0.04,
              stops: [0, 100]
            }
          },
          grid: {
            show: true,
            borderColor: 'rgba(51,65,85,.55)',
            strokeDashArray: 3,
            xaxis: { lines: { show: false } }
          },
          xaxis: { labels: { show: false }, axisTicks: { show: false }, axisBorder: { show: false } },
          yaxis: [
            { labels: { show: false }, min: 0 },
            { opposite: true, labels: { show: false }, min: 0 }
          ],
          tooltip: {
            enabled: true,
            theme: 'dark',
            shared: true,
            intersect: false,
            custom: ({ series, dataPointIndex }) => {
              const rps = (series?.[0]?.[dataPointIndex] ?? 0);
              const conn = (series?.[1]?.[dataPointIndex] ?? 0);
              const rpsTxt = Number(rps || 0).toFixed(2);
              const connTxt = String(Math.round(Number(conn || 0)));
              return `
                <div class="apex-tooltip" style="padding:8px 10px;">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                    <span style="width:8px;height:8px;border-radius:9999px;background:#22d3ee;display:inline-block;"></span>
                    <span style="color:#cbd5e1;font-weight:600;">RPS</span>
                    <span style="margin-left:auto;color:#67e8f9;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;">${rpsTxt}</span>
                  </div>
                  <div style="display:flex;align-items:center;gap:8px;">
                    <span style="width:8px;height:8px;border-radius:9999px;background:#34d399;display:inline-block;"></span>
                    <span style="color:#cbd5e1;font-weight:600;">Connections</span>
                    <span style="margin-left:auto;color:#86efac;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;">${connTxt}</span>
                  </div>
                </div>`;
            }
          },
          dataLabels: { enabled: false },
          markers: { size: 0 },
          legend: { show: false }
        });
        this.chart.render();
      },
      updateChart() {
        if (!this.chart) return;
        this.chart.updateSeries([
          { name: 'RPS', data: this.rpsHist },
          { name: 'Connections', data: this.connHist }
        ], true);
      },
      computeRpsAndUpdate() {
        const now = Date.now();
        const curReq = Number(this.data?.requests ?? 0);
        const curConn = Number(this.data?.active_connections ?? 0);
        if (!isFinite(curReq)) return;

        if (this.prevRequests !== null && this.prevTs > 0) {
          const dt = (now - this.prevTs) / 1000;
          const dr = curReq - this.prevRequests;
          if (dt > 0 && dr >= 0) {
            const rps = dr / dt;
            this.pushSeries(rps, curConn);
            this.updateChart();
          }
        } else {
          // first sample
          this.pushSeries(0, curConn);
          this.updateChart();
        }

        this.prevRequests = curReq;
        this.prevTs = now;
      },
      async load() {
        this.loading = true;
        this.error = '';
        try {
          const [rNginx, rSrv] = await Promise.all([
            fetch('/api/system/nginx-status'),
            fetch('/api/system/server-health')
          ]);
          if (!rNginx.ok) throw new Error(await rNginx.text() || rNginx.statusText);
          this.data = await rNginx.json();
          if (rSrv.ok) this.server = await rSrv.json();

          this.initChart();
          this.computeRpsAndUpdate();
        } catch (e) {
          this.error = e.message || String(e);
          this.data = null;
        } finally {
          this.loading = false;
        }
      },
      start() {
        this.$nextTick(() => this.initChart());
        this.load();
        this.timer = setInterval(() => {
          if (this.auto) this.load();
        }, 4000);
      }
    };
  }
