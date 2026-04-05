function serverHealth() {
  return {
    loading: false,
    auto: true,
    error: '',
    data: null,
    timer: null,
    prev: null,
    prevTs: 0,
    rxRate: 0,
    txRate: 0,
    diskReadRate: 0,
    diskWriteRate: 0,
    cpuHist: Array(60).fill(0),
    netHist: Array(60).fill(0),
    diskHist: Array(60).fill(0),
    charts: { ram: null, swap: null, cpu: null, net: null, disk: null },
    push(arr, v) {
      arr.push(Number(v) || 0);
      if (arr.length > 60) arr.shift();
    },
    pct(v) {
      if (v === undefined || v === null) return '—';
      return Number(v).toFixed(0) + '%';
    },
    bytesLineGiB(used, total) {
      if (!total) return '—';
      const u = Number(used || 0);
      const t = Number(total || 0);
      const free = Math.max(0, t - u);
      return u.toFixed(2) + ' GB used / ' + t.toFixed(2) + ' GB total · ' + free.toFixed(2) + ' GB free';
    },
    memPct(used, total) {
      if (!total) return 0;
      return Math.min(100, (Number(used || 0) / Number(total)) * 100);
    },
    fmtUptime(sec) {
      if (sec === undefined || sec === null) return '—';
      let s = Number(sec);
      const d = Math.floor(s / 86400);
      s -= d * 86400;
      const h = Math.floor(s / 3600);
      s -= h * 3600;
      const m = Math.floor(s / 60);
      const parts = [];
      if (d) parts.push(d + 'd');
      if (h) parts.push(h + 'h');
      parts.push(m + 'm');
      return parts.join(' ');
    },
    fmtBytes(v) {
      const n = Number(v || 0);
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let p = 0;
      let x = n;
      while (x >= 1024 && p < units.length - 1) { x /= 1024; p++; }
      return x.toFixed(p === 0 ? 0 : 2) + ' ' + units[p];
    },
    fmtRate(v) {
      return this.fmtBytes(v || 0) + '/s';
    },
    chartOpts(series, color) {
      return {
        chart: {
          type: 'area',
          height: 96,
          sparkline: { enabled: true },
          animations: { enabled: true, easing: 'linear', speed: 380 },
          toolbar: { show: false },
          zoom: { enabled: false },
          background: 'transparent'
        },
        series: [{ data: series }],
        colors: [color],
        stroke: { width: 2.1, curve: 'smooth' },
        fill: {
          type: 'gradient',
          gradient: {
            shadeIntensity: 0.35,
            inverseColors: false,
            opacityFrom: 0.35,
            opacityTo: 0.02,
            stops: [0, 100]
          }
        },
        grid: {
          show: true,
          borderColor: 'rgba(51,65,85,.55)',
          strokeDashArray: 3,
          xaxis: { lines: { show: false } },
          yaxis: { lines: { show: true } },
          padding: { left: 0, right: 0, top: 2, bottom: 2 }
        },
        tooltip: { enabled: false },
        dataLabels: { enabled: false },
        xaxis: { labels: { show: false }, axisTicks: { show: false }, axisBorder: { show: false } },
        yaxis: { labels: { show: false }, min: 0, forceNiceScale: true },
        markers: { size: 0, hover: { size: 2 } }
      };
    },
    radialOpts(value, color) {
      return {
        chart: {
          type: 'radialBar',
          height: 96,
          sparkline: { enabled: true },
          animations: { enabled: true, easing: 'linear', speed: 380 },
          background: 'transparent'
        },
        series: [Math.max(0, Math.min(100, Number(value || 0)))],
        colors: [color],
        plotOptions: {
          radialBar: {
            hollow: { size: '62%' },
            track: { background: 'rgba(51,65,85,.45)', strokeWidth: '100%' },
            dataLabels: {
              name: { show: false },
              value: {
                show: true,
                offsetY: 4,
                color: '#f8fafc',
                fontSize: '17px',
                fontWeight: 700,
                formatter: (v) => `${Math.round(v)}%`
              }
            }
          }
        },
        stroke: { lineCap: 'round' }
      };
    },
    initCharts() {
      if (typeof ApexCharts === 'undefined') return;
      if (!this.$refs.ramChart || !this.$refs.swapChart || !this.$refs.cpuChart || !this.$refs.netChart || !this.$refs.diskChart) return;
      if (!this.charts.ram) {
        this.charts.ram = new ApexCharts(this.$refs.ramChart, this.radialOpts(this.memPct(this.data?.memory_used_gb, this.data?.memory_total_gb), '#8b5cf6'));
        this.charts.ram.render();
      }
      if (!this.charts.swap) {
        this.charts.swap = new ApexCharts(this.$refs.swapChart, this.radialOpts(this.memPct(this.data?.swap_used_gb, this.data?.swap_total_gb), '#06b6d4'));
        this.charts.swap.render();
      }
      if (!this.charts.cpu) {
        this.charts.cpu = new ApexCharts(this.$refs.cpuChart, this.chartOpts(this.cpuHist, '#8b5cf6'));
        this.charts.cpu.render();
      }
      if (!this.charts.net) {
        this.charts.net = new ApexCharts(this.$refs.netChart, this.chartOpts(this.netHist, '#22d3ee'));
        this.charts.net.render();
      }
      if (!this.charts.disk) {
        this.charts.disk = new ApexCharts(this.$refs.diskChart, this.chartOpts(this.diskHist, '#fb7185'));
        this.charts.disk.render();
      }
    },
    updateCharts() {
      if (!this.charts.ram || !this.charts.swap || !this.charts.cpu || !this.charts.net || !this.charts.disk) return;
      this.charts.ram.updateSeries([this.memPct(this.data?.memory_used_gb, this.data?.memory_total_gb)], true);
      this.charts.swap.updateSeries([this.memPct(this.data?.swap_used_gb, this.data?.swap_total_gb)], true);
      this.charts.cpu.updateSeries([{ data: [...this.cpuHist] }], true);
      this.charts.net.updateSeries([{ data: [...this.netHist] }], true);
      this.charts.disk.updateSeries([{ data: [...this.diskHist] }], true);
    },
    updateRates(next) {
      const now = Date.now();
      if (!this.prev || !this.prevTs) {
        this.prev = next;
        this.prevTs = now;
        this.push(this.cpuHist, next.cpu_usage_percent || 0);
        this.push(this.netHist, 0);
        this.push(this.diskHist, 0);
        this.updateCharts();
        return;
      }
      const dt = Math.max(1, (now - this.prevTs) / 1000);
      this.rxRate = Math.max(0, (Number(next.network_rx_bytes || 0) - Number(this.prev.network_rx_bytes || 0)) / dt);
      this.txRate = Math.max(0, (Number(next.network_tx_bytes || 0) - Number(this.prev.network_tx_bytes || 0)) / dt);
      this.diskReadRate = Math.max(0, (Number(next.disk_read_bytes || 0) - Number(this.prev.disk_read_bytes || 0)) / dt);
      this.diskWriteRate = Math.max(0, (Number(next.disk_write_bytes || 0) - Number(this.prev.disk_write_bytes || 0)) / dt);
      this.push(this.cpuHist, next.cpu_usage_percent || 0);
      this.push(this.netHist, this.rxRate + this.txRate);
      this.push(this.diskHist, this.diskReadRate + this.diskWriteRate);
      this.prev = next;
      this.prevTs = now;
      this.updateCharts();
    },
    async load() {
      this.loading = true;
      this.error = '';
      try {
        const r = await fetch('/api/system/server-health');
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const payload = await r.json();
        this.data = payload || {};
        this.updateRates(this.data);
      } catch (e) {
        this.error = e.message || String(e);
      } finally {
        this.loading = false;
      }
    },
    start() {
      this.$nextTick(() => this.initCharts());
      this.load();
      this.timer = setInterval(() => {
        if (this.auto) this.load();
      }, 2000);
    }
  };
}
