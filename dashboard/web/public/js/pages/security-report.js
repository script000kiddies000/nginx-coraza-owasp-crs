function secReportApp() {
  return {
    stats: {},
    events: [],
    async load() {
      try {
        const [s, ev] = await Promise.all([
          fetch('/api/stats').then(r => r.json()),
          fetch('/api/security-events').then(r => r.json())
        ]);
        this.stats = s;
        this.events = Array.isArray(ev) ? ev : [];
      } catch (_) {}
    }
  };
}
