function iprepApp() {
  return {
    loading: true,
    error: '',
    top: [],
    ti: {},
    cfg: {},
    sample: [],
    async load() {
      this.loading = true; this.error = '';
      try {
        const d = await fetch('/api/ip-reputations').then(r => {
          if (!r.ok) throw new Error(r.statusText);
          return r.json();
        });
        this.top = d.top_offenders || [];
        this.ti = d.threat_intel_rules || {};
        this.cfg = d.threat_intel_config || {};
        this.sample = d.audit_events_sample || [];
      } catch (e) {
        this.error = e.message || String(e);
      } finally {
        this.loading = false;
      }
    }
  };
}
