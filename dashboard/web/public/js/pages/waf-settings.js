function wafSettingsApp() {
  return {
    loading: true,
    saving: false,
    okMsg: '',
    errMsg: '',
    form: { mode: 'On', paranoia_level: 1, anomaly_inbound: 5, preset: 'Auto' },
    modes: [
      { v: 'On', label: 'On', hint: 'Blokir pelanggaran' },
      { v: 'DetectionOnly', label: 'Detection only', hint: 'Log saja' },
      { v: 'Off', label: 'Off', hint: 'WAF mati' }
    ],

    // Applies a safe preset mapping so users don't need to guess threshold values.
    // Note: mapping is heuristic; always start from Auto/Balance for new apps.
    applyPreset(preset) {
      const p = (preset || '').toString();
      if (p === 'Safe') {
        this.form.paranoia_level = 1;
        this.form.anomaly_inbound = 7;
        return;
      }
      if (p === 'Balance') {
        this.form.paranoia_level = 1;
        this.form.anomaly_inbound = 5;
        return;
      }
      if (p === 'Strict') {
        this.form.paranoia_level = 2;
        this.form.anomaly_inbound = 4;
        return;
      }
      if (p === 'Aggressive') {
        this.form.paranoia_level = 4;
        this.form.anomaly_inbound = 3;
        return;
      }
      if (p === 'Auto') {
        // Auto mapping depends on SecRuleEngine mode.
        if (this.form.mode === 'DetectionOnly') {
          this.form.paranoia_level = 1;
          this.form.anomaly_inbound = 7;
        } else if (this.form.mode === 'Off') {
          // Off: threshold value doesn't really matter; keep a sane baseline.
          this.form.paranoia_level = 1;
          this.form.anomaly_inbound = 5;
        } else {
          // On (blocking)
          this.form.paranoia_level = 1;
          this.form.anomaly_inbound = 5;
        }
        return;
      }
      // Custom: do nothing.
    },

    onPresetChange() {
      if (this.form.preset !== 'Custom') {
        this.applyPreset(this.form.preset);
      }
    },

    onModeChanged() {
      if (this.form.preset === 'Auto') {
        this.applyPreset('Auto');
      }
    },

    setManualCustom() {
      if (this.form.preset !== 'Custom') {
        this.form.preset = 'Custom';
      }
    },

    async load() {
      this.loading = true;
      this.okMsg = '';
      this.errMsg = '';
      try {
        const r = await fetch('/api/waf/settings');
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const d = await r.json();
        this.form.mode = d.mode || 'On';
        this.form.paranoia_level = Number(d.paranoia_level) || 1;
        this.form.anomaly_inbound = Number(d.anomaly_inbound) || 5;

        // Detect current values as one of presets, otherwise fallback to Custom.
        const pl = this.form.paranoia_level;
        const th = this.form.anomaly_inbound;
        if (this.form.mode === 'On' && pl === 1 && th === 5) {
          this.form.preset = 'Auto';
        } else if (this.form.mode === 'DetectionOnly' && pl === 1 && th === 7) {
          this.form.preset = 'Auto';
        } else if (pl === 1 && th === 7) {
          this.form.preset = 'Safe';
        } else if (pl === 1 && th === 5) {
          this.form.preset = 'Balance';
        } else if (pl === 2 && th === 4) {
          this.form.preset = 'Strict';
        } else if (pl === 4 && th === 3) {
          this.form.preset = 'Aggressive';
        } else {
          this.form.preset = 'Custom';
        }
      } catch (e) {
        this.errMsg = e.message || String(e);
      } finally {
        this.loading = false;
      }
    },
    async save() {
      this.saving = true;
      this.okMsg = '';
      this.errMsg = '';
      try {
        const r = await fetch('/api/waf/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          // Backend only needs (mode, paranoia_level, anomaly_inbound).
          // Extra fields like `preset` are harmless (ignored by Go json decoder).
          body: JSON.stringify(this.form)
        });
        const t = await r.text();
        let j = {};
        try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t || r.statusText);
        this.okMsg = 'Pengaturan disimpan dan nginx dimuat ulang.';
      } catch (e) {
        this.errMsg = e.message || String(e);
      } finally {
        this.saving = false;
      }
    }
  };
}
