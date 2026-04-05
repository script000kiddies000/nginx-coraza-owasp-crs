function threatIntelApp() {
  return {
    loading: true,
    formReady: false,
    saving: false,
    syncing: false,
    feedsSaving: false,
    errorBanner: '',
    okBanner: '',
    paths: { ip_rules: '', feeds: '' },
    ipRules: {},
    feedsFile: {},
    feedsList: [],
    feedsEnabled: true,
    feedsAction: 'block',
    feedsError: '',
    feedModalOpen: false,
    feedEditingIdx: -1,
    feedForm: { name: '', type: 'spamhaus_drop', url: '', enabled: true, api_key: '' },
    whitelistText: '',
    form: {
      enabled: true,
      update_interval: 24,
      block_score: 90,
      whitelist_ips: [],
      last_sync: '',
      ip_count: 0
    },
    parseWhitelist(s) {
      return String(s || '').split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
    },
    whitelistToText(arr) {
      return Array.isArray(arr) ? arr.join('\n') : '';
    },
    async load() {
      this.loading = true;
      this.errorBanner = '';
      try {
        const r = await fetch('/api/threat-intel/status');
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const data = await r.json();
        const cfg = data.config || {};
        this.form = {
          enabled: !!cfg.enabled,
          update_interval: cfg.update_interval || 24,
          block_score: cfg.block_score ?? 90,
          whitelist_ips: cfg.whitelist_ips || [],
          last_sync: cfg.last_sync || '',
          ip_count: cfg.ip_count ?? 0
        };
        this.whitelistText = this.whitelistToText(cfg.whitelist_ips);
        this.ipRules = data.ip_rules || {};
        this.paths = data.paths || {};
        this.feedsError = data.feeds_error || '';
        this.feedsFile = (data.feeds_file && typeof data.feeds_file === 'object') ? data.feeds_file : {};
        this.feedsList = Array.isArray(this.feedsFile.feeds) ? this.feedsFile.feeds.map(f => ({ ...f })) : [];
        this.feedsEnabled = this.feedsFile.enabled !== undefined ? !!this.feedsFile.enabled : true;
        this.feedsAction = this.feedsFile.action || 'block';
        this.formReady = true;
      } catch (e) {
        this.errorBanner = e.message || String(e);
        this.formReady = false;
      } finally {
        this.loading = false;
      }
    },
    async saveConfig() {
      this.saving = true;
      this.errorBanner = '';
      this.okBanner = '';
      const body = {
        enabled: this.form.enabled,
        update_interval: Number(this.form.update_interval),
        block_score: Number(this.form.block_score),
        whitelist_ips: this.parseWhitelist(this.whitelistText),
        last_sync: this.form.last_sync,
        ip_count: this.form.ip_count
      };
      try {
        const r = await fetch('/api/threat-intel/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const saved = await r.json();
        this.form.last_sync = saved.last_sync || this.form.last_sync;
        this.form.ip_count = saved.ip_count ?? this.form.ip_count;
        this.okBanner = 'Pengaturan disimpan.';
        setTimeout(() => { this.okBanner = ''; }, 4000);
      } catch (e) {
        this.errorBanner = e.message || String(e);
      } finally {
        this.saving = false;
      }
    },
    async syncNow() {
      this.syncing = true;
      this.errorBanner = '';
      this.okBanner = '';
      try {
        const r = await fetch('/api/threat-intel/sync', { method: 'POST' });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        const data = await r.json();
        const msg = (data.message || 'OK') + (data.last_sync ? ' — ' + data.last_sync : '');
        this.okBanner = msg;
        await this.load();
      } catch (e) {
        this.errorBanner = e.message || String(e);
      } finally {
        this.syncing = false;
      }
    },
    resetFeedForm() {
      this.feedForm = { name: '', type: 'spamhaus_drop', url: '', enabled: true, api_key: '' };
    },
    openAddFeed() {
      this.feedEditingIdx = -1;
      this.resetFeedForm();
      this.feedModalOpen = true;
    },
    openEditFeed(idx) {
      const f = this.feedsList[idx];
      if (!f) return;
      this.feedEditingIdx = idx;
      this.feedForm = {
        name: f.name || '',
        type: f.type || 'spamhaus_drop',
        url: f.url || '',
        enabled: !!f.enabled,
        api_key: f.api_key || ''
      };
      this.feedModalOpen = true;
    },
    closeFeedModal() {
      this.feedModalOpen = false;
    },
    applyFeedForm() {
      const item = {
        name: String(this.feedForm.name || '').trim(),
        type: String(this.feedForm.type || '').trim(),
        url: String(this.feedForm.url || '').trim(),
        enabled: !!this.feedForm.enabled,
        api_key: String(this.feedForm.api_key || '').trim()
      };
      if (!item.name || !item.type || !item.url) {
        this.errorBanner = 'Nama, tipe, dan URL feed wajib diisi.';
        return;
      }
      if (this.feedEditingIdx === -1) this.feedsList.push(item);
      else this.feedsList.splice(this.feedEditingIdx, 1, item);
      this.closeFeedModal();
    },
    toggleFeed(idx) {
      if (!this.feedsList[idx]) return;
      this.feedsList[idx].enabled = !this.feedsList[idx].enabled;
    },
    deleteFeed(idx) {
      if (!this.feedsList[idx]) return;
      this.feedsList.splice(idx, 1);
    },
    async saveFeedsConfig() {
      this.feedsSaving = true;
      this.errorBanner = '';
      this.okBanner = '';
      try {
        const r = await fetch('/api/threat-intel/feeds', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabled: !!this.feedsEnabled,
            action: this.feedsAction || 'block',
            feeds: this.feedsList
          })
        });
        if (!r.ok) throw new Error(await r.text() || r.statusText);
        this.okBanner = 'Feed configuration berhasil disimpan.';
        await this.load();
      } catch (e) {
        this.errorBanner = e.message || String(e);
      } finally {
        this.feedsSaving = false;
      }
    }
  };
}
