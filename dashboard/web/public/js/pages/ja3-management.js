function jaApp() {
  return {
    saving: false,
    msgOk: '',
    msgErr: '',
    ja3: { enabled: true, entries: [], newName: '', newHash: '' },
    ja4: { enabled: true, entries: [], newName: '', newHash: '' },
    mapFile: null,
    mapFileJA4: null,
    async init() {
      await this.load();
      this.$nextTick(() => { if (window.lucide) lucide.createIcons(); });
    },
    async load() {
      this.msgOk = ''; this.msgErr = '';
      try {
        const r = await fetch('/api/ja3/config');
        const d = await r.json();
        const cfg = d.config || {};
        this.ja3.enabled = (cfg.enabled !== undefined) ? !!cfg.enabled : true;
        this.ja4.enabled = (cfg.ja4_enabled !== undefined) ? !!cfg.ja4_enabled : true;

        const ja3Entries = Array.isArray(cfg.entries) ? cfg.entries : (Array.isArray(cfg.hashes) ? cfg.hashes.map(h => ({ name: 'JA3 ' + String(h).slice(0, 8), hash: h, enabled: true, action: 'block' })) : []);
        const ja4Entries = Array.isArray(cfg.ja4_entries) ? cfg.ja4_entries : (Array.isArray(cfg.ja4_hashes) ? cfg.ja4_hashes.map(h => ({ name: 'JA4 ' + String(h).slice(0, 8), hash: h, enabled: true, action: 'block' })) : []);
        this.ja3.entries = ja3Entries.slice();
        this.ja4.entries = ja4Entries.slice();

        this.mapFile = d.map_file || null;
        this.mapFileJA4 = d.map_file_ja4 || null;
      } catch (e) {
        this.msgErr = e.message || String(e);
      }
    },
    addJA3() {
      const v = (this.ja3.newHash || '').trim().toLowerCase();
      const n = (this.ja3.newName || '').trim();
      if (!/^[a-f0-9]{32}$/.test(v)) {
        this.msgErr = 'Hash JA3 harus 32 karakter hex (a-f0-9).';
        return;
      }
      if (this.ja3.entries.some(e => e.hash === v)) {
        this.msgErr = 'Hash JA3 sudah ada.';
        return;
      }
      this.ja3.entries.push({
        name: n || ('JA3 ' + v.slice(0, 8)),
        hash: v,
        enabled: true,
        action: 'block'
      });
      this.ja3.entries.sort((a, b) => a.hash.localeCompare(b.hash));
      this.ja3.newName = '';
      this.ja3.newHash = '';
      this.msgErr = '';
    },
    removeJA3(h) {
      this.ja3.entries = this.ja3.entries.filter(x => x.hash !== h);
    },
    addJA4() {
      const v = (this.ja4.newHash || '').trim().toLowerCase();
      const n = (this.ja4.newName || '').trim();
      if (!/^[a-f0-9]{32}$/.test(v)) {
        this.msgErr = 'Hash JA4 harus 32 karakter hex (a-f0-9).';
        return;
      }
      if (this.ja4.entries.some(e => e.hash === v)) {
        this.msgErr = 'Hash JA4 sudah ada.';
        return;
      }
      this.ja4.entries.push({
        name: n || ('JA4 ' + v.slice(0, 8)),
        hash: v,
        enabled: true,
        action: 'block'
      });
      this.ja4.entries.sort((a, b) => a.hash.localeCompare(b.hash));
      this.ja4.newName = '';
      this.ja4.newHash = '';
      this.msgErr = '';
    },
    removeJA4(h) {
      this.ja4.entries = this.ja4.entries.filter(x => x.hash !== h);
    },
    async save() {
      this.saving = true; this.msgOk = ''; this.msgErr = '';
      try {
        const body = {
          enabled: !!this.ja3.enabled,
          entries: this.ja3.entries,
          ja4_enabled: !!this.ja4.enabled,
          ja4_entries: this.ja4.entries
        };
        const r = await fetch('/api/ja3/apply', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Konfigurasi JA3/JA4 tersimpan dan nginx dimuat ulang.';
        await this.load();
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.saving = false;
      }
    }
  };
}
