function settingsPageApp() {
  return {
    // ── Tab state ──────────────────────────────────────────────────────────
    activeTab: 'general',

    // ── Real IP ───────────────────────────────────────────────────────────
    saving: false,
    statusText: '',
    headerChoice: 'X-Forwarded-For',
    headerCustom: '',
    cfgTrusted: [],
    trustedProxiesInput: '127.0.0.1, ::1',
    knownHeaders: ['X-Forwarded-For','CF-Connecting-IP','X-Real-IP'],

    auditLogFormat: 'json',
    auditLogSaving: false,
    auditLogStatus: '',

    // ── Users (only executed when server rendered the admin section) ───────
    usersLoaded: false,
    usersLoading: false,
    users: [],
    showAdd: false,
    newUser: { username: '', password: '', role: 'operator' },
    msgOk: '',
    msgErr: '',
    pwUser: null,
    pwNew: '',

    async init() {
      // Load Real IP settings
      this.statusText = 'Loading…';
      try {
        const r = await fetch('/api/realip/settings');
        const d = await r.json();
        const header = (d.header || '').trim();
        const trusted = Array.isArray(d.trusted_proxies) ? d.trusted_proxies : [];
        this.cfgTrusted = trusted;
        this.trustedProxiesInput = trusted.length ? trusted.join(', ') : '127.0.0.1, ::1';
        if (this.knownHeaders.includes(header)) {
          this.headerChoice = header;
          this.headerCustom = '';
        } else if (header) {
          this.headerChoice = '__custom__';
          this.headerCustom = header;
        } else {
          this.headerChoice = 'X-Forwarded-For';
          this.headerCustom = '';
        }
        this.statusText = '';
      } catch (e) {
        this.statusText = 'Failed to load';
      }

      try {
        const ar = await fetch('/api/settings/audit-log-format');
        if (ar.ok) {
          const ad = await ar.json();
          if (ad.format === 'native' || ad.format === 'json') {
            this.auditLogFormat = ad.format;
          }
        }
        this.auditLogStatus = '';
      } catch (_) {}

      // Auto-switch to users tab if URL hash requests it
      if (window.location.hash === '#users') {
        this.activeTab = 'users';
        await this.loadUsers();
      }
    },

    computedHeader() {
      if (this.headerChoice === '__custom__') {
        return (this.headerCustom || '').trim();
      }
      return this.headerChoice;
    },

    async saveRealIP() {
      const header = this.computedHeader();
      if (!header) {
        this.statusText = 'Header is required';
        return;
      }
      this.saving = true;
      this.statusText = 'Saving…';
      try {
        const tp = (this.trustedProxiesInput || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
        const trustedProxies = tp.length ? tp : ['127.0.0.1', '::1'];
        const body = {
          enabled: true,
          header,
          trusted_proxies: trustedProxies,
        };
        const r = await fetch('/api/realip/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const d = await r.json();
        if (!r.ok) throw new Error(d?.error || 'Save failed');
        this.statusText = 'Saved';
      } catch (e) {
        this.statusText = e.message || 'Save failed';
      } finally {
        this.saving = false;
        setTimeout(() => { this.statusText = ''; }, 1600);
      }
    },

    async saveAuditLogFormat() {
      this.auditLogSaving = true;
      this.auditLogStatus = 'Menyimpan…';
      try {
        const r = await fetch('/api/settings/audit-log-format', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ format: this.auditLogFormat }),
        });
        const t = await r.text();
        let j = {};
        try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t || 'Gagal simpan');
        this.auditLogStatus = 'Tersimpan. Nginx di-reload; event baru memakai format ini.';
      } catch (e) {
        this.auditLogStatus = e.message || 'Gagal';
      } finally {
        this.auditLogSaving = false;
        setTimeout(() => { if (this.auditLogStatus.startsWith('Tersimpan')) this.auditLogStatus = ''; }, 5000);
      }
    },

    // ── User management (server already verified admin; no /api/me needed) ──
    async loadUsers() {
      if (this.usersLoaded) return;
      this.msgErr = '';
      this.usersLoading = true;
      const r = await fetch('/api/users');
      if (!r.ok) {
        this.msgErr = await r.text();
        this.usersLoading = false;
        return;
      }
      this.users = await r.json();
      this.usersLoaded = true;
      this.usersLoading = false;
    },

    async createUser() {
      this.msgOk = '';
      this.msgErr = '';
      const r = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.newUser)
      });
      const t = await r.text();
      let j = {};
      try { j = JSON.parse(t); } catch (_) {}
      if (!r.ok) {
        this.msgErr = j.error || t;
        return;
      }
      this.msgOk = 'Pengguna dibuat.';
      this.newUser = { username: '', password: '', role: 'operator' };
      this.showAdd = false;
      await this._reloadUsers();
    },

    async removeUser(name) {
      if (!confirm('Hapus pengguna ' + name + '?')) return;
      this.msgOk = '';
      this.msgErr = '';
      const r = await fetch('/api/users/' + encodeURIComponent(name), { method: 'DELETE' });
      const t = await r.text();
      let j = {};
      try { j = JSON.parse(t); } catch (_) {}
      if (!r.ok) {
        this.msgErr = j.error || t;
        return;
      }
      this.msgOk = 'Pengguna dihapus.';
      await this._reloadUsers();
    },

    openPw(name) {
      this.pwUser = name;
      this.pwNew = '';
    },

    async savePw() {
      const r = await fetch('/api/users/' + encodeURIComponent(this.pwUser) + '/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: this.pwNew })
      });
      const t = await r.text();
      let j = {};
      try { j = JSON.parse(t); } catch (_) {}
      if (!r.ok) {
        this.msgErr = j.error || t;
        return;
      }
      this.msgOk = 'Password diperbarui.';
      this.pwUser = null;
    },

    async _reloadUsers() {
      this.usersLoading = true;
      const r = await fetch('/api/users');
      if (!r.ok) {
        this.usersLoading = false;
        return;
      }
      this.users = await r.json();
      this.usersLoading = false;
    },
  };
}
