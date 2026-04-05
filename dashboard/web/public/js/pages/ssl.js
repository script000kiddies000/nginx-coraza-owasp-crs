function tlsCertsApp() {
  return {
    certificates: [],
    summary: {},
    meta: { ssl_dir: '', acme_webroot: '' },
    msgOk: '',
    msgErr: '',
    showModalLE: false,
    showModalCustom: false,
    showModalSelf: false,
    busy: false,
    leForm: { domain: '', email: '', staging: false },
    custForm: { domain: '', cert_pem: '', key_pem: '', chain_pem: '' },
    selfForm: { domain: '', days: 365 },

    get leList() {
      return (this.certificates || []).filter(c => c.source === 'letsencrypt');
    },
    get customList() {
      return (this.certificates || []).filter(c => c.source !== 'letsencrypt');
    },

    fmtDate(iso) {
      if (!iso) return '—';
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return '—';
      return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    },
    fmtDays(d) {
      if (d === null || d === undefined) return '—';
      const n = Number(d);
      if (Number.isNaN(n)) return '—';
      if (n < 0) return 'expired';
      return 'in ' + n + ' d';
    },
    statusClass(status) {
      const s = String(status || '').toLowerCase();
      if (s === 'active') return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/25';
      if (s === 'error') return 'text-rose-400 bg-rose-500/10 border-rose-500/25';
      return 'text-gray-400 bg-gray-500/10 border-gray-500/25';
    },

    openModalLE() {
      this.msgErr = '';
      this.leForm = { domain: '', email: '', staging: false };
      this.showModalSelf = false;
      this.showModalCustom = false;
      this.showModalLE = true;
    },

    openModalCustom() {
      this.msgErr = '';
      this.custForm = { domain: '', cert_pem: '', key_pem: '', chain_pem: '' };
      this.showModalSelf = false;
      this.showModalLE = false;
      this.showModalCustom = true;
    },

    openModalSelf() {
      this.msgErr = '';
      this.selfForm = { domain: '', days: 365 };
      this.showModalLE = false;
      this.showModalCustom = false;
      this.showModalSelf = true;
    },

    readFileTo(e, field) {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => { this.custForm[field] = (r.result || '').toString(); };
      r.readAsText(f);
    },

    async load() {
      this.msgErr = '';
      const r = await fetch('/api/tls/certificates');
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'load failed');
      this.certificates = Array.isArray(d.certificates) ? d.certificates : [];
      this.summary = d.summary || {};
      this.meta = { ssl_dir: d.ssl_dir || '', acme_webroot: d.acme_webroot || '' };
    },

    async init() {
      try { await this.load(); } catch (e) { this.msgErr = e.message || String(e); }
    },

    async submitLE() {
      this.busy = true;
      this.msgOk = '';
      this.msgErr = '';
      try {
        const r = await fetch('/api/tls/certificates/letsencrypt', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            domain: (this.leForm.domain || '').trim(),
            email: (this.leForm.email || '').trim(),
            staging: !!this.leForm.staging
          })
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Certificate issued for ' + (j.domain || this.leForm.domain);
        this.showModalLE = false;
        await this.load();
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.busy = false;
      }
    },

    async submitCustom() {
      this.busy = true;
      this.msgOk = '';
      this.msgErr = '';
      try {
        const r = await fetch('/api/tls/certificates/custom', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            domain: (this.custForm.domain || '').trim(),
            cert_pem: this.custForm.cert_pem || '',
            key_pem: this.custForm.key_pem || '',
            chain_pem: this.custForm.chain_pem || ''
          })
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Custom certificate saved' + (j.domain ? (' for ' + j.domain) : '');
        this.showModalCustom = false;
        await this.load();
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.busy = false;
      }
    },

    async submitSelfSigned() {
      this.busy = true;
      this.msgOk = '';
      this.msgErr = '';
      try {
        const r = await fetch('/api/tls/certificates/self-signed', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            domain: (this.selfForm.domain || '').trim(),
            days: Number(this.selfForm.days || 365)
          })
        });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Self-signed certificate generated' + (j.domain ? (' for ' + j.domain) : '');
        this.showModalSelf = false;
        await this.load();
      } catch (e) {
        this.msgErr = e.message || String(e);
      } finally {
        this.busy = false;
      }
    },

    async removeCert(c) {
      if (!c || !c.id) return;
      const used = (c.used_by && c.used_by.length) ? ('\n\nUsed by: ' + c.used_by.join(', ')) : '';
      if (!confirm('Delete certificate for "' + c.domain + '"?' + used)) return;
      this.msgErr = '';
      try {
        const r = await fetch('/api/tls/certificates/' + encodeURIComponent(c.id), { method: 'DELETE' });
        const t = await r.text();
        let j = {}; try { j = JSON.parse(t); } catch (_) {}
        if (r.status === 409) {
          this.msgErr = j.error || 'Certificate is in use by a host. Unassign it in Hosts first.';
          return;
        }
        if (!r.ok) throw new Error(j.error || t);
        this.msgOk = 'Certificate removed';
        await this.load();
      } catch (e) {
        this.msgErr = e.message || String(e);
      }
    }
  };
}
