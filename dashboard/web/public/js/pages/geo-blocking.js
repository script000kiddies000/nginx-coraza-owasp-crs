(function () {
  // ISO 3166-1 alpha-2 resmi (+ XK sering dipakai database GeoIP). Nama diisi via Intl.DisplayNames saat runtime.
  const ISO2_ALL = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK'.split(/\s+/);

  function regionName(code) {
    const c = String(code || '').trim().toUpperCase();
    if (!c || c.length !== 2) return c;
    try {
      if (typeof Intl !== 'undefined' && Intl.DisplayNames) {
        const dn = new Intl.DisplayNames(['en'], { type: 'region' });
        const n = dn.of(c);
        if (n && n !== c) return n;
      }
    } catch (_) {}
    return c;
  }

  function flagEmoji(iso2) {
    const u = String(iso2 || '').toUpperCase();
    if (u.length !== 2 || u[0] < 'A' || u[0] > 'Z' || u[1] < 'A' || u[1] > 'Z') return '🏳️';
    const A = 0x1F1E6;
    return String.fromCodePoint(A + (u.charCodeAt(0) - 65), A + (u.charCodeAt(1) - 65));
  }

  window.geoApp = function geoApp() {
    return {
      checking: true,
      isAdmin: false,
      catalog: [],
      query: '',
      suggestions: [],
      suggestOpen: false,
      hi: 0,
      blocked: [],
      codesText: '',
      saving: false,
      msgOk: '',
      msgErr: '',
      flagEmoji,
      get addingDisabled() {
        const q = this.queryTrim();
        if (!q) return true;
        const exact = this.resolveCode(q);
        if (exact && !this.isBlocked(exact)) return false;
        return !this.suggestions.length;
      },
      queryTrim() {
        return String(this.query || '').trim();
      },
      isBlocked(code) {
        const c = String(code || '').toUpperCase();
        return this.blocked.some((x) => x.code === c);
      },
      blockedSorted() {
        return [...this.blocked].sort((a, b) => a.name.localeCompare(b.name, 'en'));
      },
      buildCatalog() {
        this.catalog = ISO2_ALL.map((code) => ({ code, name: regionName(code) }));
      },
      syncCodesText() {
        this.codesText = this.blocked.map((x) => x.code).join(', ');
      },
      async init() {
        this.buildCatalog();
        try {
          const me = await fetch('/api/me').then((r) => r.json());
          this.isAdmin = me.role === 'admin';
        } catch (_) {}
        await this.load();
        this.checking = false;
      },
      async load() {
        const r = await fetch('/api/security/geo-block');
        if (!r.ok) return;
        const d = await r.json();
        const codes = Array.isArray(d.countries) ? d.countries : [];
        this.blocked = [];
        for (const raw of codes) {
          const code = String(raw || '').trim().toUpperCase();
          if (code.length !== 2) continue;
          if (this.isBlocked(code)) continue;
          this.blocked.push({ code, name: regionName(code) });
        }
        this.syncCodesText();
        this.closeSuggest();
      },
      onQueryInput() {
        this.refreshSuggestions();
        this.suggestOpen = this.queryTrim().length > 0;
        this.hi = 0;
      },
      closeSuggest() {
        this.suggestOpen = false;
        this.hi = 0;
      },
      refreshSuggestions() {
        const q = this.queryTrim().toLowerCase();
        if (!q) {
          this.suggestions = [];
          return;
        }
        const out = [];
        for (const row of this.catalog) {
          if (this.isBlocked(row.code)) continue;
          const codeL = row.code.toLowerCase();
          const nameL = row.name.toLowerCase();
          if (codeL === q || nameL.includes(q) || codeL.startsWith(q)) {
            out.push(row);
            if (out.length >= 40) break;
          }
        }
        out.sort((a, b) => {
          const qa = a.code.toLowerCase() === q ? 0 : a.name.toLowerCase().startsWith(q) ? 1 : 2;
          const qb = b.code.toLowerCase() === q ? 0 : b.name.toLowerCase().startsWith(q) ? 1 : 2;
          if (qa !== qb) return qa - qb;
          return a.name.localeCompare(b.name);
        });
        this.suggestions = out.slice(0, 10);
        if (this.hi >= this.suggestions.length) this.hi = Math.max(0, this.suggestions.length - 1);
      },
      resolveCode(qraw) {
        const q = String(qraw || '').trim().toUpperCase();
        if (q.length === 2 && ISO2_ALL.includes(q)) return q;
        return '';
      },
      pickSuggestion(s) {
        if (!s || this.isBlocked(s.code)) return;
        this.blocked.push({ code: s.code, name: s.name });
        this.query = '';
        this.closeSuggest();
        this.syncCodesText();
      },
      moveHi(delta) {
        if (!this.suggestions.length) return;
        this.hi = (this.hi + delta + this.suggestions.length) % this.suggestions.length;
      },
      onEnterSuggest() {
        if (this.suggestOpen && this.suggestions[this.hi]) {
          this.pickSuggestion(this.suggestions[this.hi]);
          return;
        }
        this.addFromQuery();
      },
      addFromQuery() {
        if (!this.isAdmin) return;
        const q = this.queryTrim();
        if (!q) return;
        const direct = this.resolveCode(q);
        if (direct && !this.isBlocked(direct)) {
          this.blocked.push({ code: direct, name: regionName(direct) });
          this.query = '';
          this.closeSuggest();
          this.syncCodesText();
          return;
        }
        this.refreshSuggestions();
        if (this.suggestions.length === 1 && !this.isBlocked(this.suggestions[0].code)) {
          this.pickSuggestion(this.suggestions[0]);
        }
      },
      applyRawText() {
        if (!this.isAdmin) return;
        const parts = this.codesText.split(/[\s,;]+/).map((s) => s.trim().toUpperCase()).filter(Boolean);
        const next = [];
        const seen = new Set();
        for (const p of parts) {
          if (p.length !== 2 || p[0] < 'A' || p[0] > 'Z' || p[1] < 'A' || p[1] > 'Z') continue;
          if (seen.has(p)) continue;
          seen.add(p);
          next.push({ code: p, name: regionName(p) });
        }
        this.blocked = next;
        this.syncCodesText();
        this.msgErr = '';
      },
      removeByCode(code) {
        if (!this.isAdmin) return;
        const c = String(code || '').toUpperCase();
        const i = this.blocked.findIndex((x) => x.code === c);
        if (i >= 0) this.blocked.splice(i, 1);
        this.syncCodesText();
      },
      async save() {
        if (!this.isAdmin) return;
        this.saving = true;
        this.msgOk = '';
        this.msgErr = '';
        try {
          const countries = this.blocked.map((x) => x.code);
          const r = await fetch('/api/security/geo-block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ countries }),
          });
          const t = await r.text();
          let j = {};
          try {
            j = JSON.parse(t);
          } catch (_) {}
          if (!r.ok) throw new Error(j.error || t);
          this.msgOk = 'Map GeoIP diperbarui dan nginx reload.';
          await this.load();
        } catch (e) {
          this.msgErr = e.message || String(e);
        } finally {
          this.saving = false;
        }
      },
    };
  };
})();
