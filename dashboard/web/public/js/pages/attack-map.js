function attackMapApp() {
  return {
    demo: false,
    label: '',
    totalToday: 0,
    categories: [],
    points: [],
    allLogs: [],
    feed: [],
    originLat: -2.5,
    originLon: 118,
    loopTimer: null,
    clockTimer: null,
    catMax: 1,
    clockTime: '00:00:00',
    clockDate: '—',
    map: null,
    layerGroup: null,
    rocketTimer: null,
    rocketAnims: [],
    globeTimer: null,
    globeArcs: [],
    viewMode: 'plane',
    globeCtx: null,
    globeW: 0,
    globeH: 0,
    globeR: 0,
    globeLandFeatures: null,
    globeRotateLon: 0,
    globeRotateLat: 0,
    globeDragging: false,
    globeDragStartX: 0,
    globeDragStartY: 0,
    globeDragStartLon: 0,
    globeDragStartLat: 0,
    globe3d: null,

    barPct(count) {
      const m = this.catMax || 1;
      return Math.min(100, Math.round((count / m) * 100));
    },
    barColorClass(i) {
      const palette = ['bg-cyan-500/70', 'bg-sky-500/70', 'bg-orange-500/70', 'bg-amber-500/70', 'bg-emerald-500/70'];
      return palette[i % palette.length];
    },

    fmtTime(ts) {
      try {
        const d = new Date(ts);
        return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
      } catch (_) { return ts; }
    },

    colorForCountry(code) {
      // Deterministic per-country color (same country always same hue).
      const palette = [
        '#fb923c', '#38bdf8', '#a78bfa', '#34d399', '#f472b6',
        '#f59e0b', '#22d3ee', '#60a5fa', '#f97316', '#10b981',
        '#e879f9', '#f43f5e', '#84cc16', '#facc15', '#06b6d4',
      ];
      const s = String(code || 'ZZ');
      let h = 0;
      for (let i = 0; i < s.length; i++) h = ((h << 5) - h) + s.charCodeAt(i);
      const idx = Math.abs(h) % palette.length;
      return palette[idx];
    },

    /** ISO 3166-1 alpha-2 (e.g. US, ID) → English country name; falls back to code. */
    displayCountryName(code) {
      const c = String(code || '').trim().toUpperCase();
      if (!c || c === 'ZZ' || c === '—') return 'Unknown';
      try {
        if (typeof Intl !== 'undefined' && Intl.DisplayNames) {
          const dn = new Intl.DisplayNames(['en'], { type: 'region' });
          const name = dn.of(c);
          if (name && name !== c) return name;
        }
      } catch (_) { /* invalid region code */ }
      return c;
    },

    approxDistanceKm(a, b) {
      const toRad = (d) => d * Math.PI / 180;
      const R = 6371;
      const dLat = toRad(b[0] - a[0]);
      const dLon = toRad(b[1] - a[1]);
      const lat1 = toRad(a[0]);
      const lat2 = toRad(b[0]);
      const x = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
      return 2 * R * Math.asin(Math.sqrt(x));
    },

    hexToRgb(hex) {
      const raw = String(hex || '').replace('#', '');
      const val = raw.length === 3
        ? raw.split('').map((c) => c + c).join('')
        : raw.padEnd(6, '0').slice(0, 6);
      const n = parseInt(val, 16);
      return {
        r: (n >> 16) & 255,
        g: (n >> 8) & 255,
        b: n & 255,
      };
    },

    curvedLatLngs(a, b, bulge) {
      const midLat = (a[0] + b[0]) / 2 + Math.abs(b[0] - a[0]) * (bulge || 0.35);
      // Plane mode: keep non-shortest interpolation as requested by user.
      const lon1 = a[1];
      const lon2 = b[1];
      const midLon = (lon1 + lon2) / 2;
      const steps = 140;
      const pts = [];
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const lat = (1 - t) * (1 - t) * a[0] + 2 * (1 - t) * t * midLat + t * t * b[0];
        const lon = (1 - t) * (1 - t) * lon1 + 2 * (1 - t) * t * midLon + t * t * lon2;
        pts.push([lat, lon]);
      }
      return pts;
    },

    /** Stop globe.gl rAF / WebGL churn when not visible (plane mode). */
    stopGlobe3dRender() {
      if (!this.globe3d) return;
      try {
        if (typeof this.globe3d.pauseAnimation === 'function') this.globe3d.pauseAnimation();
      } catch (_) {}
    },

    /** Resume globe.gl after returning to globe mode. */
    resumeGlobe3dRender() {
      if (!this.globe3d) return;
      try {
        if (typeof this.globe3d.resumeAnimation === 'function') this.globe3d.resumeAnimation();
      } catch (_) {}
    },

    startClock() {
      if (this.clockTimer) clearInterval(this.clockTimer);
      const tick = () => {
        const d = new Date();
        this.clockTime = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        this.clockDate = d.toLocaleDateString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' });
      };
      tick();
      this.clockTimer = setInterval(tick, 1000);
    },

    drawMap() {
      if (typeof L === 'undefined') return;
      const el = document.getElementById('flux-leaflet-map');
      if (!el) return;

      this.stopGlobe3dRender();

      const canvas = document.getElementById('flux-globe-canvas');
      if (canvas) canvas.classList.add('hidden');
      const globeContainer = document.getElementById('flux-globe-container');
      if (globeContainer) globeContainer.classList.add('hidden');
      if (el) el.classList.remove('hidden');

      if (this.rocketTimer) {
        // rocketTimer stores requestAnimationFrame id in plane mode.
        cancelAnimationFrame(this.rocketTimer);
        this.rocketTimer = null;
      }
      this.rocketAnims = [];

      if (this.globeTimer) {
        clearInterval(this.globeTimer);
        this.globeTimer = null;
      }

      if (this.map) {
        this.map.remove();
        this.map = null;
      }

      this.map = L.map(el, {
        zoomControl: false,
        worldCopyJump: true,
        minZoom: 2,
        maxZoom: 10,
      }).setView([this.originLat, this.originLon], 2);

      L.control.zoom({ position: 'bottomleft' }).addTo(this.map);

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20,
      }).addTo(this.map);

      this.layerGroup = L.layerGroup().addTo(this.map);

      const targetLL = [this.originLat, this.originLon];
      L.marker(targetLL, {
        icon: L.divIcon({
          className: 'flux-ct-target-marker',
          html: '<div class="flux-target-dot"></div>',
          iconSize: [18, 18],
          iconAnchor: [9, 9],
        }),
        zIndexOffset: 1000,
      }).addTo(this.layerGroup);

      (this.points || []).forEach((p, idx) => {
        const from = [p.source_lat, p.source_lon];
        const to = [p.target_lat, p.target_lon];
        const bulge = 0.26 + (idx % 9) * 0.028;
        const arc = this.curvedLatLngs(from, to, bulge);
        const color = this.colorForCountry(p.source_country);
        const distKm = this.approxDistanceKm(from, to);
        // Closer routes move faster.
        const speed = distKm < 2500 ? 4 : distKm < 7000 ? 3 : 2;

        // Rocket-stream animation: moving dot along the arc.
        const dot = L.circleMarker(arc[0], {
          radius: 3.3,
          color,
          fillColor: color,
          fillOpacity: 0.95,
          weight: 1,
          opacity: 0.95,
        }).addTo(this.layerGroup);
        // WafX-like: outer glow + inner dashed core.
        const tailCoreLen = 10 + (idx % 5);
        const tailGlowLen = tailCoreLen + 10;
        const trailGlow = L.polyline([], {
          color,
          weight: 7,
          opacity: 0.12,
          lineCap: 'round',
        }).addTo(this.layerGroup);
        const trailCore = L.polyline([], {
          color,
          weight: 3,
          opacity: 0.60,
          lineCap: 'round',
          dashArray: '7,7',
        }).addTo(this.layerGroup);
        this.rocketAnims.push({
          arc,
          dot,
          trailCore,
          trailGlow,
          t: idx % arc.length,
          step: speed + (idx % 2),
          tailCoreLen,
          tailGlowLen,
          baseRadius: 3.3,
          pulseAmp: 0.18 + (idx % 4) * 0.05,
          pulseSpeed: 1.1 + (idx % 5) * 0.18,
          pulsePhase: (idx % 360) * Math.PI / 180,
        });

        L.marker(from, {
          icon: L.divIcon({
            className: 'flux-ct-src-marker',
            html: '<div class="flux-src-dot" style="background:' + color + ';box-shadow:0 0 12px ' + color + ';border-color:rgba(255,255,255,.6)"></div>',
            iconSize: [12, 12],
            iconAnchor: [6, 6],
          }),
        }).addTo(this.layerGroup).bindPopup(
          `<div class="text-xs"><strong>${p.source_city || ''}</strong> (${p.source_country || ''})<br/>${p.attack_type || ''} · hits ${p.count ?? ''}</div>`,
          { className: 'flux-popup' }
        );
      });

      // Single animation loop for all rocket dots.
      const tick = () => {
        if (this.viewMode !== 'plane') {
          this.rocketTimer = null;
          return;
        }
        const now = performance.now();
        const nowSec = now / 1000;
        for (const a of this.rocketAnims) {
          a.t += a.step;
          if (a.t >= a.arc.length) a.t = 0;
          a.dot.setLatLng(a.arc[a.t]);

          // Pulse "head" dot.
          const pulse = 1 + (a.pulseAmp || 0.2) * Math.sin(nowSec * (a.pulseSpeed || 1) + (a.pulsePhase || 0));
          const r = Math.max(2.0, (a.baseRadius || 3.3) * pulse);
          if (a.dot && typeof a.dot.setRadius === 'function') a.dot.setRadius(r);

          // Update tails.
          const len = a.arc.length;
          const tailCoreLen = Math.min(a.tailCoreLen || 12, len - 1);
          const tailGlowLen = Math.min(a.tailGlowLen || 22, len - 1);

          const tailGlow = [];
          const startGlow = Math.max(0, a.t - tailGlowLen + 1);
          for (let idx = startGlow; idx <= a.t; idx++) {
            tailGlow.push(a.arc[idx]);
          }
          if (a.trailGlow) a.trailGlow.setLatLngs(tailGlow);

          const tailCore = [];
          const startCore = Math.max(0, a.t - tailCoreLen + 1);
          for (let idx = startCore; idx <= a.t; idx++) {
            tailCore.push(a.arc[idx]);
          }
          if (a.trailCore) {
            a.trailCore.setLatLngs(tailCore);
            // DashOffset makes the dashed core feel more "alive".
            if (typeof a.trailCore.setStyle === 'function') {
              a.trailCore.setStyle({ dashOffset: -a.t * 0.8 });
            }
          }
        }
        this.rocketTimer = requestAnimationFrame(tick);
      };
      this.rocketTimer = requestAnimationFrame(tick);

      setTimeout(() => { if (this.map) this.map.invalidateSize(); }, 200);
      setTimeout(() => { if (this.map) this.map.invalidateSize(); }, 600);
    },

    projectGlobe(lat, lon) {
      if (this.globeProjection) {
        const p = this.globeProjection([lon, lat]);
        if (!p) return null;
        return { x: p[0], y: p[1] };
      }
      // Fallback projection when d3 isn't available.
      const toRad = (d) => d * Math.PI / 180;
      const latRad = toRad(lat);
      const lonRad = toRad(lon);
      const lat0 = toRad(this.originLat);
      const lon0 = toRad(this.originLon);
      const dLon = lonRad - lon0;

      const cosc = Math.sin(lat0) * Math.sin(latRad) + Math.cos(lat0) * Math.cos(latRad) * Math.cos(dLon);
      if (cosc < 0) return null;

      const x = Math.cos(latRad) * Math.sin(dLon);
      const y = Math.cos(lat0) * Math.sin(latRad) - Math.sin(lat0) * Math.cos(latRad) * Math.cos(dLon);
      const cx = this.globeW / 2;
      const cy = this.globeH / 2;
      const R = this.globeR;
      return { x: cx + x * R, y: cy - y * R };
    },

    drawFallbackContinents(c) {
      // Coarse continent silhouettes for offline/no-CDN fallback.
      const polys = [
        [[72, -150],[60,-130],[50,-120],[45,-110],[40,-100],[30,-90],[20,-85],[15,-95],[20,-110],[25,-120],[35,-130],[50,-140],[65,-150]], // N. America
        [[10,-82],[5,-80],[-5,-75],[-15,-70],[-25,-65],[-35,-60],[-45,-64],[-55,-70],[-50,-78],[-35,-75],[-20,-70],[-5,-72],[6,-78]], // S. America
        [[72,-10],[70,10],[65,25],[60,40],[55,55],[52,70],[50,90],[45,110],[40,130],[35,150],[25,160],[15,145],[10,120],[20,95],[25,80],[30,60],[35,40],[40,25],[45,10],[52,-2],[60,-8],[68,-12]], // Eurasia
        [[35,-18],[30,-5],[24,10],[18,20],[10,28],[2,32],[-8,35],[-18,30],[-25,20],[-30,12],[-35,5],[-30,-5],[-22,-10],[-10,-5],[5,-2],[15,-5],[25,-10],[32,-15]], // Africa
        [[-12,113],[-18,120],[-24,130],[-30,140],[-36,150],[-40,146],[-42,136],[-38,126],[-30,118],[-22,112],[-15,110]], // Australia
      ];
      for (const poly of polys) {
        let started = false;
        c.beginPath();
        for (const [lat, lon] of poly) {
          const pr = this.projectGlobe(lat, lon);
          if (!pr) continue;
          if (!started) { c.moveTo(pr.x, pr.y); started = true; }
          else c.lineTo(pr.x, pr.y);
        }
        if (started) {
          c.closePath();
          c.fillStyle = 'rgba(71,85,105,0.30)';
          c.fill();
          c.strokeStyle = 'rgba(100,116,139,0.22)';
          c.lineWidth = 0.6;
          c.stroke();
        }
      }
    },

    drawGlobe() {
      if (typeof Globe !== 'undefined') {
        this.drawGlobe3dLib();
        return;
      }

      const canvas = document.getElementById('flux-globe-canvas');
      if (!canvas) return;
      const leafletEl = document.getElementById('flux-leaflet-map');
      if (leafletEl) leafletEl.classList.add('hidden');
      const globeContainer = document.getElementById('flux-globe-container');
      if (globeContainer) globeContainer.classList.add('hidden');
      canvas.classList.remove('hidden');

      if (this.globeTimer) {
        clearInterval(this.globeTimer);
        this.globeTimer = null;
      }
      this.globeArcs = [];

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      const parent = canvas.parentElement;
      const rect = parent ? parent.getBoundingClientRect() : canvas.getBoundingClientRect();
      const w = Math.max(1, Math.floor(rect.width));
      const h = Math.max(1, Math.floor(rect.height));

      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';

      // Work in CSS pixels for simpler math.
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      this.globeCtx = ctx;
      this.globeW = w;
      this.globeH = h;
      this.globeR = Math.floor(Math.min(w, h) * 0.46);

      let geoPath = null;
      if (typeof d3 !== 'undefined' && d3.geoOrthographic) {
        this.globeProjection = d3.geoOrthographic()
          .center([0, 0])
          .rotate([this.globeRotateLon, this.globeRotateLat, 0])
          .translate([this.globeW / 2, this.globeH / 2])
          .scale(this.globeR)
          .clipAngle(90);
        geoPath = d3.geoPath(this.globeProjection, ctx);
      } else {
        this.globeProjection = null;
      }

      const maxArcs = Math.min(18, (this.points || []).length);
      for (let i = 0; i < maxArcs; i++) {
        const p = this.points[i];
        const from = [p.source_lat, p.source_lon];
        const to = [p.target_lat, p.target_lon];
        const bulge = 0.26 + (i % 9) * 0.028;
        const arcLatLng = this.curvedLatLngs(from, to, bulge);
        const color = this.colorForCountry(p.source_country);
        const distKm = this.approxDistanceKm(from, to);
        const speed = distKm < 2500 ? 4 : distKm < 7000 ? 3 : 2;

        this.globeArcs.push({
          latlng: arcLatLng,
          pts: [],
          t: i % arcLatLng.length,
          step: speed + (i % 2),
          color,
        });
      }

      const renderFrame = () => {
        if (this.viewMode !== 'globe') return;
        const c = this.globeCtx;
        if (!c) return;

        const cx = this.globeW / 2;
        const cy = this.globeH / 2;
        const R = this.globeR;

        c.clearRect(0, 0, this.globeW, this.globeH);

        // Ocean sphere (stronger so globe mode looks distinct from plane mode).
        const g = c.createRadialGradient(cx - R * 0.35, cy - R * 0.35, 8, cx, cy, R);
        g.addColorStop(0, 'rgba(14,165,233,0.32)');
        g.addColorStop(0.5, 'rgba(8,47,73,0.72)');
        g.addColorStop(1, 'rgba(2,6,23,0.96)');
        c.beginPath();
        c.arc(cx, cy, R, 0, Math.PI * 2);
        c.fillStyle = g;
        c.fill();

        // Landmass map on globe (if loaded).
        if (geoPath && this.globeLandFeatures && this.globeLandFeatures.length) {
          c.save();
          c.beginPath();
          c.arc(cx, cy, R, 0, Math.PI * 2);
          c.clip();
          for (const f of this.globeLandFeatures) {
            c.beginPath();
            geoPath(f);
            c.fillStyle = 'rgba(34,197,94,0.28)';
            c.fill();
            c.strokeStyle = 'rgba(134,239,172,0.26)';
            c.lineWidth = 0.6;
            c.stroke();
          }
          c.restore();
        } else {
          this.drawFallbackContinents(c);
        }

        // Sphere edge + 3D shading.
        c.beginPath();
        c.arc(cx, cy, R, 0, Math.PI * 2);
        c.strokeStyle = 'rgba(148,163,184,0.22)';
        c.lineWidth = 1;
        c.stroke();

        // Terminator shadow.
        c.save();
        c.beginPath();
        c.arc(cx, cy, R, 0, Math.PI * 2);
        c.clip();
        const shadow = c.createLinearGradient(cx - R, cy, cx + R, cy);
        shadow.addColorStop(0, 'rgba(0,0,0,0.00)');
        shadow.addColorStop(0.55, 'rgba(0,0,0,0.08)');
        shadow.addColorStop(1, 'rgba(2,6,23,0.60)');
        c.fillStyle = shadow;
        c.fillRect(cx - R, cy - R, 2 * R, 2 * R);
        c.restore();

        // Graticules (meridians/parallels) for globe shape.
        c.save();
        c.beginPath();
        c.arc(cx, cy, R, 0, Math.PI * 2);
        c.clip();
        c.lineWidth = 1;
        c.strokeStyle = 'rgba(148,163,184,0.14)';
        c.setLineDash([2, 3]);

        // Meridians
        for (let dl = -150; dl <= 150; dl += 30) {
          const lon = this.originLon + dl;
          let started = false;
          c.beginPath();
          for (let lat = -85; lat <= 85; lat += 5) {
            const pr = this.projectGlobe(lat, lon);
            if (!pr) {
              if (started) { c.stroke(); started = false; }
              continue;
            }
            if (!started) { c.moveTo(pr.x, pr.y); started = true; }
            else { c.lineTo(pr.x, pr.y); }
          }
          if (started) c.stroke();
        }

        // Parallels
        for (let lat = -60; lat <= 60; lat += 30) {
          let started = false;
          c.beginPath();
          for (let lon = -180; lon <= 180; lon += 5) {
            const pr = this.projectGlobe(lat, lon);
            if (!pr) {
              if (started) { c.stroke(); started = false; }
              continue;
            }
            if (!started) { c.moveTo(pr.x, pr.y); started = true; }
            else { c.lineTo(pr.x, pr.y); }
          }
          if (started) c.stroke();
        }

        c.setLineDash([]);
        c.restore();

        // Rocket arcs: tail + head.
        for (let i = 0; i < this.globeArcs.length; i++) {
          const a = this.globeArcs[i];
          a.pts = [];
          for (const ll of a.latlng || []) {
            const pr = this.projectGlobe(ll[0], ll[1]);
            if (pr) a.pts.push(pr);
          }
          const len = a.pts.length;
          if (len < 2) continue;
          const head = Math.min(a.t, len - 1);
          const tailLen = Math.min(18, len - 1);

          // Tail segments with fading alpha
          const start = Math.max(0, head - tailLen + 1);
          for (let idx = start + 1; idx <= head; idx++) {
            const idx1 = idx - 1;
            const idx2 = idx;
            const seg = idx - start;
            const alpha = (seg / Math.max(1, tailLen)) * 0.6;

            c.beginPath();
            c.moveTo(a.pts[idx1].x, a.pts[idx1].y);
            c.lineTo(a.pts[idx2].x, a.pts[idx2].y);
            const rgb = this.hexToRgb(a.color || '#fb923c');
            c.strokeStyle = `rgba(${rgb.r},${rgb.g},${rgb.b},${alpha})`;
            c.lineWidth = 3;
            c.stroke();
          }

          // Head glow
          const pt = a.pts[head];
          const rgb = this.hexToRgb(a.color || '#fb923c');
          c.save();
          c.shadowBlur = 16;
          c.shadowColor = `rgba(${rgb.r},${rgb.g},${rgb.b},0.55)`;
          c.beginPath();
          c.arc(pt.x, pt.y, 3.5, 0, Math.PI * 2);
          c.fillStyle = `rgba(${rgb.r},${rgb.g},${rgb.b},0.98)`;
          c.fill();
          c.restore();
        }

        // Advance dots.
        for (const a of this.globeArcs) {
          a.t += a.step;
          if (a.t >= (a.latlng || []).length) a.t = 0;
        }
      };

      renderFrame();
      this.globeTimer = setInterval(renderFrame, 55);
      this.bindGlobeInteractions(canvas);
    },

    drawGlobe3dLib() {
      const container = document.getElementById('flux-globe-container');
      if (!container) return;
      const leafletEl = document.getElementById('flux-leaflet-map');
      if (leafletEl) leafletEl.classList.add('hidden');
      const canvas = document.getElementById('flux-globe-canvas');
      if (canvas) canvas.classList.add('hidden');
      container.classList.remove('hidden');

      if (this.globeTimer) {
        clearInterval(this.globeTimer);
        this.globeTimer = null;
      }

      const rect = container.getBoundingClientRect();
      const width = Math.max(280, Math.floor(rect.width || container.clientWidth || 0));
      const height = Math.max(240, Math.floor(rect.height || container.clientHeight || 0));
      if (width < 10 || height < 10) return;

      try {
      const shortSide = Math.min(width, height);
      // Bigger labels on small viewports (angular degrees on globe)
      const labelSize = Math.min(1.15, Math.max(0.55, shortSide / 380));
      const labelDot = Math.min(0.18, Math.max(0.1, labelSize * 0.24));
      // Lower resolutions for performance (heavier point/label tessellation).
      const labelRes = shortSide < 520 ? 3 : 2;
      const ptRadius = shortSide < 480 ? 0.30 : shortSide < 900 ? 0.25 : 0.22;
      const arcStroke = shortSide < 480 ? 0.70 : 0.55;
      // Slightly pull camera back on narrow screens so globe feels centered in the stage
      const povAlt = width < 400 ? 2.65 : width < 640 ? 2.4 : width < 1024 ? 2.25 : 2.1;

      if (!this.globe3d) {
        this.globe3d = Globe()(container)
          .backgroundColor('rgba(0,0,0,0)')
          .globeImageUrl('/public/img/earth-blue-marble.jpg')
          // Skip bump map for lighter GPU work; reference "safelIne-like" globe still looks good.
          .atmosphereColor('#67e8f9')
          .atmosphereAltitude(0.12)
          .arcStroke(arcStroke)
          .arcDashLength(0.42)
          .arcDashGap(0.8)
          .arcDashInitialGap(() => Math.random())
          .arcDashAnimateTime(1800)
          .arcLabel('tip')
          .pointAltitude(0.02)
          .pointResolution(7)
          .pointLabel('tip')
          .labelsData([])
          .labelLat('lat')
          .labelLng('lng')
          .labelText('text')
          .labelColor('color')
          .labelAltitude(0.015)
          .labelIncludeDot(false)
          .labelDotOrientation('bottom')
          .labelLabel('text');
      }

      this.globe3d
        .width(width)
        .height(height)
        .labelSize(labelSize)
        .labelDotRadius(labelDot)
        .labelResolution(labelRes)
        .pointRadius(ptRadius)
        .arcStroke(arcStroke);

      // 0ms: safe when layout is corrected immediately after (class change / ResizeObserver)
      this.globe3d.pointOfView(
        { lat: this.originLat || -2.5, lng: this.originLon || 118, altitude: povAlt },
        0
      );

      // Reduce point count + arcs count for lighter globe (keeps the "stream" look).
      const pointCandidates = (this.points || []).slice(0, 80);
      const arcCandidates = (this.points || []).slice(0, 70);

      const points = pointCandidates.map((p) => {
        const name = this.displayCountryName(p.source_country);
        return {
          lat: Number(p.source_lat),
          lng: Number(p.source_lon),
          color: this.colorForCountry(p.source_country),
          tip: name || 'Unknown',
        };
      }).filter((p) => Number.isFinite(p.lat) && Number.isFinite(p.lng));

      const seenArcKeys = new Set();
      const arcs = [];
      for (const p of arcCandidates) {
        const startLat = Number(p.source_lat);
        const startLng = Number(p.source_lon);
        const endLat = Number(p.target_lat);
        const endLng = Number(p.target_lon);
        if (!Number.isFinite(startLat) || !Number.isFinite(startLng) || !Number.isFinite(endLat) || !Number.isFinite(endLng)) continue;
        const d = p.domain || 'unknown';
        const key = `${startLat.toFixed(1)},${startLng.toFixed(1)}->${endLat.toFixed(1)},${endLng.toFixed(1)}|${d}`;
        if (seenArcKeys.has(key)) continue;
        seenArcKeys.add(key);
        const color = this.colorForCountry(p.source_country);
        const countryName = this.displayCountryName(p.source_country);
        arcs.push({
          startLat,
          startLng,
          endLat,
          endLng,
          // Keep line color style close to plane mode: same hue, fading tail.
          color: [color, color + '55'],
          tip: countryName || 'Unknown',
        });
        if (arcs.length >= 55) break;
      }

      const targetCountryCode = (this.points && this.points[0] && this.points[0].target_country)
        ? String(this.points[0].target_country).trim().toUpperCase() : '';
      const targetCountryName = targetCountryCode ? this.displayCountryName(targetCountryCode) : '';

      const targetPoint = Number.isFinite(this.originLat) && Number.isFinite(this.originLon)
        ? [{
            lat: this.originLat,
            lng: this.originLon,
            color: '#22c55e',
            tip: targetCountryName || '',
          }]
        : [];

      // One label per source country (centroid of sample points) + target country label.
      const byCountry = new Map();
      for (const p of (this.points || []).slice(0, 120)) {
        const code = String(p.source_country || '').trim().toUpperCase();
        if (!code || code === 'ZZ') continue;
        const lat = Number(p.source_lat);
        const lng = Number(p.source_lon);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
        let agg = byCountry.get(code);
        if (!agg) {
          agg = { code, sumLat: 0, sumLng: 0, n: 0 };
          byCountry.set(code, agg);
        }
        agg.sumLat += lat;
        agg.sumLng += lng;
        agg.n += 1;
      }
      // Keep only top N source country labels (performance + visual cleanliness).
      const sortedAggs = Array.from(byCountry.values()).sort((a, b) => b.n - a.n).slice(0, 8);
      const countryLabels = [];
      for (const agg of sortedAggs) {
        const name = this.displayCountryName(agg.code);
        const rgb = this.hexToRgb(this.colorForCountry(agg.code));
        countryLabels.push({
          lat: agg.sumLat / agg.n,
          lng: agg.sumLng / agg.n,
          text: name,
          color: `rgba(${rgb.r},${rgb.g},${rgb.b},0.92)`,
        });
      }
      if (Number.isFinite(this.originLat) && Number.isFinite(this.originLon) && targetCountryName) {
        countryLabels.push({
          lat: this.originLat,
          lng: this.originLon,
          text: targetCountryName,
          color: 'rgba(34, 197, 94, 0.95)',
        });
      }

      this.globe3d
        .pointsData(points.concat(targetPoint))
        .pointColor('color')
        .arcsData(arcs)
        .labelsData(countryLabels);
      } finally {
        this.resumeGlobe3dRender();
      }
    },

    bindGlobeInteractions(canvas) {
      const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

      const startDrag = (x, y) => {
        this.globeDragging = true;
        this.globeDragStartX = x;
        this.globeDragStartY = y;
        this.globeDragStartLon = this.globeRotateLon;
        this.globeDragStartLat = this.globeRotateLat;
      };
      const moveDrag = (x, y) => {
        if (!this.globeDragging || this.viewMode !== 'globe') return;
        const dx = x - this.globeDragStartX;
        const dy = y - this.globeDragStartY;
        this.globeRotateLon = this.globeDragStartLon + dx * 0.35;
        this.globeRotateLat = clamp(this.globeDragStartLat - dy * 0.28, -75, 75);
        if (this.globeProjection) {
          this.globeProjection.rotate([this.globeRotateLon, this.globeRotateLat, 0]);
        }
      };
      const endDrag = () => {
        this.globeDragging = false;
      };

      // Mouse
      canvas.onmousedown = (e) => startDrag(e.clientX, e.clientY);
      window.onmousemove = (e) => moveDrag(e.clientX, e.clientY);
      window.onmouseup = () => endDrag();

      // Touch
      canvas.ontouchstart = (e) => {
        if (!e.touches || !e.touches[0]) return;
        const t = e.touches[0];
        startDrag(t.clientX, t.clientY);
      };
      canvas.ontouchmove = (e) => {
        if (!e.touches || !e.touches[0]) return;
        const t = e.touches[0];
        moveDrag(t.clientX, t.clientY);
      };
      canvas.ontouchend = () => endDrag();
    },

    renderView() {
      if (this.viewMode === 'globe') this.drawGlobe();
      else this.drawMap();
    },

    setViewMode(mode) {
      this.viewMode = mode === 'globe' ? 'globe' : 'plane';
      this.renderView();
      // Remeasure after Alpine applies bottom offset above mobile feed panel.
      if (this.viewMode === 'globe' && typeof Globe !== 'undefined') {
        requestAnimationFrame(() => requestAnimationFrame(() => this.drawGlobe3dLib()));
      }
    },

    onWindowResize() {
      if (this.viewMode !== 'globe') return;
      requestAnimationFrame(() => {
        if (this.viewMode !== 'globe') return;
        if (typeof Globe !== 'undefined' && this.globe3d) {
          this.drawGlobe3dLib();
          return;
        }
        this.drawGlobe();
      });
    },

    startLoop() {
      if (this.loopTimer) clearInterval(this.loopTimer);
      if (!this.allLogs.length) return;
      let i = 0;
      this.loopTimer = setInterval(() => {
        const e = this.allLogs[i % this.allLogs.length];
        this.feed.unshift({ ...e, _key: 't-' + Date.now() + '-' + i });
        if (this.feed.length > 18) this.feed.pop();
        i++;
      }, 1400);
    },

    async init() {
      this.startClock();
      window.addEventListener('resize', () => this.onWindowResize());
      const mapStage = document.getElementById('flux-map-stage');
      if (mapStage && typeof ResizeObserver !== 'undefined') {
        if (this._fluxMapResizeObs) this._fluxMapResizeObs.disconnect();
        this._fluxMapResizeObs = new ResizeObserver(() => {
          if (this.viewMode !== 'globe') return;
          requestAnimationFrame(() => {
            if (this.viewMode === 'globe') this.drawGlobe3dLib();
          });
        });
        this._fluxMapResizeObs.observe(mapStage);
      }
      try {
        // Optional world landmass for globe (non-blocking).
        try {
          const topo = await fetch('/public/data/countries-110m.json').then(r => r.json());
          this.globeLandFeatures = topojson.feature(topo, topo.objects.countries).features || [];
        } catch (_) {
          this.globeLandFeatures = null;
        }

        const r = await fetch('/api/attack-map');
        const d = await r.json();
        this.demo = !!d.demo;
        this.label = d.label || '';
        this.totalToday = d.total_today || 0;
        this.categories = Array.isArray(d.categories) ? d.categories : [];
        this.catMax = Math.max(1, ...this.categories.map((c) => c.count));

        this.points = Array.isArray(d.points) ? d.points : [];
        const logs = Array.isArray(d.logs_24h) ? d.logs_24h : [];
        this.allLogs = logs.slice().sort((a, b) => new Date(b.ts) - new Date(a.ts));

        if (this.points.length && this.points[0].target_lat != null) {
          this.originLat = this.points[0].target_lat;
          this.originLon = this.points[0].target_lon;
        }
        // Start globe looking at protected origin.
        this.globeRotateLon = -this.originLon;
        this.globeRotateLat = -this.originLat;

        this.feed = this.allLogs.slice(0, 14).map((e, i) => ({ ...e, _key: 'init-' + i }));
        this.startLoop();

        setTimeout(() => this.renderView(), 50);
        setTimeout(() => this.renderView(), 280);
      } catch (e) {
        this.label = 'Gagal memuat data: ' + (e.message || e);
      }
    },
  };
}
