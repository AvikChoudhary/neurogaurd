/* Small canvas chart library (no external dependencies, works offline). */
(function () {
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const FONT = "12px 'Instrument Sans', system-ui, sans-serif";

  function setup(canvas) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    return { ctx, w, h };
  }
  const niceMax = (v) => { const p = Math.pow(10, Math.floor(Math.log10(Math.max(v, 1)))); for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p; return 10 * p; };

  /* ---------- live stacked area chart ---------- */
  NG.LiveChart = class {
    constructor(canvas, series) {
      this.c = canvas; this.series = series; this.rows = []; this.hover = null;
      new ResizeObserver(() => this.draw()).observe(canvas);
      canvas.addEventListener("mousemove", (e) => { const r = canvas.getBoundingClientRect(); this.hover = e.clientX - r.left; this.draw(); });
      canvas.addEventListener("mouseleave", () => { this.hover = null; this.draw(); });
    }
    set(rows) { this.rows = rows; this.draw(); }
    draw() {
      const { ctx, w, h } = setup(this.c);
      const L = 40, R = 8, T = 10, B = 22, pw = w - L - R, ph = h - T - B, rows = this.rows, N = Math.max(rows.length, 2);
      const totals = rows.map((r) => this.series.reduce((s, k) => s + (r[k.key] || 0), 0));
      const max = niceMax(Math.max(5, ...totals) * 1.1);
      ctx.font = FONT; ctx.textBaseline = "middle"; ctx.textAlign = "right"; ctx.lineWidth = 1;
      for (let i = 0; i <= 4; i++) {
        const y = T + ph - (ph * i) / 4;
        ctx.strokeStyle = "rgba(124,160,220,.09)"; ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - R, y); ctx.stroke();
        ctx.fillStyle = "#55657f"; ctx.fillText(NG.n((max * i) / 4), L - 8, y);
      }
      ctx.textAlign = "center"; ctx.fillStyle = "#55657f";
      [["-" + Math.max(N - 1, 1) + "s", 0], ["-" + Math.round((N - 1) / 2) + "s", 0.5], ["now", 1]].forEach(([s, k]) => ctx.fillText(s, L + pw * k, h - 8));
      if (!rows.length) return;
      const X = (i) => L + (pw * i) / (N - 1), Y = (v) => T + ph - (ph * v) / max;
      const cum = rows.map(() => 0);
      this.series.forEach((s) => {
        const top = rows.map((r, i) => cum[i] + (r[s.key] || 0));
        ctx.beginPath(); ctx.moveTo(X(0), Y(cum[0]));
        top.forEach((v, i) => ctx.lineTo(X(i), Y(v)));
        for (let i = rows.length - 1; i >= 0; i--) ctx.lineTo(X(i), Y(cum[i]));
        ctx.closePath();
        const g = ctx.createLinearGradient(0, T, 0, T + ph); g.addColorStop(0, s.color + "aa"); g.addColorStop(1, s.color + "10");
        ctx.fillStyle = g; ctx.fill();
        ctx.beginPath(); top.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
        ctx.strokeStyle = s.color; ctx.lineWidth = 1.6; ctx.stroke();
        top.forEach((v, i) => (cum[i] = v));
      });
      if (this.hover != null && this.hover >= L && this.hover <= w - R) {
        const i = Math.max(0, Math.min(rows.length - 1, Math.round(((this.hover - L) / pw) * (N - 1))));
        const r = rows[i], x = X(i);
        ctx.strokeStyle = "rgba(230,235,245,.35)"; ctx.setLineDash([3, 3]); ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T + ph); ctx.stroke(); ctx.setLineDash([]);
        const lines = [NG.time(r.t), ...this.series.map((s) => `${s.label}: ${NG.n(r[s.key] || 0)}`)];
        const bw = 128, bh = 14 * lines.length + 12, bx = Math.min(Math.max(x + 10, L), w - bw - 4);
        ctx.fillStyle = "#121d31"; ctx.strokeStyle = "#2a3f63"; ctx.beginPath(); ctx.roundRect(bx, T + 4, bw, bh, 8); ctx.fill(); ctx.stroke();
        ctx.textAlign = "left"; ctx.fillStyle = "#e6ebf5";
        lines.forEach((s, k) => ctx.fillText(s, bx + 10, T + 18 + k * 14));
      }
    }
  };

  /* ---------- donut ---------- */
  NG.donut = (canvas, items, center = {}) => {
    const { ctx, w, h } = setup(canvas);
    const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 4, r = R - 20;
    const total = items.reduce((s, i) => s + i.value, 0);
    ctx.lineWidth = 20; ctx.lineCap = "butt";
    if (!total) { ctx.strokeStyle = "#16233a"; ctx.beginPath(); ctx.arc(cx, cy, r + 10, 0, 7); ctx.stroke(); }
    else {
      let a = -Math.PI / 2;
      items.forEach((it) => {
        const da = (it.value / total) * Math.PI * 2, gap = items.length > 1 ? Math.min(0.025, da / 3) : 0;   // never let a tiny slice invert
        ctx.strokeStyle = it.color; ctx.beginPath(); ctx.arc(cx, cy, r + 10, a + gap, a + da - gap); ctx.stroke(); a += da;
      });
    }
    ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillStyle = "#e6ebf5";
    ctx.font = "700 28px 'Bricolage Grotesque', system-ui, sans-serif"; ctx.fillText(center.big ?? NG.n(total), cx, cy - 6);
    ctx.font = "400 12px 'Instrument Sans', system-ui, sans-serif"; ctx.fillStyle = "#8796b4"; ctx.fillText(center.small || "threats", cx, cy + 18);
  };

  /* ---------- generic multi-line chart (training curves) ---------- */
  NG.lineChart = (canvas, series, { yMin, yMax, fmt = (v) => v.toFixed(2), xLabel = "epoch" } = {}) => {
    const { ctx, w, h } = setup(canvas);
    const L = 46, R = 10, T = 10, B = 24, pw = w - L - R, ph = h - T - B;
    const all = series.flatMap((s) => s.values.filter((v) => v != null));
    if (!all.length) return;
    const lo = yMin ?? Math.min(...all), hi = yMax ?? Math.max(...all), span = hi - lo || 1;
    const N = Math.max(...series.map((s) => s.values.length));
    ctx.font = FONT; ctx.textBaseline = "middle"; ctx.textAlign = "right"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = T + ph - (ph * i) / 4; ctx.strokeStyle = "rgba(124,160,220,.09)";
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - R, y); ctx.stroke(); ctx.fillStyle = "#55657f"; ctx.fillText(fmt(lo + (span * i) / 4), L - 8, y);
    }
    ctx.textAlign = "center"; ctx.fillStyle = "#55657f";
    ctx.fillText(xLabel + " 1", L, h - 8); ctx.fillText(xLabel + " " + N, w - R - 14, h - 8);
    series.forEach((s) => {
      ctx.beginPath(); ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.setLineDash(s.dash || []);
      s.values.forEach((v, i) => { const x = L + (pw * i) / Math.max(N - 1, 1), y = T + ph - (ph * (v - lo)) / span; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.stroke(); ctx.setLineDash([]);
    });
  };

  /* ---------- risk gauge (SVG string) ---------- */
  NG.gauge = (value, label, color) => {
    const r = 70, c = Math.PI * r, off = c * (1 - value / 100);
    return `<svg viewBox="0 0 180 110" class="gauge" role="img" aria-label="Risk score ${value} of 100">
      <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="#16233a" stroke-width="14" stroke-linecap="round"/>
      <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="${color}" stroke-width="14" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}" style="transition:stroke-dashoffset .8s cubic-bezier(.2,.8,.2,1)"/>
      <text x="90" y="82" text-anchor="middle" font-family="Bricolage Grotesque, system-ui" font-weight="800" font-size="36" fill="#e6ebf5">${value}</text>
      <text x="90" y="102" text-anchor="middle" font-size="12" fill="#8796b4" font-family="Instrument Sans, system-ui">${label}</text></svg>`;
  };

  /* ---------- architecture diagram (SVG string) ---------- */
  NG.arch = (sizes, names, color = "#7cc4ff") => {
    const W = 640, H = 250, shown = (n) => Math.min(n, 9), colx = (i) => 50 + (i * (W - 100)) / (sizes.length - 1);
    const pos = sizes.map((n, i) => { const s = shown(n); return Array.from({ length: s }, (_, k) => [colx(i), 34 + ((H - 80) * (s === 1 ? 0.5 : k / (s - 1)))]); });
    let lines = "", dots = "", text = "";
    for (let i = 0; i < pos.length - 1; i++) for (const a of pos[i]) for (const b of pos[i + 1]) lines += `M${a[0]} ${a[1]}L${b[0]} ${b[1]}`;
    pos.forEach((col, i) => {
      col.forEach((p) => (dots += `<circle cx="${p[0]}" cy="${p[1]}" r="6" fill="#16233a" stroke="${i === 0 || i === pos.length - 1 ? color : "#3b5680"}" stroke-width="1.6"/>`));
      if (sizes[i] > shown(sizes[i])) dots += `<text x="${col[0][0]}" y="${H - 38}" text-anchor="middle" fill="#55657f" font-size="14">...</text>`;
      text += `<text x="${col[0][0]}" y="${H - 14}" text-anchor="middle" fill="#e6ebf5" font-size="12.5" font-weight="600" font-family="Instrument Sans, system-ui">${sizes[i]}</text>`;
      text += `<text x="${col[0][0]}" y="14" text-anchor="middle" fill="#8796b4" font-size="11.5" font-family="Instrument Sans, system-ui">${names[i]}</text>`;
    });
    return `<svg viewBox="0 0 ${W} ${H}" class="arch" role="img" aria-label="Network architecture ${sizes.join(' to ')}"><path d="${lines}" stroke="rgba(124,160,220,.10)" fill="none"/>${dots}${text}</svg>`;
  };
})();
