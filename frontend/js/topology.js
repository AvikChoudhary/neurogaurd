/* Animated network topology: external hosts <-> gateway/IDS sensor <-> internal assets.
   Every analysed flow becomes a particle; threats glow in their attack-class colour. */
NG.Topology = class {
  constructor(canvas) {
    this.c = canvas; this.ctx = canvas.getContext("2d");
    this.assets = []; this.ext = new Map(); this.pulses = []; this.heat = {}; this.raf = 0; this.alive = false;
    this.ro = new ResizeObserver(() => this.layout()); this.ro.observe(canvas);
    this.layout();
  }
  setAssets(a) { this.assets = a.filter((x) => x.type !== "gateway"); this.gw = a.find((x) => x.type === "gateway"); this.layout(); }

  layout() {
    const dpr = Math.min(2, devicePixelRatio || 1), w = this.c.clientWidth, h = this.c.clientHeight;
    if (!w || !h) return;
    this.c.width = w * dpr; this.c.height = h * dpr; this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = w; this.h = h;
    this.G = { x: w * 0.42, y: h * 0.5 };
    const R = Math.min(w * 0.40, h * 0.44), n = this.assets.length;
    this.pos = {};
    this.assets.forEach((a, i) => {
      const ang = (-62 + (124 * (n === 1 ? 0.5 : i / (n - 1)))) * Math.PI / 180;
      this.pos[a.id] = { x: this.G.x + Math.cos(ang) * R * 1.12, y: this.G.y + Math.sin(ang) * R, a };
    });
    this.slots = Array.from({ length: 6 }, (_, i) => {
      const ang = (118 + 124 * (i / 5)) * Math.PI / 180;
      return { x: this.G.x + Math.cos(ang) * R * 1.0, y: this.G.y + Math.sin(ang) * R };
    });
  }

  nodeFor(ip) {
    if (!ip) return null;
    for (const a of this.assets) if (a.ip === ip) return { ...this.pos[a.id], key: a.id };
    if (ip.startsWith("10.0.1.")) return { ...this.pos.ws, key: "ws" };
    let e = this.ext.get(ip);
    if (!e) {
      const used = new Set([...this.ext.values()].map((v) => v.slot));
      let slot = [0, 1, 2, 3, 4, 5].find((s) => !used.has(s));
      if (slot === undefined) {                                 // evict the stalest
        let oldest = null; this.ext.forEach((v, k) => { if (!oldest || v.seen < oldest[1].seen) oldest = [k, v]; });
        this.ext.delete(oldest[0]); slot = oldest[1].slot;
      }
      e = { slot, seen: 0, color: "#8796b4" }; this.ext.set(ip, e);
    }
    e.seen = performance.now();
    return { ...this.slots[e.slot], key: ip, ext: true, e };
  }

  pulse(f) {
    if (!this.assets.length || this.pulses.length > 90) return;
    const a = this.nodeFor(f.src), b = this.nodeFor(f.dst);
    if (!a || !b || !this.pos.ws) return;
    const threat = f.label !== "Benign", col = threat ? NG.color(f.label) : "#38d9a9";
    if (threat) {
      if (a.ext) a.e.color = col;
      if (b.ext) b.e.color = col;
      this.heat[b.key] = { v: 1, c: col }; this.heat[a.key] = { v: 1, c: col };
    }
    this.pulses.push({ a, b, t0: performance.now(), col, threat, d: threat ? 1100 : 1500 });
  }

  start() { if (this.alive) return; this.alive = true; const loop = () => { if (!this.alive) return; this.draw(); this.raf = requestAnimationFrame(loop); }; loop(); }
  stop() { this.alive = false; cancelAnimationFrame(this.raf); this.ro.disconnect(); }

  draw() {
    const { ctx, w, h, G } = this; if (!w) return;
    const now = performance.now();
    ctx.clearRect(0, 0, w, h);
    ctx.lineWidth = 1;
    // links
    ctx.strokeStyle = "rgba(124,160,220,.14)";
    for (const k in this.pos) { ctx.beginPath(); ctx.moveTo(G.x, G.y); ctx.lineTo(this.pos[k].x, this.pos[k].y); ctx.stroke(); }
    this.ext.forEach((e, ip) => { if (now - e.seen > 14000) { this.ext.delete(ip); return; }
      const s = this.slots[e.slot]; ctx.strokeStyle = e.color + "55"; ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(G.x, G.y); ctx.stroke(); });

    // gateway / sensor
    const pr = 26 + Math.sin(now / 500) * 1.5;
    const g = ctx.createRadialGradient(G.x, G.y, 4, G.x, G.y, 52); g.addColorStop(0, "rgba(124,196,255,.28)"); g.addColorStop(1, "rgba(124,196,255,0)");
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(G.x, G.y, 52, 0, 7); ctx.fill();
    ctx.fillStyle = "#0c1524"; ctx.strokeStyle = "#7cc4ff"; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(G.x, G.y, 21, 0, 7); ctx.fill(); ctx.stroke();
    ctx.strokeStyle = "rgba(124,196,255,.35)"; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(G.x, G.y, pr, 0, 7); ctx.stroke();
    ctx.fillStyle = "#7cc4ff"; ctx.font = "700 10.5px 'Instrument Sans', sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("IDS", G.x, G.y);
    ctx.fillStyle = "#8796b4"; ctx.font = "500 11px 'Instrument Sans', sans-serif"; ctx.fillText("ANN sensor", G.x, G.y + 42);

    // internal assets
    for (const k in this.pos) {
      const p = this.pos[k], ht = this.heat[k];
      if (ht && ht.v > 0.02) {
        const gl = ctx.createRadialGradient(p.x, p.y, 2, p.x, p.y, 34); gl.addColorStop(0, ht.c + Math.round(ht.v * 150).toString(16).padStart(2, "0")); gl.addColorStop(1, ht.c + "00");
        ctx.fillStyle = gl; ctx.beginPath(); ctx.arc(p.x, p.y, 34, 0, 7); ctx.fill(); ht.v *= 0.985;
      }
      ctx.fillStyle = "#121d31"; ctx.strokeStyle = ht && ht.v > 0.2 ? ht.c : "#2f4770"; ctx.lineWidth = 1.6;
      ctx.beginPath(); ctx.roundRect(p.x - 13, p.y - 13, 26, 26, 7); ctx.fill(); ctx.stroke();
      ctx.fillStyle = "#e6ebf5"; ctx.font = "500 11.5px 'Instrument Sans', sans-serif"; ctx.textAlign = "left"; ctx.fillText(p.a.name, p.x + 20, p.y - 5);
      ctx.fillStyle = "#55657f"; ctx.font = "400 10.5px 'JetBrains Mono', monospace"; ctx.fillText(p.a.ip, p.x + 20, p.y + 8);
    }
    // external hosts
    this.ext.forEach((e, ip) => {
      const s = this.slots[e.slot], ht = this.heat[ip];
      ctx.fillStyle = "#121d31"; ctx.strokeStyle = e.color; ctx.lineWidth = 1.6; ctx.beginPath(); ctx.arc(s.x, s.y, 9, 0, 7); ctx.fill(); ctx.stroke();
      if (ht && ht.v > 0.02) { ctx.fillStyle = ht.c + "40"; ctx.beginPath(); ctx.arc(s.x, s.y, 9 + 14 * (1 - ht.v), 0, 7); ctx.fill(); ht.v *= 0.97; }
      ctx.textAlign = "center"; ctx.fillStyle = "#8796b4"; ctx.font = "400 10.5px 'JetBrains Mono', monospace"; ctx.fillText(ip, s.x, s.y - 17);
    });

    // particles
    this.pulses = this.pulses.filter((p) => now - p.t0 < p.d);
    for (const p of this.pulses) {
      const k = (now - p.t0) / p.d, seg = k < 0.5 ? [p.a, G, k * 2] : [G, p.b, (k - 0.5) * 2];
      const e = seg[2] * seg[2] * (3 - 2 * seg[2]), x = seg[0].x + (seg[1].x - seg[0].x) * e, y = seg[0].y + (seg[1].y - seg[0].y) * e;
      if (p.threat) { ctx.fillStyle = p.col + "44"; ctx.beginPath(); ctx.arc(x, y, 9, 0, 7); ctx.fill(); }
      ctx.fillStyle = p.col; ctx.beginPath(); ctx.arc(x, y, p.threat ? 4 : 2.6, 0, 7); ctx.fill();
    }
  }
};
