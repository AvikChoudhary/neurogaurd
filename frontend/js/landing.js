/* Landing page: animated neural network hero + live model stats */
(function () {
  const CLASSES = [
    ["Benign", "#38D9A9"], ["DoS/DDoS", "#FF5470"], ["Port Scan", "#FFC83D"], ["Brute Force", "#FF8A3D"],
    ["Web Attack", "#B38CFF"], ["Botnet C2", "#FF6FD8"], ["Data Exfiltration", "#4CC2FF"], ["Infiltration", "#9BE15D"],
  ];
  const LAYERS = [8, 7, 6, 5, 8];
  const canvas = document.getElementById("net");
  const ctx = canvas.getContext("2d");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let W = 0, H = 0, dpr = 1, nodes = [], pulses = [], last = 0, spawnAt = 0, seq = 0;

  function layout() {
    dpr = Math.min(2, window.devicePixelRatio || 1);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const x0 = W * 0.17, x1 = W * 0.70;
    nodes = LAYERS.map((n, li) => {
      const x = x0 + (x1 - x0) * (li / (LAYERS.length - 1));
      const pad = 34, span = H - pad * 2;
      return Array.from({ length: n }, (_, i) => ({ x, y: pad + (n === 1 ? span / 2 : span * i / (n - 1)) }));
    });
  }

  function spawn(t) {
    const attack = Math.random() < 0.55;
    const cls = attack ? 1 + Math.floor(Math.random() * 7) : 0;
    const path = LAYERS.map((n, li) => (li === LAYERS.length - 1 ? cls : Math.floor(Math.random() * n)));
    const ghost = LAYERS.map((n, li) => (li === LAYERS.length - 1 ? [] : Array.from({ length: 2 }, () => Math.floor(Math.random() * n))));
    const entry = Math.random() * H * 0.8 + H * 0.1;
    pulses.push({ t0: t, cls, path, ghost, entry, conf: 91 + Math.random() * 8.5, id: ++seq });
    if (pulses.length > 7) pulses.shift();
  }

  const lerp = (a, b, k) => a + (b - a) * k;
  const bell = (x, c, w) => Math.exp(-(((x - c) / w) ** 2));

  function draw(now) {
    const t = now / 1000;
    ctx.clearRect(0, 0, W, H);

    // faint full connectivity
    ctx.lineWidth = 1;
    for (let l = 0; l < nodes.length - 1; l++) {
      ctx.strokeStyle = "rgba(124,160,220,.09)";
      ctx.beginPath();
      for (const a of nodes[l]) for (const b of nodes[l + 1]) { ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); }
      ctx.stroke();
    }

    // node activation from pulses
    const act = nodes.map((L) => L.map(() => ({ v: 0, c: null })));
    const out = [];
    for (const p of pulses) {
      const age = t - p.t0;
      const travel = 0.9;                       // packet flight time into the input layer
      const color = CLASSES[p.cls][1];
      // packet flying in
      if (age < travel) {
        const k = age / travel, n0 = nodes[0][p.path[0]];
        const x = lerp(8, n0.x, k * k * (3 - 2 * k)), y = lerp(p.entry, n0.y, k * k * (3 - 2 * k));
        ctx.fillStyle = "rgba(230,235,245,.95)"; ctx.beginPath(); ctx.arc(x, y, 3.4, 0, 7); ctx.fill();
        ctx.strokeStyle = "rgba(230,235,245,.22)"; ctx.beginPath(); ctx.moveTo(x - 26 * (1 - k * .4), y - (y - n0.y) * 0.0); ctx.lineTo(x, y); ctx.stroke();
      }
      for (let l = 0; l < nodes.length; l++) {
        const c = travel + l * 0.32, e = bell(age, c + 0.15, 0.32);
        if (e < 0.02) continue;
        const idx = new Set([p.path[l], ...p.ghost[l]]);
        idx.forEach((i) => {
          const s = i === p.path[l] ? e : e * 0.35;
          if (s > act[l][i].v) act[l][i] = { v: s, c: l === nodes.length - 1 ? color : "#7cc4ff" };
        });
        if (l > 0) {                                  // highlighted connection
          const a = nodes[l - 1][p.path[l - 1]], b = nodes[l][p.path[l]];
          ctx.strokeStyle = (l === nodes.length - 1 ? color : "#7cc4ff") + Math.round(Math.min(1, e) * 200).toString(16).padStart(2, "0");
          ctx.lineWidth = 1.6; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); ctx.lineWidth = 1;
        }
      }
      const outAge = age - (travel + (LAYERS.length - 1) * 0.32);
      if (outAge > 0 && outAge < 2.4) out.push({ p, k: outAge, color });
    }

    // nodes
    nodes.forEach((L, li) => L.forEach((n, i) => {
      const a = act[li][i];
      const r = li === nodes.length - 1 ? 8 : 6.5;
      if (a.v > 0.03) {
        const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, r * 3.6);
        g.addColorStop(0, a.c + "99"); g.addColorStop(1, a.c + "00");
        ctx.fillStyle = g; ctx.beginPath(); ctx.arc(n.x, n.y, r * 3.6, 0, 7); ctx.fill();
      }
      ctx.fillStyle = a.v > 0.03 ? a.c : "#16233a";
      ctx.strokeStyle = a.v > 0.03 ? a.c : "#2a3f63";
      ctx.beginPath(); ctx.arc(n.x, n.y, r * (1 + a.v * 0.25), 0, 7); ctx.fill(); ctx.lineWidth = 1.4; ctx.stroke(); ctx.lineWidth = 1;
    }));

    // output labels
    const outNodes = nodes[nodes.length - 1];
    ctx.font = "500 12px 'Instrument Sans', system-ui, sans-serif"; ctx.textBaseline = "middle";
    CLASSES.forEach(([name, col], i) => {
      const n = outNodes[i], hit = out.find((o) => o.p.cls === i);
      ctx.fillStyle = hit ? col : "#5f7090";
      ctx.fillText(name, n.x + 18, n.y);
      if (hit) {
        const fade = Math.max(0, 1 - hit.k / 2.4);
        ctx.globalAlpha = fade; ctx.fillStyle = col; ctx.font = "700 12px 'JetBrains Mono', monospace";
        ctx.fillText(hit.p.conf.toFixed(1) + "%", n.x + 18 + ctx.measureText(name).width + 12, n.y);
        ctx.globalAlpha = 1; ctx.font = "500 12px 'Instrument Sans', system-ui, sans-serif";
      }
    });

    // column captions
    ctx.fillStyle = "#55657f"; ctx.font = "500 11.5px 'Instrument Sans', system-ui, sans-serif"; ctx.textAlign = "center";
    ["31 flow features", "128", "64", "32", "Verdict"].forEach((s, i) => ctx.fillText(s, nodes[i][0].x, H - 8));
    ctx.textAlign = "left";
  }

  function frame(now) {
    if (now >= spawnAt) { spawn(now / 1000); spawnAt = now + 1100 + Math.random() * 700; }
    draw(now);
    if (!reduce) requestAnimationFrame(frame);
  }

  layout();
  addEventListener("resize", layout);
  if (reduce) { spawn(0); spawn(-1); draw(1500); } else requestAnimationFrame(frame);

  // ---------- live content from the API ----------
  fetch("/api/status").then((r) => r.json()).then((s) => {
    const list = document.getElementById("dlist");
    list.innerHTML = Object.entries(s.intel).filter(([k]) => k !== "Benign").map(([k, v]) =>
      `<li style="--c:${v.color}"><span class="bar"></span><div><h3>${k}${v.mitre ? `<span class="tag">MITRE ${v.mitre}</span>` : ""}</h3><p>${v.desc}</p></div></li>`).join("");
    if (s.model && s.model.accuracy) document.getElementById("p-acc").textContent = (s.model.accuracy * 100).toFixed(1) + "%";
  }).catch(() => {});
})();
