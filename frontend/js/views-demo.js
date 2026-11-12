/* Views: Attack simulator, Payload inspector, and the guided presentation demo */
(function () {
  const S = NG.S, $ = NG.$;

  /* ============================== SIMULATOR ============================== */
  NG.views.simulator = {
    sel: {}, ends: {}, timer: 0,
    mount(el) {
      const sc = S.scenarios;
      Object.keys(sc).forEach((k) => (this.sel[k] = this.sel[k] || { int: 3, dur: 30 }));
      el.innerHTML = `
      <div class="panel sim-head"><div><h3>Launch an attack</h3><p class="muted">Each scenario injects realistic flow features into the same pipeline used for live capture. The detector never sees the ground-truth label; the scoreboard compares its verdicts against it.</p></div>
        <div class="sim-tools"><label class="field inline"><span>Background traffic <b id="s-base-v" class="num"></b> flows/s</span><input type="range" id="s-base" min="0" max="60" value="${S.settings.baseline_rate}"></label>
          <button class="btn" id="s-stop">${NG.ic("stop")}Stop all</button><button class="btn primary" id="s-demo">${NG.ic("play")}Run guided demo</button></div></div>
      <div class="scn-grid">${Object.entries(sc).map(([k, v]) => `
        <article class="scn" data-k="${k}" style="--c:${NG.color(v.label)}">
          <header><span class="scn-ic">${NG.ic(k)}</span><div><h3>${NG.esc(v.title)}</h3><span class="mono faint">${NG.esc((S.intel[v.label] || {}).mitre || "ANN + autoencoder")}</span></div></header>
          <p class="muted">${NG.esc(v.desc)}</p>
          <div class="muted small">Target: ${NG.esc(v.target)}</div>
          <div class="scn-ctl"><div class="seg" role="group" aria-label="Intensity">${[1, 2, 3, 4, 5].map((n) => `<button data-int="${n}" title="Intensity ${n}: ${v.rates[n - 1]} flows/s" class="${this.sel[k].int === n ? "on" : ""}">${n}</button>`).join("")}</div>
            <select class="select dur" aria-label="Duration">${[15, 30, 60, 120].map((d) => `<option value="${d}" ${this.sel[k].dur === d ? "selected" : ""}>${d}s</option>`).join("")}</select></div>
          <button class="btn primary launch">${NG.ic("play")}Launch</button>
          <div class="prog"><i></i></div>
        </article>`).join("")}</div>
      <div class="grid g-d">
        <div class="panel"><div class="panel-h"><div><h3>Detection scoreboard</h3><div class="sub">Measured live against simulation ground truth</div></div></div>
          <div class="score-top" id="sc-top"></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Scenario</th><th class="r">Flows injected</th><th>Flagged as threat</th><th>Exact class</th></tr></thead><tbody id="sc-body"></tbody></table></div></div>
        <div class="panel"><div class="panel-h"><h3>Incident feed</h3><a href="#/incidents">View all</a></div><div class="tbl-wrap"><table class="tbl"><tbody id="sc-feed"></tbody></table></div></div>
      </div>`;
      const base = $("#s-base"); $("#s-base-v").textContent = base.value;
      base.oninput = () => ($("#s-base-v").textContent = base.value);
      base.onchange = () => NG.api("/api/settings", { baseline_rate: +base.value });
      $("#s-stop").onclick = () => NG.api("/api/simulate/stop", {});
      $("#s-demo").onclick = () => NG.demo.start();
      NG.$$(".scn").forEach((card) => {
        const k = card.dataset.k;
        NG.$$("[data-int]", card).forEach((b) => (b.onclick = () => { this.sel[k].int = +b.dataset.int; NG.$$("[data-int]", card).forEach((x) => x.classList.toggle("on", x === b)); }));
        $(".dur", card).onchange = (e) => (this.sel[k].dur = +e.target.value);
        $(".launch", card).onclick = async () => {
          const running = card.classList.contains("live");
          try {
            if (running) await NG.api("/api/simulate/stop", { scenario: k });
            else await NG.api("/api/simulate/start", { scenario: k, intensity: this.sel[k].int, duration: this.sel[k].dur });
          } catch (e) { NG.toast("Could not start", e.message, "bad"); }
        };
      });
      this.slow = NG.throttle(() => this.feed(), 700);
      this.syncSim(S.sim); this.score(); this.feed();
      this.timer = setInterval(() => this.countdown(), 400);
    },
    unmount() { clearInterval(this.timer); },
    syncSim(list) {
      this.ends = {}; list.forEach((s) => (this.ends[s.key] = { until: Date.now() + s.remaining * 1000, dur: s.duration }));
      NG.$$(".scn").forEach((c) => { const on = !!this.ends[c.dataset.k]; c.classList.toggle("live", on);
        $(".launch", c).innerHTML = on ? NG.ic("stop") + "Stop" : NG.ic("play") + "Launch"; $(".launch", c).classList.toggle("danger", on); $(".launch", c).classList.toggle("primary", !on); });
      this.countdown();
    },
    countdown() {
      NG.$$(".scn").forEach((c) => { const e = this.ends[c.dataset.k], bar = $(".prog i", c);
        if (!e) { bar.style.width = "0%"; return; }
        const left = Math.max(0, (e.until - Date.now()) / 1000); bar.style.width = (100 - (left / e.dur) * 100) + "%"; });
    },
    score() {
      const ev = (S.stats && S.stats.ev) || {}, by = ev.by_class || {};
      if (!$("#sc-top")) return;
      $("#sc-top").innerHTML = `<div><span>Detection rate</span><b class="t-good">${ev.detection_rate == null ? "--" : NG.pct(ev.detection_rate)}</b></div>
        <div><span>False-positive rate</span><b>${ev.fpr == null ? "--" : NG.pct(ev.fpr, 2)}</b></div>
        <div><span>Attack flows</span><b>${NG.n((ev.tp || 0) + (ev.fn || 0))}</b></div><div><span>Benign flows</span><b>${NG.n((ev.fp || 0) + (ev.tn || 0))}</b></div>`;
      const rows = Object.keys(by).filter((k) => k !== "Benign");
      $("#sc-body").innerHTML = rows.length ? rows.map((k) => { const v = by[k], f = v.flagged / v.total, c = v.correct / v.total;
        return `<tr><td>${NG.chip(k)}</td><td class="r num">${NG.n(v.total)}</td><td><span class="conf"><i style="width:${f * 100}%"></i></span><span class="num muted">${NG.pct(f)}</span></td><td><span class="conf"><i style="width:${c * 100}%"></i></span><span class="num muted">${NG.pct(c)}</span></td></tr>`; }).join("")
        : `<tr><td colspan="4"><div class="empty"><b>No attacks launched yet</b>Pick a scenario above.</div></td></tr>`;
    },
    feed() {
      if (!$("#sc-feed")) return;
      const l = NG.incList().slice(0, 8);
      $("#sc-feed").innerHTML = l.length ? l.map((i) => `<tr class="click" data-id="${i.id}"><td>${NG.chip(i.label)}</td><td>${NG.sev(i.severity)}</td><td class="mono muted">${NG.esc(i.src)}</td><td class="r num">${NG.n(i.count)}</td></tr>`).join("")
        : `<tr><td><div class="empty"><b>Quiet</b>Incidents will appear as soon as an attack is detected.</div></td></tr>`;
      NG.$$("#sc-feed tr[data-id]").forEach((r) => (r.onclick = () => NG.openIncident(r.dataset.id)));
    },
    onEvent(type, d) { if (type === "sim") this.syncSim(d); else if (type === "tick") this.score(); else if (type === "incident") this.slow(); },
  };

  /* ============================ PAYLOAD INSPECTOR ============================ */
  NG.views.inspector = {
    mount(el) {
      el.innerHTML = `<div class="grid g-e">
        <div class="panel"><div class="panel-h"><div><h3>Request or payload</h3><div class="sub">Paste an HTTP request, URL, log line or command</div></div></div>
          <div class="panel-b"><div class="samples" id="i-samples"></div>
            <textarea class="textarea" id="i-in" rows="9" spellcheck="false" placeholder="GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1"></textarea>
            <div class="row-tools" style="margin-top:12px"><button class="btn primary" id="i-go">${NG.ic("search")}Inspect payload</button><span class="muted small">Analysed locally by the signature engine. URL-decoded twice before matching.</span></div></div></div>
        <div class="panel"><div class="panel-h"><div><h3>Result</h3><div class="sub">Signature and heuristic findings</div></div></div><div class="panel-b" id="i-out"><div class="empty"><b>Nothing inspected yet</b>Choose a sample or paste your own payload.</div></div></div></div>`;
      NG.api("/api/inspect/samples").then((s) => {
        this.samples = s;
        $("#i-samples").innerHTML = Object.keys(s).map((k) => `<button class="btn sm" data-k="${NG.esc(k)}">${NG.esc(k)}</button>`).join("");
        NG.$$("#i-samples button").forEach((b) => (b.onclick = () => { $("#i-in").value = s[b.dataset.k]; this.run(); }));
      });
      $("#i-go").onclick = () => this.run();
    },
    async run() {
      const payload = $("#i-in").value; if (!payload.trim()) { NG.toast("Enter a payload first"); return; }
      const r = await NG.api("/api/inspect", { payload });
      const col = r.risk >= 70 ? "#ff5470" : r.risk >= 35 ? "#ffc83d" : "#38d9a9";
      const hl = (h) => { const c = h.context, m = h.match, i = c.indexOf(m); return i < 0 ? NG.esc(c) : NG.esc(c.slice(0, i)) + "<mark>" + NG.esc(m) + "</mark>" + NG.esc(c.slice(i + m.length)); };
      $("#i-out").innerHTML = `<div class="verdict">${NG.gauge(r.risk, "risk score", col)}<div><h3 style="color:${col}">${r.verdict}</h3>
          <p class="muted">${r.hits.length ? `${r.hits.length} rule${r.hits.length > 1 ? "s" : ""} matched` : "No attack signatures matched"}. ${r.length} characters, ${r.entropy} bits/char entropy.</p>
          ${r.notes.map((n) => `<p class="small muted">${NG.esc(n)}</p>`).join("")}</div></div>
        ${r.hits.map((h) => `<div class="hit"><div class="hit-h"><span class="sev ${["", "Low", "Medium", "High", "Critical"][h.severity]}">${["", "Low", "Medium", "High", "Critical"][h.severity]}</span><b>${NG.esc(h.name)}</b><span class="mono faint">${h.id}</span></div>
          <p class="muted small">${NG.esc(h.description)} <span class="faint">${NG.esc(h.reference)}</span></p><pre class="code">${hl(h)}</pre></div>`).join("")}
        ${r.decoded ? `<details class="feat"><summary>Decoded payload</summary><pre class="code">${NG.esc(r.decoded)}</pre></details>` : ""}`;
    },
  };

  /* ============================== GUIDED DEMO ============================== */
  const nar = () => $("#narrator");
  NG.demo = {
    running: false, abort: false, skip: null, total: 0,

    wait(sec) {
      return new Promise((res, rej) => {
        const t = setTimeout(done, sec * 1000);
        const iv = setInterval(() => { if (NG.demo.abort) { cleanup(); rej("abort"); } }, 150);
        function cleanup() { clearTimeout(t); clearInterval(iv); NG.demo.skip = null; }
        function done() { cleanup(); res(); }
        NG.demo.skip = done;
      });
    },
    say(i, title, text, sec) {
      nar().hidden = false;
      nar().innerHTML = `<div class="nar-top"><span class="step">Step ${i} of ${this.total}</span><span><button class="btn ghost sm" id="n-skip">Skip step</button><button class="btn ghost sm" id="n-end">End demo</button></span></div>
        <h3>${NG.esc(title)}</h3><p>${text}</p><div class="nar-bar"><i style="transition-duration:${sec}s"></i></div>`;
      requestAnimationFrame(() => requestAnimationFrame(() => { const b = $(".nar-bar i", nar()); if (b) b.style.width = "100%"; }));
      $("#n-skip").onclick = () => this.skip && this.skip();
      $("#n-end").onclick = () => this.stop();
    },
    stop() { this.abort = true; nar().hidden = true; this.setBtn(false); },
    setBtn(on) { const b = $("#run-demo"); if (b) b.innerHTML = on ? NG.ic("stop") + "Stop demo" : NG.ic("play") + "Run guided demo"; },
    launch(k, intensity, duration) { return NG.api("/api/simulate/start", { scenario: k, intensity, duration }); },
    firstOf(label) { return NG.incList().find((i) => i.label === label); },

    async start() {
      if (this.running) { this.stop(); return; }
      this.running = true; this.abort = false; this.setBtn(true);
      const steps = [
        ["Normal traffic", "NeuroGuard is scoring about ten flows every second. Each one passes through the neural network, which labels it <b>Benign</b>. This is the baseline the autoencoder learns to recognise.", 8, async () => {}],
        ["Reconnaissance: port scan", "One external host probes thousands of ports. Every probe is a one-packet SYN flow with no payload. The ANN recognises it from packet count, duration and TCP flags alone.", 15, () => this.launch("portscan", 3, 14)],
        ["Credential brute force", "Rapid, regular, short SSH, FTP and RDP sessions. Notice the incident correlation: hundreds of detections collapse into one incident per attacker.", 15, () => this.launch("bruteforce", 3, 14)],
        ["Web attack, confirmed by payload", "The ANN flags abnormal HTTP flows. The signature engine then confirms the cause from the request content: SQL injection, XSS, traversal, Log4Shell.", 14, () => this.launch("webattack", 3, 13)],
        ["Explain a verdict", "Opening the web-attack incident. The attribution bars show which flow features pushed the network toward its verdict, and the payload matches the signatures.", 12, async () => {
          location.hash = "#/incidents"; await NG.sleep(500);
          const i = this.firstOf("Web Attack"); if (!i) return;
          await NG.openIncident(i.id);
          (async () => {                       // detached: walk the audience down the drawer while the narrator talks
            const d = $("#drawer"), hs = () => NG.$$("h4", d), go = (txt) => { const h = hs().find((x) => x.textContent.startsWith(txt)); if (h) d.scrollTo({ top: h.offsetTop - 18, behavior: "smooth" }); };
            await NG.sleep(3200); go("Why the model"); await NG.sleep(4200); go("Payload evidence");
          })();
        }],
        ["Distributed denial of service", "Dozens of sources flood the web server with SYN floods, HTTP floods and slowloris connections. Back on the dashboard, watch the severity climb and the threat level change.", 16, async () => { NG.drawer.close(); location.hash = "#/overview"; await this.launch("dos", 4, 15); }],
        ["Compromised hosts", "A workstation beacons to a command-and-control server at machine-regular intervals, while a server quietly pushes data out over HTTPS. Both are Critical.", 16, async () => { await this.launch("botnet", 3, 15); await this.launch("exfil", 3, 15); await this.launch("infiltration", 3, 15); }],
        ["The unknown: a zero-day", "This behaviour matches <b>no trained class</b>. A classifier alone would force it into the nearest known attack family. The autoencoder and the embedding-distance test see that it is far from normal traffic <i>and</i> from every known attack, and raise a Zero-Day Anomaly.", 18, () => this.launch("zeroday", 4, 17)],
        ["Active response", "Switching on auto-response. Sources of confirmed attacks are now blocked at the sensor, and their later flows are dropped before they reach the network.", 14, async () => { await NG.api("/api/settings", { auto_block: true }); await this.launch("dos", 4, 13); await this.launch("portscan", 4, 13); }],
        ["Results", "", 0, async () => { await NG.api("/api/settings", { auto_block: false }); }],
      ];
      this.total = steps.length;
      try {
        await NG.api("/api/reset", {});
        await NG.api("/api/settings", { baseline_rate: 10, sim_paused: false, auto_block: false, anomaly: true, min_conf: 0.7 });
        location.hash = "#/overview"; await NG.sleep(500);
        for (let i = 0; i < steps.length; i++) {
          const [title, text, sec, fn] = steps[i];
          if (i === steps.length - 1) break;
          this.say(i + 1, title, text, sec); await fn(); await this.wait(sec);
        }
        await steps[steps.length - 1][3]();
        const ev = S.stats.ev || {}, t = S.stats.totals || {};
        this.say(steps.length, "Results", `Across <b>${NG.n(t.flows || 0)}</b> flows the ANN pipeline reached a <b>${NG.pct(ev.detection_rate)}</b> detection rate with a <b>${NG.pct(ev.fpr, 2)}</b> false-positive rate, opened <b>${S.incidents.size}</b> correlated incidents and blocked <b>${NG.n(t.blocked || 0)}</b> hostile flows. Open the Model lab to see how the network was trained.`, 0);
        $(".nar-bar", nar()).remove(); $("#n-skip").remove(); $("#n-end").textContent = "Close";
        await this.wait(600000);
      } catch (e) { if (e !== "abort") console.error(e); }
      finally { this.running = false; this.setBtn(false); nar().hidden = true; }
    },
  };
})();
