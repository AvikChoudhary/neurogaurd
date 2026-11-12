/* Console core: boot sequence, live event stream, hash router, side drawer. */
(function () {
  const S = NG.S;
  const TITLES = {
    overview: ["Overview", "Real-time view of everything the ANN is analysing"],
    traffic: ["Live traffic", "Every flow, as it is classified"],
    incidents: ["Incidents", "Correlated detections with evidence, MITRE mapping and response"],
    simulator: ["Attack simulator", "Launch realistic attacks and watch the ANN detect them"],
    inspector: ["Payload inspector", "Signature and heuristic analysis of request content"],
    model: ["Model lab", "Architecture, training results and explainability"],
    capture: ["Live capture", "Analyse real packets from this machine's network interface"],
    settings: ["Settings", "Detection sensitivity, response mode and data"],
  };

  NG.emit = (type, data) => { const v = NG.current; if (v && v.onEvent) v.onEvent(type, data); };
  NG.incList = () => Array.from(S.incidents.values()).sort((a, b) => b.first - a.first);

  /* ---------------- boot ---------------- */
  NG.boot = async function () {
    try {
      const [st, stats, incs] = await Promise.all([NG.api("/api/status"), NG.api("/api/stats"), NG.api("/api/incidents?limit=500")]);
      S.status = st; S.intel = st.intel; S.classes = st.classes; S.assets = st.assets; S.scenarios = st.scenarios;
      S.severity = st.severity; S.settings = st.settings; S.model = st.model; S.stats = stats; S.series = stats.series || [];
      S.blocklist = stats.blocklist || [];
      S.cum = { ...(stats.by_class || {}) }; delete S.cum.Benign;
      S.top = stats.top_attackers || [];
      incs.forEach((i) => S.incidents.set(i.id, i));
    } catch (e) {
      document.getElementById("view").innerHTML = `<div class="panel"><div class="empty"><b>Cannot reach the NeuroGuard server</b>Start it with <code>python run.py</code> and reload this page.</div></div>`;
      return;
    }
    renderEngineMeta();
    connect();
    NG.$("#run-demo").onclick = () => NG.demo.start();
    NG.$("#menu-btn").onclick = () => NG.$("#rail").classList.toggle("open");
    NG.$("#nav").addEventListener("click", () => NG.$("#rail").classList.remove("open"));
    addEventListener("hashchange", route);
    addEventListener("keydown", (e) => { if (e.key === "Escape") NG.drawer.close(); });
    NG.$("#scrim").onclick = () => NG.drawer.close();
    route();
  };

  function renderEngineMeta() {
    const m = S.model || {};
    NG.$("#eng-meta").textContent = m.loaded
      ? `ANN ${m.accuracy ? (m.accuracy * 100).toFixed(1) + "% accuracy" : "loaded"} / ${S.status.os}` : "Model not loaded";
  }

  /* ---------------- live stream ---------------- */
  let lastToast = 0;
  function connect() {
    const es = new EventSource("/api/stream");
    es.onopen = () => { S.connected = true; setConn(true); resync(); };
    es.onerror = () => { S.connected = false; setConn(false); };
    const on = (t, fn) => es.addEventListener(t, (e) => { try { fn(JSON.parse(e.data)); } catch (x) { console.error(t, x); } });

    on("tick", (d) => {
      S.tick = d; S.stats = S.stats || {};
      S.series.push({ t: d.t, flows: d.flows, threats: d.threats, benign: d.benign, blocked: d.blocked, bytes: d.bytes });
      if (S.series.length > 300) S.series.shift();
      for (const k in d.by_class) S.cum[k] = (S.cum[k] || 0) + d.by_class[k];
      S.top = d.top || S.top;
      S.stats.totals = d.totals; S.stats.ev = d.ev; S.stats.latency = d.latency; S.stats.level = d.level; S.stats.active = d.active; S.stats.mode = d.mode;
      setLevel(d.level);
      const c = NG.$("#nav-inc"); c.hidden = !d.active; c.textContent = d.active;
      NG.emit("tick", d);
    });
    on("incident", (d) => {
      const prev = S.incidents.get(d.id);
      S.incidents.set(d.id, { ...(prev || {}), ...d });
      if (d.new && d.sev >= 3 && Date.now() - lastToast > 2500) {
        lastToast = Date.now();
        NG.toast(`${d.severity}: ${d.label}`, `${d.src} to ${d.dst}`, "bad");
      }
      NG.emit("incident", d);
    });
    on("flows", (rows) => {
      S.flows.unshift(...rows.reverse()); if (S.flows.length > 300) S.flows.length = 300;
      NG.emit("flows", rows);
    });
    on("sim", (d) => { S.sim = d; NG.emit("sim", d); });
    on("settings", (d) => { S.settings = d; NG.emit("settings", d); });
    on("blocklist", (d) => { S.blocklist = d; NG.emit("blocklist", d); });
    on("train", (d) => NG.emit("train", d));
    on("capture", (d) => NG.emit("capture", d));
    on("model", (d) => { S.model = d; renderEngineMeta(); NG.emit("model", d); });
    on("reset", () => { S.incidents.clear(); S.flows = []; S.series = []; S.sim = []; S.cum = {}; S.top = []; NG.$("#nav-inc").hidden = true; NG.emit("reset", {}); route(); });
  }

  async function resync() {
    try { const st = await NG.api("/api/stats"); S.stats = st; S.series = st.series || S.series; S.blocklist = st.blocklist; } catch (e) {}
  }

  function setConn(ok) {
    NG.$("#conn-dot").className = "dot " + (ok ? "ok" : "bad");
    NG.$("#conn-text").textContent = ok ? "Live engine connected" : "Reconnecting...";
  }
  function setLevel(l) {
    const el = NG.$("#level"); el.className = "level lv-" + l; NG.$("#level-t").textContent = "Threat level: " + l;
  }

  /* ---------------- router ---------------- */
  function route() {
    const name = (location.hash.replace(/^#\/?/, "") || "overview").split("?")[0];
    const key = NG.views[name] ? name : "overview";
    if (NG.current && NG.current.unmount) NG.current.unmount();
    const [t, sub] = TITLES[key];
    NG.$("#title").textContent = t; NG.$("#subtitle").textContent = sub; document.title = `${t} | NeuroGuard`;
    NG.$$("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.r === key));
    const host = NG.$("#view");
    host.innerHTML = ""; NG.current = NG.views[key];
    NG.current.mount(host);
    setLevel((S.stats && S.stats.level) || "Normal");
    host.focus({ preventScroll: true });
  }
  NG.route = route;

  /* ---------------- drawer ---------------- */
  NG.drawer = {
    open(html) {
      const d = NG.$("#drawer"); d.innerHTML = `<button class="btn ghost sm x" aria-label="Close details">${NG.ic("x")}</button>${html}`;
      NG.$(".x", d).onclick = NG.drawer.close; d.classList.add("open"); d.setAttribute("aria-hidden", "false"); NG.$("#scrim").hidden = false; document.body.classList.add("drawer-open");
    },
    close() { NG.$("#drawer").classList.remove("open"); NG.$("#drawer").setAttribute("aria-hidden", "true"); NG.$("#scrim").hidden = true; document.body.classList.remove("drawer-open"); },
  };
})();
