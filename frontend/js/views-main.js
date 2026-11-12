/* Views: Overview, Live traffic, Incidents (+ incident drawer) */
(function () {
  const S = NG.S, $ = NG.$;
  const srcText = (i) => NG.esc(i.src) + (i.sources_count > 1 ? ` <span class="faint">+${i.sources_count - 1}</span>` : "");
  const dstText = (i) => NG.esc(i.dst) + (i.targets_count > 1 ? ` <span class="faint">+${i.targets_count - 1}</span>` : "");
  const fval = (v) => (Math.abs(v) >= 1000 ? NG.n(v) : Number.isInteger(v) ? String(v) : (+v).toFixed(2));
  const open = (id) => NG.openIncident(id);

  const incRows = (list, compact) => list.map((i) => `<tr class="click" data-id="${i.id}">
      <td class="mono muted">${NG.time(i.first)}</td><td>${NG.chip(i.label)}</td><td>${NG.sev(i.severity)}</td>
      <td class="mono">${srcText(i)} <span class="faint">to</span> ${dstText(i)}</td>
      <td class="r num">${NG.n(i.count)}</td>${compact ? "" : `<td>${NG.confBar(i.conf_max)}</td><td class="mono muted">${i.mitre || "--"}</td>`}
      <td>${NG.statusBadge(i.status)}</td></tr>`).join("");
  const bindRows = (root) => NG.$$("tr[data-id]", root).forEach((r) => (r.onclick = () => open(r.dataset.id)));

  /* =============================== OVERVIEW =============================== */
  NG.views.overview = {
    mount(el) {
      el.innerHTML = `
      <section class="kpis panel" aria-label="Key metrics">
        <div class="kpi"><span>Flows analysed</span><b id="k1">0</b><small id="k1s">0 / s</small></div>
        <div class="kpi"><span>Threats detected</span><b id="k2" class="t-bad">0</b><small id="k2s">0% of flows</small></div>
        <div class="kpi"><span>Active incidents</span><b id="k3">0</b><small id="k3s">0 total</small></div>
        <div class="kpi"><span>Detection rate</span><b id="k4" class="t-good">--</b><small id="k4s">Run an attack to measure</small></div>
        <div class="kpi"><span>Blocked flows</span><b id="k5">0</b><small id="k5s">0 sources blocked</small></div>
        <div class="kpi"><span>ANN latency</span><b id="k6">--</b><small>per flow</small></div>
      </section>
      <div class="grid g-a">
        <div class="panel"><div class="panel-h"><div><h3>Network activity</h3><div class="sub">Flows per second, split by verdict</div></div>
          <div class="legend"><span><i style="background:#38d9a9"></i>Benign</span><span><i style="background:#ff5470"></i>Threats</span></div></div>
          <div class="panel-b"><canvas id="c-live" class="cv" style="height:300px"></canvas></div></div>
        <div class="panel"><div class="panel-h"><div><h3>Live network</h3><div class="sub">Each particle is a flow crossing the ANN sensor</div></div></div>
          <div class="panel-b"><canvas id="c-topo" class="cv" style="height:300px"></canvas></div></div>
      </div>
      <div class="grid g-3">
        <div class="panel"><div class="panel-h"><div><h3>Threat mix</h3><div class="sub">By attack family, since start</div></div></div>
          <div class="panel-b donut-b"><canvas id="c-donut" class="cv" style="height:150px;width:150px"></canvas><div id="d-leg" class="dleg"></div></div></div>
        <div class="panel"><div class="panel-h"><h3>Top sources by detections</h3></div><div class="panel-b" id="top-src"></div></div>
        <div class="panel"><div class="panel-h"><h3>Incidents by severity</h3></div><div class="panel-b" id="sev-bars"></div></div>
      </div>
      <div class="grid g-c">
        <div class="panel"><div class="panel-h"><h3>Recent incidents</h3><a href="#/incidents">View all</a></div>
          <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source / target</th><th class="r">Hits</th><th>Status</th></tr></thead><tbody id="rec"></tbody></table></div></div>
        <div class="panel"><div class="panel-h"><h3>Flow feed</h3><a href="#/traffic">Open</a></div>
          <div class="tbl-wrap"><table class="tbl"><tbody id="feed"></tbody></table></div></div>
      </div>`;
      this.live = new NG.LiveChart($("#c-live"), [{ key: "benign", color: "#38d9a9", label: "Benign" }, { key: "threats", color: "#ff5470", label: "Threats" }]);
      this.topo = new NG.Topology($("#c-topo")); this.topo.setAssets(S.assets); this.topo.start();
      this.slow = NG.throttle(() => this.lists(), 500);
      this.tickUI(); this.lists(); this.live.set(S.series.slice(-120));
    },
    unmount() { if (this.topo) this.topo.stop(); },
    tickUI() {
      const t = (S.stats && S.stats.totals) || {}, ev = (S.stats && S.stats.ev) || {}, tk = S.tick || {};
      const set = (id, v) => { const e = $("#" + id); if (e) e.textContent = v; };
      set("k1", NG.n(t.flows || 0)); set("k1s", NG.n(tk.flows || 0) + " / s");
      set("k2", NG.n(t.threats || 0)); set("k2s", t.flows ? ((t.threats / t.flows) * 100).toFixed(1) + "% of flows" : "0% of flows");
      set("k3", S.stats.active || 0); set("k3s", S.incidents.size + " total");
      set("k4", ev.detection_rate == null ? "--" : NG.pct(ev.detection_rate));
      set("k4s", ev.detection_rate == null ? "Run an attack to measure" : "False positives " + NG.pct(ev.fpr, 2));
      set("k5", NG.n(t.blocked || 0)); set("k5s", S.blocklist.length + " sources blocked");
      set("k6", S.stats.latency ? S.stats.latency.toFixed(3) + " ms" : "--");
    },
    lists() {
      if (!$("#rec")) return;
      const list = NG.incList();
      $("#rec").innerHTML = list.length ? incRows(list.slice(0, 7), true) : `<tr><td colspan="6"><div class="empty"><b>No incidents yet</b>Launch an attack from the simulator and it will appear here.</div></td></tr>`;
      bindRows($("#rec"));
      $("#feed").innerHTML = S.flows.slice(0, 9).map((f) => `<tr><td class="mono muted">${NG.time(f.t)}</td><td>${NG.chip(f.label)}</td><td class="mono">${NG.esc(f.src)} <span class="faint">to</span> ${NG.esc(f.dst)}:${f.dport}</td></tr>`).join("");
      const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
      list.forEach((i) => { if (sev[i.severity] !== undefined) sev[i.severity]++; });
      $("#sev-bars").innerHTML = NG.hbars(Object.entries(sev).map(([k, v]) => [k, v, `var(--sev-${k.toLowerCase()})`]), { max: Math.max(3, ...Object.values(sev)) });
      $("#top-src").innerHTML = (S.top && S.top.length) ? NG.hbars(S.top.slice(0, 6).map(([ip, n]) => [ip, n, "var(--threat)"])) : `<div class="muted">No hostile sources yet.</div>`;
    },
    donut() {
      const items = Object.entries(S.cum || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v, color: NG.color(k) }));
      NG.donut($("#c-donut"), items, { small: "threats" });
      $("#d-leg").innerHTML = items.length ? items.slice(0, 7).map((i) => `<div><span class="chip" style="--c:${i.color}">${NG.esc(i.label)}</span><b class="num">${NG.n(i.value)}</b></div>`).join("") : `<div class="muted">Waiting for threats...</div>`;
    },
    onEvent(type, d) {
      if (type === "tick") { this.tickUI(); this.live.set(S.series.slice(-120)); this.donut(); this.slow(); }
      else if (type === "incident") this.slow();
      else if (type === "flows") { d.forEach((f) => this.topo.pulse(f)); this.slow(); }
      else if (type === "blocklist") this.tickUI();
    },
  };

  /* ================================ TRAFFIC ================================ */
  NG.views.traffic = {
    paused: false, only: false,
    mount(el) {
      el.innerHTML = `<div class="panel"><div class="panel-h"><div><h3>Flow stream</h3><div class="sub">A sample of analysed flows, newest first</div></div>
        <div class="row-tools"><label class="check"><span class="toggle"><input type="checkbox" id="t-only"><span></span></span>Threats only</label>
        <button class="btn sm" id="t-pause">${NG.ic("stop")}Pause</button></div></div>
        <div class="tbl-wrap tall"><table class="tbl"><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Port</th><th>Proto</th><th>Verdict</th><th>Confidence</th><th>Origin</th></tr></thead><tbody id="t-body"></tbody></table></div></div>`;
      this.paused = false; this.only = false;
      $("#t-only").onchange = (e) => { this.only = e.target.checked; this.render(); };
      $("#t-pause").onclick = (e) => { this.paused = !this.paused; e.currentTarget.innerHTML = this.paused ? NG.ic("play") + "Resume" : NG.ic("stop") + "Pause"; if (!this.paused) this.render(); };
      this.slow = NG.throttle(() => !this.paused && this.render(), 400);
      this.render();
    },
    render() {
      if (!$("#t-body")) return;
      const rows = S.flows.filter((f) => !this.only || f.label !== "Benign").slice(0, 120);
      $("#t-body").innerHTML = rows.length ? rows.map((f) => `<tr><td class="mono muted">${NG.time(f.t)}</td><td class="mono">${NG.esc(f.src)}</td><td class="mono">${NG.esc(f.dst)}</td>
        <td class="mono">${f.dport}</td><td class="muted">${f.proto}</td><td>${NG.chip(f.label)}</td><td>${NG.confBar(f.conf)}</td><td class="muted">${f.source === "live" ? "Live capture" : "Simulation"}</td></tr>`).join("")
        : `<tr><td colspan="8"><div class="empty"><b>Waiting for traffic</b>Flows appear here as soon as the engine classifies them.</div></td></tr>`;
    },
    onEvent(type) { if (type === "flows") this.slow(); },
  };

  /* =============================== INCIDENTS =============================== */
  NG.views.incidents = {
    f: { q: "", sev: "", label: "", status: "" },
    mount(el) {
      const opts = (arr, all) => `<option value="">${all}</option>` + arr.map((a) => `<option>${a}</option>`).join("");
      el.innerHTML = `<div class="panel"><div class="panel-h"><div><h3>All incidents</h3><div class="sub" id="i-count"></div></div>
        <div class="row-tools"><a class="btn sm" href="/api/export/incidents.csv">${NG.ic("download")}CSV</a><a class="btn sm" href="/api/export/incidents.json">${NG.ic("download")}JSON</a></div></div>
        <div class="filters"><input class="input" id="f-q" placeholder="Search by ID, IP or type" value="${NG.esc(this.f.q)}" aria-label="Search incidents">
          <select class="select" id="f-sev" aria-label="Severity">${opts(["Critical", "High", "Medium", "Low"], "All severities")}</select>
          <select class="select" id="f-label" aria-label="Type">${opts(S.classes.filter((c) => c !== "Benign"), "All types")}</select>
          <select class="select" id="f-status" aria-label="Status">${opts(["active", "closed", "mitigated", "resolved"], "All statuses")}</select></div>
        <div class="tbl-wrap tall"><table class="tbl"><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source / target</th><th class="r">Detections</th><th>Confidence</th><th>MITRE</th><th>Status</th></tr></thead><tbody id="i-body"></tbody></table></div></div>`;
      $("#f-sev").value = this.f.sev; $("#f-label").value = this.f.label; $("#f-status").value = this.f.status;
      const upd = () => { this.f = { q: $("#f-q").value, sev: $("#f-sev").value, label: $("#f-label").value, status: $("#f-status").value }; this.render(); };
      ["f-q", "f-sev", "f-label", "f-status"].forEach((id) => ($("#" + id).oninput = upd));
      this.slow = NG.throttle(() => this.render(), 700); this.render();
    },
    render() {
      if (!$("#i-body")) return;
      const f = this.f, q = f.q.toLowerCase();
      const list = NG.incList().filter((i) => (!f.sev || i.severity === f.sev) && (!f.label || i.label === f.label) && (!f.status || i.status === f.status) &&
        (!q || `${i.id} ${i.src} ${i.dst} ${i.label}`.toLowerCase().includes(q)));
      $("#i-count").textContent = `${list.length} shown of ${S.incidents.size}`;
      $("#i-body").innerHTML = list.length ? incRows(list.slice(0, 250)) : `<tr><td colspan="8"><div class="empty"><b>No incidents match</b>Start an attack in the simulator, or clear the filters.</div></td></tr>`;
      bindRows($("#i-body"));
    },
    onEvent(type) { if (type === "incident") this.slow(); },
  };

  /* ============================ INCIDENT DRAWER ============================ */
  NG.openIncident = async function (id) {
    NG.drawer.open(`<div class="empty">Loading ${id}...</div>`);
    let d;
    try { d = await NG.api("/api/incidents/" + id); } catch (e) { NG.drawer.open(`<div class="empty"><b>Incident not found</b></div>`); return; }
    const ev = d.evidence || {}, probs = Object.entries(ev.probs || {}).sort((a, b) => b[1] - a[1]);
    const ae = ev.ae_ratio || 0, nv = ev.nov_ratio || 0;
    const feats = Object.entries(ev.features || {});
    const sigs = (ev.signatures || []);
    NG.drawer.open(`
      <div class="dr-h"><div class="dr-t">${NG.chip(d.label)}${NG.sev(d.severity)}${NG.statusBadge(d.status)}</div>
        <h2>${d.id}: ${NG.esc(d.label)}</h2><p class="muted">${NG.esc(d.description)}</p></div>
      <dl class="meta">
        <div><dt>Source</dt><dd class="mono">${NG.esc(d.src)}${d.sources_count > 1 ? ` <span class="faint">+${d.sources_count - 1} more</span>` : ""}</dd></div>
        <div><dt>Target</dt><dd class="mono">${NG.esc(d.dst)}${d.targets_count > 1 ? ` <span class="faint">+${d.targets_count - 1} more</span>` : ""}</dd></div>
        <div><dt>First seen</dt><dd>${NG.time(d.first)}</dd></div>
        <div><dt>Duration</dt><dd>${NG.dur(d.last - d.first)}</dd></div>
        <div><dt>Detections</dt><dd class="num">${NG.n(d.count)}</dd></div>
        <div><dt>Peak confidence</dt><dd class="num">${NG.pct(d.conf_max)}</dd></div>
        <div><dt>Ports seen</dt><dd class="mono">${d.top_ports.join(", ") || "--"}${d.ports_count > 5 ? ` <span class="faint">(${NG.n(d.ports_count)} unique)</span>` : ""}</dd></div>
        <div><dt>MITRE ATT&amp;CK</dt><dd>${d.mitre ? `<span class="mono">${d.mitre}</span> ${NG.esc(d.mitre_name)}` : NG.esc(d.mitre_name)}</dd></div>
      </dl>
      ${Object.keys(d.alts || {}).length ? `<p class="note">Correlated: also seen as ${Object.entries(d.alts).map(([k, v]) => `${NG.esc(k)} x${v}`).join(", ")} from the same source.</p>` : ""}
      <h4>ANN verdict</h4>
      <div class="sec">${NG.hbars(probs.slice(0, 5).map(([k, v]) => [k, v, NG.color(k)]), { max: 1, fmt: (v) => (v * 100).toFixed(1) + "%" })}
        <div class="ae"><span>Autoencoder: distance from normal</span><b class="${ae >= 1 ? "t-bad" : "t-good"}">${ae.toFixed(1)}x</b><span class="muted">${ae >= 1 ? "above threshold" : "within normal range"}</span></div>
        <div class="ae"><span>Embedding: distance from known attacks</span><b class="${nv >= 1 ? "t-bad" : "t-good"}">${nv.toFixed(1)}x</b><span class="muted">${nv >= 1 ? "unlike any trained class" : "close to a known class"}</span></div>
        ${d.label === "Zero-Day Anomaly" && ev.nearest ? `<div class="ae"><span>Closest known class</span><b style="font-size:15px">${NG.esc(ev.nearest)}</b></div>` : ""}</div>
      <h4>Why the model flagged it</h4>
      <div class="sec explain">${(() => { const mx = Math.max(0.01, ...(ev.explain || []).map((e) => Math.abs(e.impact))); return (ev.explain || []).map((e) => ({ ...e, w: Math.abs(e.impact) / mx })); })().map((e) => `<div class="ex"><span class="n">${NG.esc(e.feature)}</span><span class="mono muted">${fval(e.value)}</span>
        <span class="track"><span class="fill ${e.impact < 0 ? "neg" : ""}" style="width:${Math.max(4, e.w * 100)}%"></span></span><span class="v num">${NG.attr(e.impact)}</span></div>`).join("")}
        <p class="faint small">Gradient x input attribution on the evidence flow. Positive values pushed the network toward this verdict.</p></div>
      ${ev.payload ? `<h4>Payload evidence</h4><div class="sec"><pre class="code">${NG.esc(ev.payload)}</pre>
        ${sigs.map((s) => `<div class="sig"><span class="sev ${["", "Low", "Medium", "High", "Critical"][s.severity]}">${NG.esc(s.id)}</span> <b>${NG.esc(s.name)}</b><div class="muted small">${NG.esc(s.description)} <span class="faint">${NG.esc(s.reference)}</span></div></div>`).join("") || `<p class="muted">No signature matched the payload.</p>`}</div>` : ""}
      <h4>Recommended response</h4>
      <ol class="play">${d.playbook.map((p) => `<li>${NG.esc(p)}</li>`).join("")}</ol>
      <details class="feat"><summary>Observed flow features (${feats.length})</summary><div class="fgrid">${feats.map(([k, v]) => `<span class="muted">${NG.esc(k)}</span><span class="mono">${fval(v)}</span>`).join("")}</div></details>
      <div class="dr-act"><button class="btn danger" id="a-block" ${d.blocked ? "disabled" : ""}>${NG.ic("ban")}${d.blocked ? "Source blocked" : d.sources_count > 1 ? "Block all sources" : "Block source"}</button>
        <button class="btn" id="a-res" ${d.status === "resolved" ? "disabled" : ""}>${NG.ic("check")}Mark resolved</button></div>`);
    const act = async (a, msg) => { try { await NG.api(`/api/incidents/${id}/action`, { action: a }); NG.toast(msg, id, "good"); NG.openIncident(id); } catch (e) { NG.toast("Action failed", e.message, "bad"); } };
    $("#a-block").onclick = () => act("block", "Source(s) blocked at the sensor");
    $("#a-res").onclick = () => act("resolve", "Incident resolved");
  };
})();
