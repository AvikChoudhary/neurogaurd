/* Views: Model lab, Live capture, Settings */
(function () {
  const S = NG.S, $ = NG.$;
  const SHORT = { "Benign": "Benign", "DoS/DDoS": "DoS", "Port Scan": "Scan", "Brute Force": "Brute", "Web Attack": "Web", "Botnet C2": "Botnet", "Data Exfiltration": "Exfil", "Infiltration": "Lateral" };
  const fv = (v) => (Math.abs(v) >= 1000 ? Math.round(v) : Number.isInteger(v) ? v : +(+v).toFixed(2));

  /* ================================ MODEL LAB ================================ */
  NG.views.model = {
    async mount(el) {
      el.innerHTML = `<div class="empty">Loading model...</div>`;
      let m; try { m = await NG.api("/api/model"); } catch (e) { el.innerHTML = `<div class="empty"><b>Model unavailable</b>${NG.esc(e.message)}</div>`; return; }
      this.m = m;
      const a = m.architecture || {}, ae = m.ae || {}, cm = m.confusion || [], cls = m.classes || [];
      const rep = m.report || {};
      el.innerHTML = `
      <section class="kpis panel">
        <div class="kpi"><span>Test accuracy</span><b class="t-good">${NG.pct(m.accuracy)}</b><small>on ${NG.n(m.test)} unseen flows</small></div>
        <div class="kpi"><span>Macro F1</span><b>${(m.macro_f1 || 0).toFixed(3)}</b><small>mean across classes</small></div>
        <div class="kpi"><span>False-positive rate</span><b>${NG.pct(m.false_positive_rate, 2)}</b><small>benign flagged as attack</small></div>
        <div class="kpi"><span>Zero-day (bundled scenario)</span><b class="t-good">${NG.pct((m.novelty || ae || {}).zero_day_detection)}</b><small>flagged as unknown behaviour</small></div>
        <div class="kpi"><span>Parameters</span><b>${NG.n((a.params_classifier || 0) + (a.params_autoencoder || 0))}</b><small>classifier + autoencoder</small></div>
        <div class="kpi"><span>Trained</span><b class="sm-v">${NG.esc((m.trained_at || "").slice(0, 10))}</b><small>${NG.esc(m.data_source || "")}</small></div>
      </section>
      <div class="grid g-f">
        <div class="panel"><div class="panel-h"><div><h3>Architecture</h3><div class="sub">Two cooperating neural networks</div></div></div><div class="panel-b">
          <h4 class="mini">Classifier: which known attack is this flow?</h4>${NG.arch(a.classifier || [50, 128, 64, 32, 8], ["Input", "Dense + ReLU", "Dense + ReLU", "Dense + ReLU", "Softmax"])}
          <h4 class="mini">Autoencoder: how far is it from normal?</h4>${NG.arch(a.autoencoder || [50, 32, 12, 32, 50], ["Input", "Encode", "Bottleneck", "Decode", "Reconstruct"], "#38d9a9")}
          <div class="tags"><span class="chip" style="--c:#7cc4ff">Dropout ${a.dropout}</span><span class="chip" style="--c:#7cc4ff">${NG.esc(a.optimizer || "")}</span><span class="chip" style="--c:#7cc4ff">${NG.esc(a.loss || "")}</span><span class="chip" style="--c:#38d9a9">Autoencoder threshold: 99.9th percentile of benign error</span><span class="chip" style="--c:#b38cff">Novelty: Mahalanobis distance in the 32-d embedding</span></div></div></div>
        <div class="panel"><div class="panel-h"><div><h3>Training curves</h3><div class="sub">${m.epochs_run} epochs, early stopping on validation loss</div></div>
          <div class="legend"><span><i style="background:#7cc4ff"></i>Train</span><span><i style="background:#ffc83d"></i>Validation</span></div></div><div class="panel-b">
          <h4 class="mini">Loss</h4><canvas id="c-loss" class="cv" style="height:170px"></canvas><h4 class="mini">Accuracy</h4><canvas id="c-acc" class="cv" style="height:170px"></canvas></div></div>
      </div>
      <div class="grid g-g">
        <div class="panel"><div class="panel-h"><div><h3>Per-class performance</h3><div class="sub">Held-out test set</div></div></div><div class="tbl-wrap"><table class="tbl"><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th class="r">Support</th></tr></thead><tbody>
          ${cls.map((c) => { const r = rep[c] || {}; return `<tr><td>${NG.chip(c)}</td><td class="num">${NG.pct(r.precision)}</td><td class="num">${NG.pct(r.recall)}</td><td><span class="conf"><i style="width:${(r.f1 || 0) * 100}%"></i></span><span class="num muted">${(r.f1 || 0).toFixed(3)}</span></td><td class="r num">${NG.n(r.support)}</td></tr>`; }).join("")}</tbody></table></div></div>
        <div class="panel"><div class="panel-h"><div><h3>Confusion matrix</h3><div class="sub">Rows are the actual class, columns the prediction</div></div></div><div class="panel-b" id="cm"></div></div>
      </div>
      <div class="grid g-g">
        <div class="panel"><div class="panel-h"><div><h3>What the network pays attention to</h3><div class="sub">Global feature importance (mean absolute gradient x input)</div></div></div><div class="panel-b">${NG.hbars((m.importance || []).slice(0, 10).map(([k, v]) => [k, v * 100]), { max: Math.max(...(m.importance || [[0, 0.1]]).map((x) => x[1] * 100)), fmt: (v) => v.toFixed(1) + "%" })}</div></div>
        <div class="panel"><div class="panel-h"><div><h3>Retrain the models</h3><div class="sub">Generates fresh data, trains both networks, then hot-swaps them into the running engine</div></div></div><div class="panel-b" id="rt"></div></div>
      </div>
      <div class="panel"><div class="panel-h"><div><h3>Flow analyzer</h3><div class="sub">Generate a flow, edit any feature, and watch the ANN respond</div></div></div><div class="panel-b" id="fa"></div></div>`;
      NG.lineChart($("#c-loss"), [{ values: m.history.loss, color: "#7cc4ff" }, { values: m.history.val_loss, color: "#ffc83d", dash: [5, 4] }]);
      NG.lineChart($("#c-acc"), [{ values: m.history.acc, color: "#7cc4ff" }, { values: m.history.val_acc, color: "#ffc83d", dash: [5, 4] }], { yMin: Math.min(...m.history.val_acc) - 0.02, yMax: 1, fmt: (v) => (v * 100).toFixed(0) + "%" });
      this.matrix(cm, cls); this.retrain(); this.analyzer();
    },
    matrix(cm, cls) {
      const max = (r) => Math.max(1, r.reduce((a, b) => a + b, 0));
      $("#cm").innerHTML = `<div class="cm" style="grid-template-columns:70px repeat(${cls.length},1fr)"><span></span>${cls.map((c) => `<span class="cm-h">${SHORT[c]}</span>`).join("")}
        ${cm.map((row, i) => `<span class="cm-h l">${SHORT[cls[i]]}</span>` + row.map((v, j) => { const p = v / max(row); const c = i === j ? "124,196,255" : "255,84,112";
          return `<span class="cm-c" style="background:rgba(${c},${v ? Math.min(1, 0.08 + p * (i === j ? 0.8 : 3)) : 0})" title="Actual ${cls[i]} predicted ${cls[j]}: ${v} (${(p * 100).toFixed(1)}%)">${v || ""}</span>`; }).join("")).join("")}</div>`;
    },
    retrain() {
      $("#rt").innerHTML = `<div class="rt-form"><label class="field"><span>Training samples</span><select class="select" id="rt-n"><option value="20000">20,000 (fast)</option><option value="40000" selected>40,000</option><option value="80000">80,000</option></select></label>
        <label class="field"><span>Max epochs</span><select class="select" id="rt-e"><option>30</option><option selected>45</option><option>60</option></select></label>
        <button class="btn primary" id="rt-go">${NG.ic("refresh")}Retrain now</button></div>
        <div class="rt-prog" id="rt-p" hidden><div class="bar"><i id="rt-bar"></i></div><div class="muted small" id="rt-t"></div></div>
        <p class="faint small">To train on the real CIC-IDS2017 dataset instead, run <code>python -m backend.train --csv your_file.csv</code> and restart.</p>`;
      $("#rt-go").onclick = async () => { const r = await NG.api("/api/model/train", { samples: +$("#rt-n").value, epochs: +$("#rt-e").value }); if (!r.started) NG.toast("Training already running"); else { $("#rt-p").hidden = false; $("#rt-go").disabled = true; } };
      if (this.m.training && this.m.training.running) { $("#rt-p").hidden = false; $("#rt-go").disabled = true; }
    },
    analyzer() {
      const feats = this.m.features || [], labels = S.classes;
      $("#fa").innerHTML = `<div class="samples">${labels.map((c) => `<button class="btn sm" data-c="${NG.esc(c)}"><span class="dotc" style="background:${NG.color(c)}"></span>${NG.esc(c)}</button>`).join("")}</div>
        <div class="fa-grid">${feats.map((f, i) => `<label class="fa-f"><span title="${NG.esc(f)}">${NG.esc(f)}</span><input class="input" type="number" step="any" data-f="${NG.esc(f)}" value="0"></label>`).join("")}</div>
        <div class="row-tools" style="margin:14px 0"><button class="btn primary" id="fa-go">${NG.ic("zap")}Run ANN on these values</button><span class="muted small">Pick a class above to generate a typical flow, then change values and re-run.</span></div><div id="fa-out"></div>`;
      const fill = (f) => NG.$$("[data-f]").forEach((i) => (i.value = fv(f[i.dataset.f] ?? 0)));
      const show = (r) => {
        $("#fa-out").innerHTML = `<div class="fa-res"><div><div class="fa-v">${NG.chip(r.label)}</div><div class="muted small" style="margin-top:8px">Confidence <b class="num">${NG.pct(r.confidence)}</b><br>Autoencoder <b class="num ${r.ae_ratio >= 1 ? "t-bad" : "t-good"}">${r.ae_ratio.toFixed(1)}x</b> / embedding distance <b class="num ${r.nov_ratio >= 1 ? "t-bad" : "t-good"}">${r.nov_ratio.toFixed(1)}x</b> threshold</div></div>
          <div>${NG.hbars(Object.entries(r.probs).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => [k, v, NG.color(k)]), { max: 1, fmt: (v) => (v * 100).toFixed(1) + "%" })}</div>
          <div class="explain">${(() => { const t = r.explain.slice(0, 5), mx = Math.max(0.01, ...t.map((e) => Math.abs(e.impact))); return t.map((e) => ({ ...e, w: Math.abs(e.impact) / mx })); })().map((e) => `<div class="ex"><span class="n">${NG.esc(e.feature)}</span><span class="mono muted">${fv(e.value)}</span><span class="track"><span class="fill ${e.impact < 0 ? "neg" : ""}" style="width:${Math.max(4, e.w * 100)}%"></span></span><span class="v num">${NG.attr(e.impact)}</span></div>`).join("")}</div></div>`;
      };
      NG.$$("[data-c]").forEach((b) => (b.onclick = async () => { const r = await NG.api("/api/analyze", { sample: b.dataset.c }); fill(r.features); show(r); }));
      $("#fa-go").onclick = async () => { const f = {}; NG.$$("[data-f]").forEach((i) => (f[i.dataset.f] = parseFloat(i.value) || 0)); show(await NG.api("/api/analyze", { features: f })); };
    },
    onEvent(type, d) {
      if (type === "train") {
        const p = $("#rt-p"); if (!p) return; p.hidden = false;
        const pct = d.phase === "done" ? 100 : d.phase === "classifier" ? (d.epoch / d.epochs) * 55 : d.phase === "autoencoder" ? 55 + (d.epoch / d.epochs) * 40 : d.phase === "evaluating" ? 96 : 3;
        $("#rt-bar").style.width = pct + "%";
        $("#rt-t").textContent = d.error ? "Error: " + d.error : d.phase === "done" ? "Done. Models hot-swapped into the engine." : `${d.phase} ${d.epoch ? `epoch ${d.epoch}/${d.epochs}` : ""} ${d.val_acc ? "validation accuracy " + (d.val_acc * 100).toFixed(1) + "%" : ""}`;
        if (d.phase === "done") { NG.toast("Model retrained", "New weights are live", "good"); setTimeout(() => NG.route(), 900); }
        if (d.phase === "error") $("#rt-go").disabled = false;
      }
    },
  };

  /* =============================== LIVE CAPTURE =============================== */
  NG.views.capture = {
    async mount(el) {
      this.el = el; await this.load();
      this.timer = setInterval(() => this.poll(), 2000);
    },
    unmount() { clearInterval(this.timer); },
    async poll() { try { this.st = await NG.api("/api/capture/status"); this.stats(); } catch (e) {} },
    async load() {
      const st = (this.st = await NG.api("/api/capture/status"));
      const ok = (b, t, f) => `<span class="status ${b ? "mitigated" : "active"}">${b ? t : f}</span>`;
      this.el.innerHTML = `<div class="grid g-h">
        <div class="panel"><div class="panel-h"><div><h3>Capture control</h3><div class="sub">Sniff this machine's network interface and classify real flows with the same ANN</div></div></div><div class="panel-b">
          <div class="cap-checks"><div><span>Scapy library</span>${ok(st.available, "Installed " + (st.scapy || ""), "Not installed")}</div><div><span>Privileges</span>${ok(st.admin, "Administrator / root", "Not elevated")}</div><div><span>Operating system</span><b>${NG.esc(st.os)}</b></div></div>
          ${st.available ? `<label class="field" style="margin-top:16px"><span>Interface</span><select class="select" id="cap-if"><option value="">System default</option>${(st.interfaces || []).map((i) => `<option value="${NG.esc(i.id)}">${NG.esc(i.label)}</option>`).join("")}</select></label>
            <div class="row-tools" style="margin-top:14px"><button class="btn primary" id="cap-go">${NG.ic("radio")}${st.running ? "Capturing..." : "Start capture"}</button><button class="btn" id="cap-stop" ${st.running ? "" : "disabled"}>${NG.ic("stop")}Stop</button></div>` :
            `<div class="note" style="margin-top:16px">Install the optional capture library, then restart NeuroGuard:<pre class="code">pip install scapy</pre></div>`}
          <div class="cap-stats" id="cap-stats"></div>
          <p class="faint small">While capturing, simulated background traffic is paused so you only see real flows. Only monitor networks you own or are authorised to monitor.</p></div></div>
        <div class="panel"><div class="panel-h"><div><h3>Setup by operating system</h3><div class="sub">Packet capture needs elevated rights on every platform</div></div></div><div class="panel-b">
          <div class="seg" id="os-tabs">${["Windows", "macOS", "Linux"].map((o) => `<button data-o="${o}" class="${o === st.os ? "on" : ""}">${o}</button>`).join("")}</div><div id="os-body" style="margin-top:16px"></div></div></div></div>`;
      const OS = {
        Windows: ["Install <b>Npcap</b> from npcap.com and tick <i>WinPcap API-compatible mode</i>.", "Open VS Code or PowerShell <b>as Administrator</b>.", "<code>pip install scapy</code> then <code>python run.py</code>.", "Choose the Wi-Fi or Ethernet adapter in the list."],
        macOS: ["<code>pip install scapy</code> inside your virtual environment.", "Start with <code>sudo venv/bin/python run.py</code> so Python can open the BPF devices.", "Pick <b>en0</b> (Wi-Fi) or the interface you want."],
        Linux: ["<code>pip install scapy</code> inside your virtual environment.", "Run <code>sudo venv/bin/python run.py</code>, or grant the capability once: <code>sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python)</code>.", "Pick <b>eth0</b>, <b>wlan0</b>, or <b>any</b>."],
      };
      const show = (o) => ($("#os-body").innerHTML = `<ol class="play">${OS[o].map((s) => `<li>${s}</li>`).join("")}</ol>`);
      show(st.os in OS ? st.os : "Windows");
      NG.$$("#os-tabs button").forEach((b) => (b.onclick = () => { NG.$$("#os-tabs button").forEach((x) => x.classList.toggle("on", x === b)); show(b.dataset.o); }));
      if (st.available) {
        $("#cap-go").onclick = async () => { try { await NG.api("/api/capture/start", { iface: $("#cap-if").value || null }); NG.toast("Capture started", "Analysing live traffic", "good"); this.load(); } catch (e) { NG.toast("Could not start capture", e.message, "bad"); } };
        $("#cap-stop").onclick = async () => { await NG.api("/api/capture/stop", {}); NG.toast("Capture stopped"); this.load(); };
      }
      this.stats();
    },
    stats() {
      const st = this.st, b = $("#cap-stats"); if (!b) return;
      b.innerHTML = [["Status", st.running ? "Capturing" : "Idle"], ["Packets", NG.n(st.packets)], ["Flows analysed", NG.n(st.flows)], ["Open flows", NG.n(st.open_flows)]].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join("");
    },
    onEvent(type, d) { if (type === "capture") { this.st = { ...this.st, ...d }; this.stats(); } },
  };

  /* ================================= SETTINGS ================================= */
  NG.views.settings = {
    mount(el) {
      const s = S.settings;
      const tog = (id, on, label, sub) => `<div class="set-row"><div><b>${label}</b><div class="muted small">${sub}</div></div><label class="toggle"><input type="checkbox" id="${id}" ${on ? "checked" : ""}><span></span></label></div>`;
      el.innerHTML = `<div class="grid g-i"><div class="panel"><div class="panel-h"><h3>Detection</h3></div><div class="panel-b">
          <div class="set-row col"><div><b>Confidence threshold</b><div class="muted small">Minimum ANN confidence before a flow is reported as an attack. Lower catches more attacks but raises false alarms.</div></div>
            <div class="slider"><input type="range" id="st-conf" min="30" max="99" value="${Math.round(s.min_conf * 100)}"><b class="num" id="st-conf-v">${Math.round(s.min_conf * 100)}%</b></div></div>
          ${tog("st-ae", s.anomaly, "Zero-day anomaly detection", "Use the autoencoder to flag traffic that matches no known class.")}
          ${tog("st-ab", s.auto_block, "Auto-response (IPS mode)", "Automatically block the sources of confirmed attacks (confidence of 90% or more). Servers are never blocked.")}
          ${tog("st-sp", s.sim_paused, "Pause simulated traffic", "Stops all background and scenario traffic from the simulator.")}</div></div>
        <div class="panel"><div class="panel-h"><div><h3>Blocked sources</h3><div class="sub">Flows from these addresses are dropped before analysis</div></div></div><div class="tbl-wrap"><table class="tbl"><tbody id="bl"></tbody></table></div></div>
        <div class="panel"><div class="panel-h"><h3>Data</h3></div><div class="panel-b"><p class="muted">Clear every incident, counter and blocked source. Useful right before a presentation.</p>
          <div class="row-tools" style="margin-top:12px"><button class="btn danger" id="st-reset">${NG.ic("trash")}Reset all data</button></div></div></div>
        <div class="panel"><div class="panel-h"><h3>About</h3></div><div class="panel-b about"><div><span>Engine</span><b>NeuroGuard IDS</b></div><div><span>Host OS</span><b>${NG.esc(S.status.os)}</b></div><div><span>Python</span><b>${NG.esc(S.status.python)}</b></div><div><span>Model trained</span><b>${NG.esc((S.model && S.model.version) || "--")}</b></div></div></div></div>`;
      const push = (o) => NG.api("/api/settings", o);
      $("#st-conf").oninput = (e) => ($("#st-conf-v").textContent = e.target.value + "%");
      $("#st-conf").onchange = (e) => push({ min_conf: e.target.value / 100 });
      $("#st-ae").onchange = (e) => push({ anomaly: e.target.checked });
      $("#st-ab").onchange = (e) => { push({ auto_block: e.target.checked }); NG.toast(e.target.checked ? "Auto-response enabled" : "Auto-response disabled", "", e.target.checked ? "good" : ""); };
      $("#st-sp").onchange = (e) => push({ sim_paused: e.target.checked });
      $("#st-reset").onclick = async () => { if (confirm("Clear all incidents, statistics and blocked sources?")) { await NG.api("/api/reset", {}); NG.toast("All data cleared", "", "good"); } };
      this.list();
    },
    list() {
      const b = $("#bl"); if (!b) return;
      b.innerHTML = S.blocklist.length ? S.blocklist.map((x) => `<tr><td class="mono">${NG.esc(x.ip)}</td><td class="muted small">${NG.esc(x.reason)}</td><td class="r"><button class="btn sm" data-ip="${NG.esc(x.ip)}">Unblock</button></td></tr>`).join("") : `<tr><td><div class="empty"><b>No blocked sources</b>Use Block on an incident, or enable auto-response.</div></td></tr>`;
      NG.$$("[data-ip]", b).forEach((x) => (x.onclick = () => NG.api(`/api/blocklist/${encodeURIComponent(x.dataset.ip)}`, undefined, "DELETE")));
    },
    onEvent(type) { if (type === "blocklist") this.list(); },
  };
})();
