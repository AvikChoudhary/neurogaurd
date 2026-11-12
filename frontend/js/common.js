/* NeuroGuard console: shared utilities. Everything hangs off the global NG object. */
window.NG = {
  views: {},
  S: {                       // shared state
    status: null, intel: {}, classes: [], assets: [], scenarios: {}, severity: [],
    stats: null, series: [], incidents: new Map(), flows: [], sim: [], settings: {}, blocklist: [],
    tick: null, connected: false, model: null,
  },
};

NG.esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
NG.$ = (sel, root = document) => root.querySelector(sel);
NG.$$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

NG.n = (v) => (v == null ? "--" : Math.abs(v) >= 1e6 ? (v / 1e6).toFixed(2) + "M" : Math.abs(v) >= 1e4 ? (v / 1e3).toFixed(1) + "k" : Math.round(v).toLocaleString());
NG.pct = (v, d = 1) => (v == null ? "--" : (v * 100).toFixed(d) + "%");
NG.bytes = (b) => { const u = ["B", "KB", "MB", "GB"]; let i = 0; b = b || 0; while (b >= 1024 && i < 3) { b /= 1024; i++; } return b.toFixed(i ? 1 : 0) + " " + u[i]; };
NG.time = (t) => new Date(t * 1000).toLocaleTimeString([], { hour12: false });
NG.dur = (s) => { s = Math.max(0, Math.round(s)); return s < 60 ? s + "s" : s < 3600 ? Math.floor(s / 60) + "m " + (s % 60) + "s" : Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m"; };
NG.ago = (t) => { const s = Date.now() / 1000 - t; return s < 5 ? "just now" : NG.dur(s) + " ago"; };

NG.ic = (name, cls = "ic") => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
NG.color = (label) => (NG.S.intel[label] && NG.S.intel[label].color) || "#8796b4";
NG.chip = (label) => `<span class="chip" style="--c:${NG.color(label)}">${NG.esc(label)}</span>`;
NG.sev = (s) => `<span class="sev ${NG.esc(s)}">${NG.esc(s)}</span>`;
NG.statusBadge = (s) => `<span class="status ${s}">${s[0].toUpperCase() + s.slice(1)}</span>`;
NG.confBar = (c) => `<span class="conf"><i style="width:${Math.round(c * 100)}%"></i></span><span class="num muted">${Math.round(c * 100)}%</span>`;

NG.hbars = (rows, { max, fmt = NG.n, colorOf } = {}) => {
  max = max || Math.max(1, ...rows.map((r) => r[1]));
  return rows.map(([name, v, c]) => `<div class="hbar"><span class="n" title="${NG.esc(name)}">${NG.esc(name)}</span>
    <span class="track"><span class="fill" style="width:${Math.max(1.5, (v / max) * 100)}%;--c:${c || (colorOf ? colorOf(name) : "var(--brand)")}"></span></span>
    <span class="v">${fmt(v)}</span></div>`).join("");
};

NG.api = async (path, body, method) => {
  const opt = { method: method || (body !== undefined ? "POST" : "GET"), headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
};

NG.toast = (title, msg = "", kind = "") => {
  const el = document.createElement("div");
  el.className = "toast " + kind;
  el.innerHTML = `<b>${NG.esc(title)}</b>${msg ? `<span>${NG.esc(msg)}</span>` : ""}`;
  document.getElementById("toasts").appendChild(el);
  setTimeout(() => { el.style.opacity = 0; el.style.transition = "opacity .3s"; setTimeout(() => el.remove(), 320); }, 3800);
};

NG.debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
// Leading+trailing throttle: guarantees live lists refresh at least every `ms` even under constant events
NG.throttle = (fn, ms) => { let last = 0, t = null; return (...a) => { const w = ms - (Date.now() - last); if (w <= 0) { last = Date.now(); fn(...a); } else if (!t) t = setTimeout(() => { t = null; last = Date.now(); fn(...a); }, w); }; };
NG.sleep = (ms) => new Promise((r) => setTimeout(r, ms));

NG.attr = (n) => (n >= 0 ? "+" : "") + (n * 100).toFixed(0) + "%";
