"""
Detection engine.

    flows --> blocklist (IPS drop) --> ANN classifier + autoencoder --> verdict
          --> alert correlation (many detections -> one incident) --> severity / MITRE / playbook
          --> live broadcast (Server-Sent Events) + statistics + response actions
"""
import csv
import io
import json
import queue
import threading
import time
from collections import Counter, OrderedDict, deque, defaultdict

import numpy as np

from . import signatures
from .detector import Detector
from .schema import ANOMALY, CLASSES, FEATURES, INTEL, SEVERITY, ALL_LABELS

MIN_HITS = 3                # detections required before an incident is raised (suppresses one-off noise)
INCIDENT_GAP = 8.0          # seconds of silence before an incident is closed
MAX_INCIDENTS = 1500
PROTECTED_PREFIX = "10.0.2."  # servers are never auto-quarantined

DEFAULT_SETTINGS = {"min_conf": 0.70, "anomaly": True, "auto_block": False,
                    "baseline_rate": 8, "sim_paused": False}


def _default(o):
    if isinstance(o, np.generic):
        return o.item()
    if isinstance(o, (set, tuple)):
        return list(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def dumps(o):
    return json.dumps(o, default=_default)


class Engine:
    def __init__(self, detector: Detector):
        self.det = detector
        self.lock = threading.RLock()
        self.subs = set()
        self.settings = dict(DEFAULT_SETTINGS)
        self.mode = "simulation"
        self.started = time.time()
        self._stop = False
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self):
        with self.lock:
            self.counters = Counter()
            self.by_class = Counter()
            self.by_sev = Counter()
            self.attackers = Counter()
            self.incidents = OrderedDict()
            self.open = {}
            self.by_src = {}
            self.blocklist = {}
            self.dirty = set()
            self.seq = 0
            self.series = deque(maxlen=300)
            self.win = Counter()
            self.win_cls = Counter()
            self.win_bytes = 0.0
            self.lat = 0.0
            self.ev = Counter()                       # simulation ground-truth evaluation
            self.ev_cls = defaultdict(lambda: [0, 0, 0])   # truth -> [total, flagged, correct label]

    def set_settings(self, d):
        with self.lock:
            if "min_conf" in d:
                self.settings["min_conf"] = float(min(0.99, max(0.30, float(d["min_conf"]))))
            if "baseline_rate" in d:
                self.settings["baseline_rate"] = int(min(150, max(0, int(d["baseline_rate"]))))
            for k in ("anomaly", "auto_block", "sim_paused"):
                if k in d:
                    self.settings[k] = bool(d[k])
        self.publish("settings", self.settings)
        return self.settings

    # ---------------------------------------------------------------- pub/sub
    def subscribe(self):
        q = queue.Queue(maxsize=600)
        self.subs.add(q)
        return q

    def unsubscribe(self, q):
        self.subs.discard(q)

    def publish(self, event, data):
        msg = f"event: {event}\ndata: {dumps(data)}\n\n"
        for q in list(self.subs):
            try:
                q.put_nowait(msg)
            except queue.Full:
                try:
                    q.get_nowait(); q.put_nowait(msg)
                except Exception:
                    pass

    # --------------------------------------------------------------- pipeline
    def process(self, X, meta):
        """X: (n, 31) raw flow features, meta: list of dicts (src,dst,sport,dport,proto,source,[truth,payload])."""
        X = np.asarray(X, dtype=float)
        if len(X) == 0 or not self.det.loaded:
            return
        with self.lock:
            keep = [i for i, m in enumerate(meta) if m["src"] not in self.blocklist]
            nb = len(meta) - len(keep)
            if nb:
                self.counters["blocked"] += nb
                self.win["blocked"] += nb
        if not keep:
            return
        Xk, mk = X[keep], [meta[i] for i in keep]
        t0 = time.perf_counter()
        r = self.det.infer(Xk)
        per_flow_ms = (time.perf_counter() - t0) * 1000.0 / len(Xk)

        threats, benign = [], []
        with self.lock:
            s = self.settings
            self.lat = per_flow_ms if self.lat == 0 else 0.9 * self.lat + 0.1 * per_flow_ms
            now = time.time()
            for j, m in enumerate(mk):
                pred, conf, ae, nov = int(r["pred"][j]), float(r["conf"][j]), float(r["ae"][j]), float(r["nov"][j])
                label = Detector.verdict(pred, conf, ae, s["min_conf"], s["anomaly"], nov)
                threat = label != "Benign"
                if label == ANOMALY:
                    conf = min(0.99, 0.55 + 0.1 * float(np.log2(1 + max(ae, nov))))
                self.counters["flows"] += 1
                self.win["flows"] += 1
                self.win_bytes += float(Xk[j, 4] + Xk[j, 5])
                truth = m.get("truth")
                if truth is not None:
                    attack = truth != "Benign"
                    self.ev["tp" if attack and threat else "fn" if attack else "fp" if threat else "tn"] += 1
                    row = self.ev_cls[truth]
                    row[0] += 1
                    row[1] += int(threat)
                    row[2] += int(label == truth)
                self.by_class[label] += 1
                row = {"t": now, "src": m["src"], "dst": m["dst"], "sport": m.get("sport", 0),
                       "dport": int(Xk[j, 0]), "proto": m.get("proto", "TCP"), "label": label,
                       "conf": round(conf, 3), "source": m.get("source", "sim")}
                if threat:
                    self.counters["threats"] += 1
                    self.win["threats"] += 1
                    self.win_cls[label] += 1
                    if label == ANOMALY:
                        self.counters["anomalies"] += 1
                    self.attackers[m["src"]] += 1
                    self._record(label, conf, m, Xk[j], r["probs"][j], (ae, nov), now)
                    threats.append(row)
                else:
                    benign.append(row)
        sample = threats[:3] + benign[:2]
        if sample:
            self.publish("flows", sample)

    # -------------------------------------------------------------- incidents
    def _severity(self, inc):
        v = INTEL[inc["label"]]["base"]
        if inc["count"] >= 100:
            v += 1
        if inc["conf_sum"] / inc["count"] < 0.70:
            v -= 1
        return int(min(4, max(1, v)))

    def _evidence(self, label, conf, m, x, probs, ae):
        ev = {
            "features": {n: float(round(v, 3)) for n, v in zip(FEATURES, x)},
            "probs": {CLASSES[i]: float(p) for i, p in enumerate(probs)},
            "ae_ratio": round(float(ae[0]), 2), "nov_ratio": round(float(ae[1]), 2), "conf": round(float(conf), 3),
            "nearest": max(CLASSES, key=lambda c: probs[CLASSES.index(c)]),
            "explain": self.det.explain(x, label),
        }
        pl = m.get("payload")
        if pl:
            ev["payload"] = pl
            ev["signatures"] = signatures.inspect(pl)["hits"]
        return ev

    def _record(self, label, conf, m, x, probs, ae, now):
        src, dst = m["src"], m["dst"]
        key = (label, dst) if label == "DoS/DDoS" else (label, src)
        inc = self.open.get(key)
        if inc is not None and now - inc["last"] > INCIDENT_GAP:
            inc = None
        if inc is None:
            # Correlation: a stray verdict from a source that already has an established incident of a
            # different type is folded into that incident instead of opening a new, noisy one.
            dom = self.by_src.get(src)
            if (dom is not None and dom["label"] != label and now - dom["last"] <= INCIDENT_GAP and dom["count"] >= 5
                    and sum(dom["alts"].values()) + 1 <= 0.25 * dom["count"]):
                dom["alts"][label] += 1
                dom["count"] += 1
                dom["conf_sum"] += conf
                dom["last"] = now
                self.dirty.add(dom["id"])
                return
            # New candidate. It stays "pending" (invisible, no ID) until it accumulates MIN_HITS detections,
            # so isolated one-flow false alarms never reach the analyst.
            inc = {"id": None, "label": label, "src": src, "dst": dst, "first": now,
                   "last": now, "count": 0, "conf_sum": 0.0, "conf_max": 0.0, "status": "pending",
                   "ports": set(), "port_top": Counter(), "sources": set(), "targets": set(),
                   "alts": Counter(), "source": m.get("source", "sim"), "severity": 1, "evidence": None}
            self.open[key] = inc
        self.by_src[src] = inc
        if len(inc["targets"]) < 500:
            inc["targets"].add(dst)
        inc["count"] += 1
        inc["conf_sum"] += conf
        inc["last"] = now
        if len(inc["sources"]) < 500:
            inc["sources"].add(src)
        if len(inc["ports"]) < 70000:
            inc["ports"].add(int(x[0]))
        if len(inc["port_top"]) < 64 or int(x[0]) in inc["port_top"]:
            inc["port_top"][int(x[0])] += 1
        if conf > inc["conf_max"] + 0.05 or inc["evidence"] is None:
            inc["evidence"] = self._evidence(label, conf, m, x, probs, ae)
        inc["conf_max"] = max(inc["conf_max"], conf)

        new = False
        if inc["status"] == "pending":
            if inc["count"] < MIN_HITS:
                return
            self.seq += 1
            inc["id"], inc["status"], new = f"INC-{self.seq:04d}", "active", True
            self.incidents[inc["id"]] = inc
            while len(self.incidents) > MAX_INCIDENTS:
                self.incidents.popitem(last=False)
        elif inc["status"] == "closed":
            inc["status"] = "active"

        sev = self._severity(inc)
        if sev != inc["severity"]:
            inc["severity"] = sev
        # active response (IPS mode)
        if (self.settings["auto_block"] and label != ANOMALY and conf >= 0.9 and
                src not in self.blocklist and not src.startswith(PROTECTED_PREFIX)):
            self._block(src, f"Auto-response: {label} ({inc['id']})", auto=True)
            if inc["status"] != "resolved":
                inc["status"] = "mitigated"
            self.dirty.add(inc["id"])
        if new:
            self.publish("incident", self.summary(inc, new=True))
        else:
            self.dirty.add(inc["id"])

    def summary(self, inc, new=False):
        intel = INTEL[inc["label"]]
        srcs = list(inc["sources"])
        return {
            "id": inc["id"], "label": inc["label"], "severity": SEVERITY[inc["severity"]], "sev": inc["severity"],
            "src": inc["src"], "dst": inc["dst"], "sources_count": len(srcs), "first": inc["first"],
            "last": inc["last"], "count": inc["count"], "conf_max": round(inc["conf_max"], 3),
            "conf_avg": round(inc["conf_sum"] / max(inc["count"], 1), 3), "status": inc["status"],
            "ports_count": len(inc["ports"]), "targets_count": max(1, len(inc["targets"])),
            "alts": dict(inc["alts"]), "top_ports": [p for p, _ in inc["port_top"].most_common(5)],
            "mitre": intel["mitre"], "mitre_name": intel["mitre_name"], "source": inc["source"],
            "blocked": inc["src"] in self.blocklist, "new": new,
        }

    def detail(self, iid):
        with self.lock:
            inc = self.incidents.get(iid)
            if not inc:
                return None
            d = self.summary(inc)
            intel = INTEL[inc["label"]]
            d.update({"evidence": inc["evidence"], "description": intel["desc"], "playbook": intel["playbook"],
                      "sources": sorted(inc["sources"])[:40], "targets": sorted(inc["targets"])[:40], "color": intel["color"]})
            return d

    def list_incidents(self, label=None, severity=None, status=None, q=None, limit=300):
        with self.lock:
            out = []
            for inc in reversed(self.incidents.values()):
                if label and inc["label"] != label:
                    continue
                if severity and SEVERITY[inc["severity"]] != severity:
                    continue
                if status and inc["status"] != status:
                    continue
                if q and q.lower() not in f"{inc['id']} {inc['src']} {inc['dst']} {inc['label']}".lower():
                    continue
                out.append(self.summary(inc))
                if len(out) >= limit:
                    break
            return out

    # --------------------------------------------------------------- response
    def _block(self, ip, reason, auto=False):
        self.blocklist[ip] = {"since": time.time(), "reason": reason, "auto": auto}
        self.publish("blocklist", self.blocklist_view())

    def blocklist_view(self):
        return [{"ip": ip, **v} for ip, v in self.blocklist.items()]

    def action(self, iid, act):
        with self.lock:
            inc = self.incidents.get(iid)
            if not inc:
                return None
            if act == "block":
                targets = list(inc["sources"]) or [inc["src"]]
                for ip in targets:
                    if ip not in self.blocklist:
                        self._block(ip, f"Analyst action on {iid}")
                inc["status"] = "mitigated"
            elif act == "resolve":
                inc["status"] = "resolved"
            else:
                return None
            self.open = {k: v for k, v in self.open.items() if v["id"] != iid}
            s = self.summary(inc)
        self.publish("incident", s)
        return s

    def unblock(self, ip):
        with self.lock:
            self.blocklist.pop(ip, None)
        self.publish("blocklist", self.blocklist_view())

    # ------------------------------------------------------------------ ticks
    def start(self):
        threading.Thread(target=self._tick_loop, daemon=True).start()

    def _level(self):
        mx = 0
        for inc in self.open.values():
            if inc["status"] == "active":
                mx = max(mx, inc["severity"])
        return ["Normal", "Normal", "Elevated", "High", "Critical"][mx]

    def _tick_loop(self):
        while not self._stop:
            time.sleep(1.0)
            with self.lock:
                now = time.time()
                for key, inc in list(self.open.items()):
                    if now - inc["last"] > INCIDENT_GAP:
                        if inc["status"] == "active":
                            inc["status"] = "closed"
                        if inc["id"]:
                            self.dirty.add(inc["id"])
                        del self.open[key]
                self.by_src = {k: v for k, v in self.by_src.items() if now - v["last"] <= INCIDENT_GAP}
                w = self.win
                tick = {"t": now, "flows": w["flows"], "threats": w["threats"], "benign": w["flows"] - w["threats"],
                        "blocked": w["blocked"], "bytes": self.win_bytes, "by_class": dict(self.win_cls),
                        "latency": round(self.lat, 4), "level": self._level(), "mode": self.mode,
                        "active": sum(1 for i in self.incidents.values() if i["status"] == "active"),
                        "totals": dict(self.counters), "ev": self.eval_summary(),
                        "top": self.attackers.most_common(8)}
                self.series.append({k: tick[k] for k in ("t", "flows", "threats", "benign", "blocked", "bytes")})
                self.win, self.win_cls, self.win_bytes = Counter(), Counter(), 0.0
                dirty = [self.summary(self.incidents[i]) for i in self.dirty if i in self.incidents]
                self.dirty.clear()
            self.publish("tick", tick)
            for d in dirty:
                self.publish("incident", d)

    # ------------------------------------------------------------- statistics
    def eval_summary(self):
        e = self.ev
        att, ben = e["tp"] + e["fn"], e["fp"] + e["tn"]
        return {"tp": e["tp"], "fn": e["fn"], "fp": e["fp"], "tn": e["tn"],
                "detection_rate": (e["tp"] / att) if att else None, "fpr": (e["fp"] / ben) if ben else None,
                "by_class": {k: {"total": v[0], "flagged": v[1], "correct": v[2]} for k, v in self.ev_cls.items()}}

    def stats(self):
        with self.lock:
            sev = Counter(SEVERITY[i["severity"]] for i in self.incidents.values())
            return {
                "totals": dict(self.counters), "by_class": dict(self.by_class), "by_severity": dict(sev),
                "top_attackers": self.attackers.most_common(8), "series": list(self.series)[-120:],
                "incidents_total": len(self.incidents),
                "active": sum(1 for i in self.incidents.values() if i["status"] == "active"),
                "blocklist": self.blocklist_view(), "settings": self.settings, "latency": round(self.lat, 4),
                "level": self._level(), "uptime": time.time() - self.started, "ev": self.eval_summary(),
                "mode": self.mode,
            }

    # ----------------------------------------------------------------- export
    def export_csv(self):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "type", "severity", "status", "source", "target", "first_seen", "last_seen", "detections",
                    "max_confidence", "mitre", "origin"])
        with self.lock:
            for inc in self.incidents.values():
                f = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
                w.writerow([inc["id"], inc["label"], SEVERITY[inc["severity"]], inc["status"], inc["src"], inc["dst"],
                            f(inc["first"]), f(inc["last"]), inc["count"], round(inc["conf_max"], 3),
                            INTEL[inc["label"]]["mitre"], inc["source"]])
        return buf.getvalue()

    def export_json(self):
        with self.lock:
            return [self.summary(i) for i in self.incidents.values()]
