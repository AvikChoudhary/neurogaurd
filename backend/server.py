"""Flask application: REST API + Server-Sent Events stream + static front-end."""
import os
import platform
import queue
import threading
import time

import numpy as np
from flask import Flask, Response, jsonify, request, send_from_directory

from . import signatures
from .capture import LiveCapture, list_interfaces, scapy_available
from .detector import Detector
from .engine import Engine, dumps
from .schema import ALL_LABELS, CLASSES, FEATURES, INTEL, SEVERITY
from .simulator import ASSETS, SCENARIOS, Simulator
from .traffic import generate
from .train import MODEL_DIR, train_models

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND = os.path.join(ROOT, "frontend")


class Trainer:
    """Runs (re)training in a background thread and hot-swaps the model when finished."""

    def __init__(self, engine):
        self.e = engine
        self.state = {"running": False, "phase": "idle", "epoch": 0, "epochs": 0, "loss": 0, "val_loss": 0,
                      "acc": None, "val_acc": None, "message": "", "error": ""}
        self.lock = threading.Lock()

    def start(self, samples=40000, epochs=45):
        with self.lock:
            if self.state["running"]:
                return False
            self.state.update(running=True, phase="data", epoch=0, epochs=epochs, error="", message="Generating data")
        threading.Thread(target=self._run, args=(samples, epochs), daemon=True).start()
        return True

    def _cb(self, phase, ep, E, loss, vloss, acc, vacc):
        self.state.update(phase=phase, epoch=ep, epochs=E, loss=loss, val_loss=vloss, acc=acc, val_acc=vacc)
        if phase in ("data", "evaluating") or ep % 2 == 0 or ep == E:
            self.e.publish("train", self.state)

    def _run(self, samples, epochs):
        try:
            train_models(MODEL_DIR, n_samples=samples, epochs=epochs, seed=int(time.time()) % 10000, callback=self._cb)
            self.e.det.load()
            self.state.update(running=False, phase="done", message="Model retrained and hot-swapped")
        except Exception as ex:   # surfaced in the UI
            self.state.update(running=False, phase="error", error=str(ex))
        self.e.publish("train", self.state)
        self.e.publish("model", self.e.det.summary())


def create_app(port=5000):
    app = Flask(__name__, static_folder=None)
    det = Detector()
    engine = Engine(det)
    sim = Simulator(engine)
    cap = LiveCapture(engine, dashboard_port=port)
    trainer = Trainer(engine)
    engine.start()
    sim.start()

    def J(obj, code=200):
        return Response(dumps(obj), status=code, mimetype="application/json")

    # ------------------------------------------------------------------ pages
    @app.route("/")
    def landing():
        return send_from_directory(FRONTEND, "index.html")

    @app.route("/console")
    def console():
        return send_from_directory(FRONTEND, "console.html")

    @app.route("/<path:p>")
    def static_files(p):
        return send_from_directory(FRONTEND, p)

    @app.after_request
    def no_cache(r):
        if request.path.startswith("/api/"):
            r.headers["Cache-Control"] = "no-store"
        return r

    # -------------------------------------------------------------- live stream
    @app.route("/api/stream")
    def stream():
        q = engine.subscribe()

        def gen():
            try:
                yield "retry: 2000\n\n"
                yield f"event: sim\ndata: {dumps(sim.state())}\n\n"
                while True:
                    try:
                        yield q.get(timeout=15)
                    except queue.Empty:
                        yield ": keep-alive\n\n"
            finally:
                engine.unsubscribe(q)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})

    # --------------------------------------------------------------- status/stats
    @app.route("/api/status")
    def status():
        ok, ver = scapy_available()
        return J({
            "name": "NeuroGuard IDS", "model": det.summary(), "classes": ALL_LABELS,
            "intel": {k: {"color": v["color"], "mitre": v["mitre"], "mitre_name": v["mitre_name"], "desc": v["desc"]}
                      for k, v in INTEL.items()},
            "severity": SEVERITY, "assets": ASSETS,
            "scenarios": {k: {kk: vv for kk, vv in v.items()} for k, v in SCENARIOS.items()},
            "os": platform.system(), "python": platform.python_version(), "scapy": ok,
            "mode": engine.mode, "settings": engine.settings, "training": trainer.state,
        })

    @app.route("/api/stats")
    def stats():
        return J(engine.stats())

    # ---------------------------------------------------------------- incidents
    @app.route("/api/incidents")
    def incidents():
        a = request.args
        return J(engine.list_incidents(a.get("label") or None, a.get("severity") or None, a.get("status") or None,
                                       a.get("q") or None, int(a.get("limit", 300))))

    @app.route("/api/incidents/<iid>")
    def incident(iid):
        d = engine.detail(iid)
        return J(d) if d else J({"error": "not found"}, 404)

    @app.route("/api/incidents/<iid>/action", methods=["POST"])
    def incident_action(iid):
        r = engine.action(iid, (request.get_json(silent=True) or {}).get("action"))
        return J(r) if r else J({"error": "unknown incident or action"}, 404)

    @app.route("/api/blocklist/<ip>", methods=["DELETE"])
    def unblock(ip):
        engine.unblock(ip)
        return J({"ok": True})

    @app.route("/api/export/incidents.csv")
    def export_csv():
        return Response(engine.export_csv(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=neuroguard-incidents.csv"})

    @app.route("/api/export/incidents.json")
    def export_json():
        return Response(dumps(engine.export_json()), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=neuroguard-incidents.json"})

    @app.route("/api/reset", methods=["POST"])
    def reset():
        engine.reset()
        sim.stop_scenario()
        engine.publish("reset", {})
        return J({"ok": True})

    # ----------------------------------------------------------------- settings
    @app.route("/api/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            engine.set_settings(request.get_json(silent=True) or {})
        return J(engine.settings)

    # ---------------------------------------------------------------- simulator
    @app.route("/api/simulate/start", methods=["POST"])
    def sim_start():
        d = request.get_json(silent=True) or {}
        try:
            sim.start_scenario(d.get("scenario"), int(d.get("intensity", 3)), float(d.get("duration", 30)))
        except KeyError:
            return J({"error": "unknown scenario"}, 400)
        return J(sim.state())

    @app.route("/api/simulate/stop", methods=["POST"])
    def sim_stop():
        sim.stop_scenario((request.get_json(silent=True) or {}).get("scenario"))
        return J(sim.state())

    @app.route("/api/simulate/state")
    def sim_state():
        return J(sim.state())

    # ---------------------------------------------------------------- inspector
    @app.route("/api/inspect", methods=["POST"])
    def inspect_payload():
        return J(signatures.inspect((request.get_json(silent=True) or {}).get("payload", "")))

    @app.route("/api/inspect/samples")
    def inspect_samples():
        return J(signatures.SAMPLES)

    # -------------------------------------------------------------------- model
    @app.route("/api/model")
    def model():
        return J({**det.metrics, "summary": det.summary(), "training": trainer.state})

    @app.route("/api/model/train", methods=["POST"])
    def model_train():
        d = request.get_json(silent=True) or {}
        ok = trainer.start(int(min(120000, max(5000, d.get("samples", 40000)))), int(min(100, max(5, d.get("epochs", 45)))))
        return J({"started": ok, "training": trainer.state})

    @app.route("/api/analyze", methods=["POST"])
    def analyze():
        d = request.get_json(silent=True) or {}
        if "sample" in d:
            label = d["sample"]
            if label not in ALL_LABELS:
                return J({"error": "unknown class"}, 400)
            x = generate(label, 1, np.random.default_rng())[0]
        else:
            f = d.get("features", {})
            x = np.array([float(f.get(k, 0)) for k in FEATURES])
        res = det.analyze(x, engine.settings["min_conf"], engine.settings["anomaly"])
        res["features"] = {k: float(round(v, 3)) for k, v in zip(FEATURES, x)}
        return J(res)

    # ------------------------------------------------------------------ capture
    @app.route("/api/capture/status")
    def cap_status():
        return J({**cap.status(), "interfaces": list_interfaces() if scapy_available()[0] else []})

    @app.route("/api/capture/start", methods=["POST"])
    def cap_start():
        try:
            cap.start((request.get_json(silent=True) or {}).get("iface"))
        except Exception as ex:
            return J({"error": str(ex)}, 400)
        return J(cap.status())

    @app.route("/api/capture/stop", methods=["POST"])
    def cap_stop():
        cap.stop()
        return J(cap.status())

    app.engine, app.sim, app.cap, app.trainer = engine, sim, cap, trainer
    return app
