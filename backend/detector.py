"""
Hybrid ANN detector.

  1. Classifier ANN (MLP, softmax)  -> which known attack family a flow belongs to
  2. Autoencoder ANN                -> how far the flow is from learned *normal* behaviour
                                       (catches zero-day / never-seen-before activity)
  3. Explainability                 -> gradient x input attribution for every verdict
"""
import json
import os
import numpy as np

from .ann import MLP
from .schema import (CLASSES, ANOMALY, FEATURES, Preprocessor, column_groups, N_CLASSES)
from .train import MODEL_DIR, MODEL_FILE, METRICS_FILE, novelty_distance

GROUPS = column_groups()
FEATURE_INDEX = {n: i for i, n in enumerate(FEATURES)}


class Detector:
    def __init__(self, model_dir=MODEL_DIR):
        self.model_dir = model_dir
        self.loaded = False
        self.metrics = {}
        self.version = "-"
        self.load()

    @staticmethod
    def exists(model_dir=MODEL_DIR):
        return os.path.exists(os.path.join(model_dir, MODEL_FILE))

    def load(self):
        path = os.path.join(self.model_dir, MODEL_FILE)
        if not os.path.exists(path):
            self.loaded = False
            return False
        d = np.load(path, allow_pickle=False)
        clf, ae = MLP.from_state(d, "clf"), MLP.from_state(d, "ae")
        pp, thr = Preprocessor.from_state(d), float(d["ae_threshold"])
        nov = (d["nov_mu"], d["nov_prec"], float(d["nov_thr"]), [int(i) for i in d["nov_present"]])
        mp = os.path.join(self.model_dir, METRICS_FILE)
        metrics = {}
        if os.path.exists(mp):
            with open(mp, encoding="utf-8") as fh:
                metrics = json.load(fh)
        # swap everything at once so a hot-reload during retraining is atomic
        self.clf, self.ae, self.pp, self.threshold, self.nov, self.metrics = clf, ae, pp, thr, nov, metrics
        self.version = metrics.get("trained_at", "unknown")
        self.loaded = True
        return True

    # ------------------------------------------------------------------ inference
    def infer(self, X_raw):
        Xs = self.pp.transform(X_raw)
        P = self.clf.predict_proba(Xs)
        err = ((self.ae.reconstruct(Xs) - Xs) ** 2).mean(1)
        mu, prec, nthr, present = self.nov
        nov = novelty_distance(self.clf.embed(Xs), mu, prec, present) / nthr
        return {"pred": P.argmax(1), "conf": P.max(1), "probs": P, "ae": err / self.threshold, "nov": nov}

    @staticmethod
    def verdict(pred, conf, ae_ratio, min_conf=0.7, anomaly=True, nov=0.0):
        # 1. far from EVERY known class in the ANN's embedding -> unknown behaviour, whatever the classifier says
        if anomaly and nov >= 1.0:
            return ANOMALY
        # 2. confident known attack
        if pred != 0 and conf >= min_conf:
            return CLASSES[pred]
        if anomaly and ae_ratio >= 1.0:
            return ANOMALY
        return "Benign"

    # -------------------------------------------------------------- explainability
    def explain(self, x_raw, label, top=6):
        x_raw = np.asarray(x_raw, dtype=float).reshape(1, -1)
        Xs = self.pp.transform(x_raw)
        if label == ANOMALY:
            contrib = (self.ae.reconstruct(Xs) - Xs)[0] ** 2
            sign = 1.0
        else:
            c = CLASSES.index(label) if label in CLASSES else int(self.clf.predict_proba(Xs).argmax())
            contrib = (self.clf.input_gradient(Xs, np.array([c])) * Xs)[0]
            sign = 1.0
        agg = {}
        for col, v in enumerate(contrib):
            agg[GROUPS[col]] = agg.get(GROUPS[col], 0.0) + float(v) * sign
        total = sum(abs(v) for v in agg.values()) or 1.0
        rows = sorted(agg.items(), key=lambda kv: -abs(kv[1]))[:top]
        return [{"feature": k, "value": float(x_raw[0, FEATURE_INDEX[k]]), "impact": v / total} for k, v in rows]

    def analyze(self, x_raw, min_conf=0.7, anomaly=True):
        """Full single-flow analysis used by the Flow Analyzer tool."""
        r = self.infer(np.asarray(x_raw, dtype=float).reshape(1, -1))
        pred, conf, ae, nov = int(r["pred"][0]), float(r["conf"][0]), float(r["ae"][0]), float(r["nov"][0])
        label = self.verdict(pred, conf, ae, min_conf, anomaly, nov)
        return {
            "label": label, "confidence": conf, "ae_ratio": ae, "nov_ratio": nov, "nearest": CLASSES[pred],
            "probs": {CLASSES[i]: float(r["probs"][0, i]) for i in range(N_CLASSES)},
            "explain": self.explain(x_raw, label) if label != "Benign" else self.explain(x_raw, "Benign"),
        }

    def summary(self):
        m = self.metrics
        return {
            "loaded": self.loaded, "version": self.version,
            "accuracy": m.get("accuracy"), "macro_f1": m.get("macro_f1"),
            "params": (m.get("architecture", {}).get("params_classifier", 0) +
                       m.get("architecture", {}).get("params_autoencoder", 0)),
        }
