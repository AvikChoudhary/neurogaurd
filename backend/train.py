"""
Training pipeline.

    python -m backend.train                       # synthetic CIC-style data (default)
    python -m backend.train --samples 60000 --epochs 60
    python -m backend.train --csv path/to/cicids2017.csv    # real data (needs pandas)

Produces:
    models/neuroguard.npz   weights of the classifier ANN + autoencoder + scaler + threshold
    models/metrics.json     accuracy, per-class P/R/F1, confusion matrix, curves, importances
"""
import argparse
import json
import os
import time
import numpy as np

from .ann import MLP
from .schema import (CLASSES, N_CLASSES, N_INPUT, FEATURES, Preprocessor, column_groups)
from .traffic import generate_dataset, generate

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_FILE = "neuroguard.npz"
METRICS_FILE = "metrics.json"
CLF_SIZES = [N_INPUT, 128, 64, 32, N_CLASSES]
AE_SIZES = [N_INPUT, 32, 12, 32, N_INPUT]


def split(X, y, rng, fr=(0.70, 0.15, 0.15)):
    tr, va, te = [], [], []
    for c in np.unique(y):
        idx = rng.permutation(np.where(y == c)[0])
        a, b = int(len(idx) * fr[0]), int(len(idx) * (fr[0] + fr[1]))
        tr.append(idx[:a]); va.append(idx[a:b]); te.append(idx[b:])
    f = lambda L: rng.permutation(np.concatenate(L))
    return f(tr), f(va), f(te)


def confusion(y, p, k):
    m = np.zeros((k, k), dtype=int)
    np.add.at(m, (y, p), 1)
    return m


def class_report(cm):
    out = {}
    for i, name in enumerate(CLASSES):
        tp = cm[i, i]; fp = cm[:, i].sum() - tp; fn = cm[i, :].sum() - tp
        pr = tp / (tp + fp) if tp + fp else 0.0
        rc = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
        out[name] = dict(precision=pr, recall=rc, f1=f1, support=int(cm[i, :].sum()))
    return out


def load_csv(path, per_class_cap=40000, seed=1):
    """Load a CIC-IDS2017 style CSV (CICFlowMeter columns) and map labels onto our 8 classes."""
    import pandas as pd
    df = pd.read_csv(path, low_memory=False, encoding_errors="replace")
    df.columns = [c.strip() for c in df.columns]
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing required columns: {missing}")
    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    if label_col is None:
        raise SystemExit("CSV needs a 'Label' column")

    def mapl(s):
        s = str(s).lower()
        if "benign" in s: return 0
        if "dos" in s or "ddos" in s: return 1
        if "portscan" in s or "port scan" in s: return 2
        if "patator" in s or "brute force" in s and "web" not in s: return 3
        if "web attack" in s or "sql" in s or "xss" in s: return 4
        if s.strip() == "bot": return 5
        if "heartbleed" in s: return 6
        if "infiltration" in s: return 7
        return -1

    y = df[label_col].map(mapl).to_numpy()
    X = df[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0).to_numpy(dtype=float)
    keep = y >= 0
    X, y = X[keep], y[keep]
    rng = np.random.default_rng(seed)
    idx = np.concatenate([rng.permutation(np.where(y == c)[0])[:per_class_cap] for c in np.unique(y)])
    idx = rng.permutation(idx)
    return X[idx], y[idx]


def fit_novelty(clf, Xtr, ytr, Xva):
    """Class-conditional Gaussians (shared covariance) in the classifier's hidden embedding.
    novelty(x) = min over classes of the Mahalanobis distance; far from every class = unknown behaviour."""
    H = clf.embed(Xtr)
    present = [c for c in range(N_CLASSES) if (ytr == c).any()]
    mu = np.zeros((N_CLASSES, H.shape[1]))
    for c in present:
        mu[c] = H[ytr == c].mean(0)
    cen = H - mu[ytr]
    cov = cen.T @ cen / len(H)
    cov += np.eye(len(cov)) * 0.05 * np.trace(cov) / len(cov)       # ridge: dead ReLU units must not explode distances
    prec = np.linalg.inv(cov)
    thr = float(np.percentile(novelty_distance(clf.embed(Xva), mu, prec, present), 99.9) * 1.1)
    return mu, prec, thr, present


def novelty_distance(H, mu, prec, present=None):
    present = present if present is not None else range(len(mu))
    d = np.stack([np.einsum("nd,de,ne->n", H - mu[c], prec, H - mu[c]) for c in present], axis=1)
    return d.min(1)


def global_importance(clf, Xs, y, groups, n=2500, seed=0):
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(Xs), min(n, len(Xs)), replace=False)
    g = clf.input_gradient(Xs[idx], y[idx]) * Xs[idx]
    imp = {}
    for col, name in enumerate(groups):
        imp[name] = imp.get(name, 0.0) + float(np.abs(g[:, col]).mean())
    tot = sum(imp.values()) or 1.0
    return sorted(((k, v / tot) for k, v in imp.items()), key=lambda kv: -kv[1])


def train_models(model_dir=MODEL_DIR, n_samples=40000, epochs=45, seed=42, csv_path=None, callback=None):
    """callback(phase, epoch, epochs, loss, val_loss, acc, val_acc)"""
    t0 = time.time()
    os.makedirs(model_dir, exist_ok=True)
    rng = np.random.default_rng(seed)
    say = callback or (lambda *a: None)

    say("data", 0, 1, 0, 0, None, None)
    if csv_path:
        X, y = load_csv(csv_path)
        source = f"CSV: {os.path.basename(csv_path)}"
    else:
        X, y = generate_dataset(n_samples, seed)
        source = "Synthetic CIC-IDS style flows"
    itr, iva, ite = split(X, y, rng)
    pp = Preprocessor().fit(X[itr])
    Xtr, Xva, Xte = pp.transform(X[itr]), pp.transform(X[iva]), pp.transform(X[ite])
    ytr, yva, yte = y[itr], y[iva], y[ite]

    # --- 1. classifier ANN ---------------------------------------------------
    counts = np.bincount(ytr, minlength=N_CLASSES).astype(float)
    cw = np.where(counts > 0, counts.sum() / (N_CLASSES * np.maximum(counts, 1)), 0.0)
    cw = np.clip(cw, 0.5, 3.0) * (counts > 0)
    clf = MLP(CLF_SIZES, "classify", dropout=0.15, l2=1e-5, seed=seed)
    h1 = clf.fit(Xtr, ytr, Xva, yva, epochs=epochs, batch=256, lr=2e-3, class_weight=cw, seed=seed,
                 callback=lambda e, E, l, vl, a, va: say("classifier", e, E, l, vl, a, va))

    say("evaluating", 0, 1, 0, 0, None, None)
    pred = clf.predict_proba(Xte).argmax(1)
    cm = confusion(yte, pred, N_CLASSES)
    rep = class_report(cm)
    acc = float((pred == yte).mean())
    macro_f1 = float(np.mean([v["f1"] for v in rep.values() if v["support"]]))
    benign_total = cm[0].sum()
    fpr = float(1 - cm[0, 0] / benign_total) if benign_total else 0.0
    atk = yte != 0
    det_rate = float((pred[atk] != 0).mean()) if atk.any() else 0.0

    # --- 2. autoencoder on benign traffic only (zero-day detector) ----------------
    ae = MLP(AE_SIZES, "autoencoder", dropout=0.0, l2=1e-6, seed=seed + 1)
    Btr, Bva = Xtr[ytr == 0], Xva[yva == 0]
    h2 = ae.fit(Btr, None, Bva, None, epochs=max(20, epochs), batch=256, lr=2e-3, patience=8, seed=seed,
                callback=lambda e, E, l, vl, a, va: say("autoencoder", e, E, l, vl, None, None))
    err_va = ((ae.reconstruct(Bva) - Bva) ** 2).mean(1)
    threshold = float(np.percentile(err_va, 99.9) * 1.15)
    err_te = ((ae.reconstruct(Xte) - Xte) ** 2).mean(1)
    ae_flag = err_te > threshold
    ae_rep = {
        "benign_false_alarm": float(ae_flag[yte == 0].mean()),
        "per_class_detection": {CLASSES[c]: float(ae_flag[yte == c].mean()) for c in range(1, N_CLASSES) if (yte == c).any()},
    }
    zd = pp.transform(generate("Zero-Day Anomaly", 1500, np.random.default_rng(seed + 9)))
    ae_rep["zero_day_detection"] = float((((ae.reconstruct(zd) - zd) ** 2).mean(1) > threshold).mean())

    # --- 3. class-aware novelty (zero-day) detector on the classifier embedding ---------------------
    nmu, nprec, nthr, npresent = fit_novelty(clf, Xtr, ytr, Xva)
    nov_te = novelty_distance(clf.embed(Xte), nmu, nprec, npresent) / nthr
    nov_zd = novelty_distance(clf.embed(zd), nmu, nprec, npresent) / nthr
    ae_zd = ((ae.reconstruct(zd) - zd) ** 2).mean(1) / threshold
    novelty_rep = {
        "known_flagged": float((nov_te >= 1).mean()),
        "per_class_flagged": {CLASSES[c]: float((nov_te[yte == c] >= 1).mean()) for c in range(N_CLASSES) if (yte == c).any()},
        "zero_day_detection": float((nov_zd >= 1).mean()),
        "zero_day_either": float(((nov_zd >= 1) | (ae_zd >= 1)).mean()),
    }
    imp = global_importance(clf, Xte, yte, column_groups())

    metrics = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"), "duration_s": round(time.time() - t0, 1),
        "data_source": source, "samples": int(len(X)), "train": int(len(itr)), "val": int(len(iva)),
        "test": int(len(ite)), "epochs_run": len(h1["loss"]),
        "accuracy": acc, "macro_f1": macro_f1, "false_positive_rate": fpr, "detection_rate": det_rate,
        "classes": CLASSES, "confusion": cm.tolist(), "report": rep,
        "history": {"loss": h1["loss"], "val_loss": h1["val_loss"], "acc": h1["acc"], "val_acc": h1["val_acc"]},
        "ae_history": {"loss": h2["loss"], "val_loss": h2["val_loss"]},
        "ae": ae_rep, "ae_threshold": threshold, "novelty": novelty_rep, "novelty_threshold": nthr,
        "importance": imp[:15],
        "architecture": {"classifier": CLF_SIZES, "autoencoder": AE_SIZES,
                         "params_classifier": clf.param_count(), "params_autoencoder": ae.param_count(),
                         "dropout": clf.dropout, "optimizer": "Adam + cosine LR decay", "loss": "Weighted cross-entropy"},
        "features": FEATURES,
    }
    state = {**clf.state("clf"), **ae.state("ae"), **pp.state(), "ae_threshold": np.array(threshold),
             "nov_mu": nmu, "nov_prec": nprec, "nov_thr": np.array(nthr), "nov_present": np.array(npresent)}
    np.savez(os.path.join(model_dir, MODEL_FILE), **state)
    with open(os.path.join(model_dir, METRICS_FILE), "w", encoding="utf-8") as f:
        json.dump(metrics, f)
    say("done", 1, 1, 0, 0, acc, acc)
    return metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train the NeuroGuard ANN models")
    ap.add_argument("--samples", type=int, default=40000)
    ap.add_argument("--epochs", type=int, default=45)
    ap.add_argument("--csv", type=str, default=None, help="CIC-IDS2017 style CSV (optional)")
    a = ap.parse_args()

    def cb(phase, e, E, l, vl, acc, vacc):
        if phase in ("classifier", "autoencoder"):
            extra = f" acc={acc:.4f} val_acc={vacc:.4f}" if acc is not None else ""
            print(f"[{phase}] epoch {e:>2}/{E} loss={l:.4f} val_loss={vl:.4f}{extra}")
        else:
            print(f"[{phase}]")

    m = train_models(n_samples=a.samples, epochs=a.epochs, csv_path=a.csv, callback=cb)
    print(f"\nTest accuracy {m['accuracy']*100:.2f}% | macro-F1 {m['macro_f1']:.4f} | "
          f"FPR {m['false_positive_rate']*100:.2f}% | zero-day (autoencoder) {m['ae']['zero_day_detection']*100:.1f}% "
          f"| novelty flags {m['novelty']['known_flagged']*100:.2f}% of known / {m['novelty']['zero_day_detection']*100:.1f}% of zero-day | {m['duration_s']}s")
