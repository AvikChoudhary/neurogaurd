"""
Synthetic network-flow generator.

Each generator returns a (n, 31) matrix of CICFlowMeter-style flow features
(see schema.FEATURES).  Profiles are modelled on the behaviour documented for the
CIC-IDS2017 attack families.  Sub-profiles (e.g. SYN-flood vs slowloris for DoS)
are mixed so the classes are multi-modal, and a fraction of every attack class is
blended towards benign behaviour ("low-and-slow" evasion) so the ANN has to learn
real decision boundaries instead of memorising separable blobs.

The same generator powers the training set AND the live attack simulator.
"""
import numpy as np
from .schema import FEATURES, CLASSES, N_RAW


def _ln(rng, median, sigma, n, lo=None, hi=None):
    x = median * np.exp(sigma * rng.standard_normal(n))
    return np.clip(x, lo if lo is not None else 0, hi if hi is not None else np.inf)


def _pick(rng, values, probs, n):
    p = np.asarray(probs, dtype=float)
    return rng.choice(values, size=n, p=p / p.sum())


def _mix(rng, n, parts):
    """parts: [(weight, fn(rng, m) -> matrix)]  ->  n rows, shuffled."""
    w = np.array([p[0] for p in parts], dtype=float)
    counts = rng.multinomial(n, w / w.sum())
    blocks = [fn(rng, int(c)) for (_, fn), c in zip(parts, counts) if c > 0]
    X = np.vstack(blocks)
    return X[rng.permutation(len(X))]


def _assemble(rng, port, dur, fp, bp, fl, bl, *, syn, fin, rst, psh, ack, urg, iat_cv,
              wf, wb, idle_frac=0.0, udp=False):
    n = len(port)
    fp = np.maximum(np.round(fp), 1.0)
    bp = np.maximum(np.round(bp), 0.0)
    dur = np.maximum(dur, 1.0)
    fl = np.maximum(fl, 0.0)
    bl = np.where(bp > 0, np.maximum(bl, 0.0), 0.0)
    fb, bb = fp * fl, bp * bl
    tp, tb = fp + bp, fp * fl + bp * bl
    sec = dur / 1e6
    iat_mean = dur / np.maximum(tp - 1, 1)
    iat_std = iat_mean * iat_cv
    iat_max = np.minimum(dur, iat_mean * (1 + iat_cv * (1 + 2 * np.abs(rng.standard_normal(n)))))
    avg = tb / tp
    pf = fp / tp
    between = pf * (fl - avg) ** 2 + (1 - pf) * (bl - avg) ** 2
    pstd = np.sqrt(between + (0.5 * avg * rng.uniform(0.3, 1.2, n)) ** 2)
    pmin = np.minimum(fl, np.where(bp > 0, bl, fl)) * rng.uniform(0, 0.6, n)
    pmax = np.minimum(1514, np.maximum(fl, bl) * rng.uniform(1.0, 2.0, n) + 20 * (tb > 0))
    pmax = np.maximum(pmax, avg)
    idle = dur * idle_frac * rng.uniform(0.5, 1.0, n)
    flags = lambda v: np.zeros(n) if udp else np.asarray(v, dtype=float)
    d = {
        "Destination Port": port, "Flow Duration": dur, "Total Fwd Packets": fp,
        "Total Backward Packets": bp, "Total Length of Fwd Packets": fb,
        "Total Length of Bwd Packets": bb, "Fwd Packet Length Mean": fl,
        "Bwd Packet Length Mean": bl, "Flow Bytes/s": tb / sec, "Flow Packets/s": tp / sec,
        "Flow IAT Mean": iat_mean, "Flow IAT Std": iat_std, "Flow IAT Max": iat_max,
        "Fwd IAT Mean": dur / np.maximum(fp - 1, 1),
        "Bwd IAT Mean": np.where(bp > 1, dur / np.maximum(bp - 1, 1), 0.0),
        "Fwd PSH Flags": flags(np.round(np.asarray(psh) * 0.6)),
        "FIN Flag Count": flags(fin), "SYN Flag Count": flags(syn), "RST Flag Count": flags(rst),
        "PSH Flag Count": flags(psh), "ACK Flag Count": flags(ack), "URG Flag Count": flags(urg),
        "Down/Up Ratio": np.round(bp / fp), "Average Packet Size": avg, "Packet Length Std": pstd,
        "Min Packet Length": pmin, "Max Packet Length": pmax,
        "Init_Win_bytes_forward": -np.ones(n) if udp else wf,
        "Init_Win_bytes_backward": -np.ones(n) if udp else np.where(bp > 0, wb, -1),
        "Active Mean": np.maximum(dur - idle, 1.0), "Idle Mean": idle,
    }
    return np.column_stack([d[k] for k in FEATURES])


WIN_F = [8192, 29200, 64240, 65535, 5840, 14600]
WIN_B = [28960, 65535, 64240, 14600, 8192, 29200]


def _tcp_common(rng, n, fp, bp, syn=1.0):
    """Typical TCP flag counters derived from packet counts."""
    fp_, bp_ = np.maximum(np.round(fp), 1), np.maximum(np.round(bp), 0)
    tp = fp_ + bp_
    psh = np.minimum(tp, np.round(0.4 * tp + rng.poisson(1.0, n)))
    ack = np.maximum(tp - 1, 0)
    fin = rng.choice([0, 1, 2], n, p=[0.1, 0.55, 0.35])
    rst = (rng.random(n) < 0.08).astype(float)
    return dict(syn=np.full(n, syn) + (rng.random(n) < 0.2), fin=fin, rst=rst, psh=psh, ack=ack,
                urg=np.zeros(n))


def _win(rng, n):
    return rng.choice(WIN_F, n), rng.choice(WIN_B, n)


# ---------------------------------------------------------------------- benign
def _b_web(rng, n):
    port = _pick(rng, [443, 80, 8080, 8443], [60, 25, 10, 5], n)
    fp, bp = _ln(rng, 9, .8, n), _ln(rng, 12, .9, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, port, _ln(rng, 3e5, 1.6, n), fp, bp, _ln(rng, 180, .6, n, hi=1400),
                     _ln(rng, 600, .7, n, hi=1460), iat_cv=_ln(rng, 1.6, .4, n), wf=wf, wb=wb,
                     idle_frac=0.3, **_tcp_common(rng, n, fp, bp))


def _b_dns(rng, n):
    return _assemble(rng, np.full(n, 53), _ln(rng, 2e4, 1.0, n), 1 + rng.poisson(.1, n), np.ones(n),
                     _ln(rng, 45, .25, n), _ln(rng, 110, .5, n), syn=0, fin=0, rst=0, psh=0, ack=0,
                     urg=0, iat_cv=_ln(rng, 1.0, .3, n), wf=0, wb=0, udp=True)


def _b_interactive(rng, n):
    port = _pick(rng, [22, 3389, 23, 5900], [70, 22, 3, 5], n)
    fp, bp = _ln(rng, 200, 1.0, n), _ln(rng, 260, 1.0, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, port, _ln(rng, 2e7, 1.3, n), fp, bp, _ln(rng, 60, .6, n),
                     _ln(rng, 120, .8, n), iat_cv=_ln(rng, 3.0, .4, n), wf=wf, wb=wb,
                     idle_frac=0.5, **_tcp_common(rng, n, fp, bp))


def _b_bulk(rng, n):
    fp, bp = _ln(rng, 60, .9, n), _ln(rng, 900, .8, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, np.full(n, 443), _ln(rng, 3e7, 1.1, n), fp, bp, _ln(rng, 100, .5, n),
                     _ln(rng, 1300, .15, n, hi=1460), iat_cv=_ln(rng, 1.2, .4, n), wf=wf, wb=wb,
                     idle_frac=0.15, **_tcp_common(rng, n, fp, bp))


def _b_other(rng, n):
    port = _pick(rng, [25, 993, 143, 110, 123, 3306], [30, 25, 15, 10, 10, 10], n)
    fp, bp = _ln(rng, 8, .6, n), _ln(rng, 7, .6, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, port, _ln(rng, 5e5, 1.3, n), fp, bp, _ln(rng, 250, .8, n, hi=1400),
                     _ln(rng, 150, .8, n, hi=1400), iat_cv=_ln(rng, 1.4, .4, n), wf=wf, wb=wb,
                     idle_frac=0.25, **_tcp_common(rng, n, fp, bp))


def gen_benign(rng, n):
    return _mix(rng, n, [(55, _b_web), (15, _b_dns), (12, _b_interactive), (8, _b_bulk), (10, _b_other)])


# ------------------------------------------------------------------------ DoS
def _d_syn(rng, n):
    fp, bp = rng.integers(1, 4, n), rng.integers(0, 2, n)
    return _assemble(rng, _pick(rng, [80, 443], [65, 35], n), _ln(rng, 1e3, 1.5, n), fp, bp,
                     np.zeros(n), np.zeros(n), syn=fp, fin=np.zeros(n), rst=bp.astype(float),
                     psh=np.zeros(n), ack=np.zeros(n), urg=np.zeros(n), iat_cv=_ln(rng, .5, .4, n),
                     wf=rng.choice([1024, 2048, 29200, 65535], n), wb=rng.choice([0, 29200], n))


def _d_http(rng, n):
    fp, bp = _ln(rng, 6, .5, n), _ln(rng, 1.5, .5, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, _pick(rng, [80, 443, 8080], [55, 35, 10], n), _ln(rng, 5e4, 1.0, n), fp, bp,
                     _ln(rng, 350, .3, n), _ln(rng, 200, .5, n), iat_cv=_ln(rng, .4, .4, n), wf=wf, wb=wb,
                     **_tcp_common(rng, n, fp, bp))


def _d_slow(rng, n):
    fp, bp = _ln(rng, 8, .4, n), _ln(rng, 2, .5, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, _pick(rng, [80, 443, 8080], [60, 30, 10], n), _ln(rng, 6e7, .5, n), fp, bp,
                     _ln(rng, 25, .4, n), _ln(rng, 100, .5, n), iat_cv=_ln(rng, .2, .4, n), wf=wf, wb=wb,
                     idle_frac=0.9, **_tcp_common(rng, n, fp, bp))


def gen_dos(rng, n):
    return _mix(rng, n, [(35, _d_syn), (30, _d_http), (35, _d_slow)])


# ------------------------------------------------------------------ port scan
def _p_syn(rng, n):
    bp = rng.choice([0, 1], n, p=[.4, .6])
    port = np.where(rng.random(n) < .3, rng.integers(1, 1024, n), rng.integers(1, 65536, n))
    return _assemble(rng, port, _ln(rng, 300, 1.2, n), np.ones(n), bp, np.zeros(n), np.zeros(n),
                     syn=np.ones(n), fin=np.zeros(n), rst=bp.astype(float), psh=np.zeros(n),
                     ack=np.zeros(n), urg=np.zeros(n), iat_cv=_ln(rng, .3, .4, n),
                     wf=rng.choice([1024, 29200, 5840, 2048], n), wb=np.zeros(n))


def _p_connect(rng, n):
    fp, bp = rng.integers(3, 5, n), rng.integers(2, 4, n)
    return _assemble(rng, rng.integers(1, 65536, n), _ln(rng, 2e3, .8, n), fp, bp, np.zeros(n),
                     np.zeros(n), syn=np.full(n, 2.0), fin=np.zeros(n), rst=np.ones(n),
                     psh=np.zeros(n), ack=np.full(n, 2.0), urg=np.zeros(n), iat_cv=_ln(rng, .5, .4, n),
                     wf=rng.choice([64240, 29200], n), wb=rng.choice([65535, 28960], n))


def _p_xmas(rng, n):
    bp = rng.choice([0, 1], n, p=[.7, .3])
    return _assemble(rng, rng.integers(1, 65536, n), _ln(rng, 200, 1.0, n), np.ones(n), bp,
                     np.zeros(n), np.zeros(n), syn=np.zeros(n), fin=np.ones(n),
                     rst=bp.astype(float), psh=np.ones(n) * (rng.random(n) < .6),
                     ack=np.zeros(n), urg=np.ones(n) * (rng.random(n) < .6), iat_cv=_ln(rng, .3, .4, n),
                     wf=rng.choice([1024, 2048, 4096], n), wb=np.zeros(n))


def gen_portscan(rng, n):
    return _mix(rng, n, [(60, _p_syn), (25, _p_connect), (15, _p_xmas)])


# ---------------------------------------------------------------- brute force
def _bf(rng, n, port, dur, fp, bp, fl, bl, cv=.7):
    f, b = _ln(rng, fp, .3, n), _ln(rng, bp, .3, n)
    wf, wb = _win(rng, n)
    p = port if hasattr(port, "__len__") else np.full(n, port)
    return _assemble(rng, p, _ln(rng, dur, .5, n), f, b, _ln(rng, fl, .35, n, hi=1460), _ln(rng, bl, .35, n, hi=1460),
                     iat_cv=_ln(rng, cv, .3, n), wf=wf, wb=wb, idle_frac=0.12, **_tcp_common(rng, n, f, b))


def gen_bruteforce(rng, n):
    return _mix(rng, n, [
        (45, lambda r, m: _bf(r, m, 22, 2.5e6, 14, 16, 58, 95)),
        (15, lambda r, m: _bf(r, m, 21, 1.2e6, 10, 11, 24, 52)),
        (15, lambda r, m: _bf(r, m, 3389, 3e6, 20, 18, 140, 220)),
        (25, lambda r, m: _bf(r, m, _pick(r, [80, 443, 8080], [50, 40, 10], m), 8e5, 7, 6, 320, 380, 1.0)),
    ])


# ----------------------------------------------------------------- web attack
def _w_inject(rng, n):
    fp, bp = _ln(rng, 7, .4, n), _ln(rng, 6, .5, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, _pick(rng, [80, 443, 8080, 8443], [40, 35, 15, 10], n), _ln(rng, 1.2e6, .8, n),
                     fp, bp, _ln(rng, 900, .4, n, hi=1400), _ln(rng, 520, .9, n, hi=1460),
                     iat_cv=_ln(rng, 1.1, .4, n), wf=wf, wb=wb, idle_frac=0.3, **_tcp_common(rng, n, fp, bp))


def _w_scanner(rng, n):
    fp, bp = _ln(rng, 4, .3, n), _ln(rng, 3, .3, n)
    wf, wb = _win(rng, n)
    return _assemble(rng, _pick(rng, [80, 443], [60, 40], n), _ln(rng, 2e5, .7, n), fp, bp,
                     _ln(rng, 280, .25, n), _ln(rng, 310, .7, n, hi=1400), iat_cv=_ln(rng, .5, .4, n),
                     wf=wf, wb=wb, idle_frac=0.15, **_tcp_common(rng, n, fp, bp))


def gen_web(rng, n):
    return _mix(rng, n, [(70, _w_inject), (30, _w_scanner)])


# --------------------------------------------------------------------- botnet
def _c(rng, n, port, dur, fp, bp, fl, bl, cv, idle=.5, jit=.25):
    f, b = _ln(rng, fp, jit, n), _ln(rng, bp, jit, n)
    wf, wb = _win(rng, n)
    p = port if hasattr(port, "__len__") else np.full(n, port)
    return _assemble(rng, p, _ln(rng, dur, .4, n), f, b, _ln(rng, fl, .2, n, hi=1460), _ln(rng, bl, .3, n, hi=1460),
                     iat_cv=_ln(rng, cv, .4, n), wf=wf, wb=wb, idle_frac=idle, **_tcp_common(rng, n, f, b))


def gen_botnet(rng, n):
    return _mix(rng, n, [
        (60, lambda r, m: _c(r, m, _pick(r, [443, 8080, 8443, 4444, 6667], [40, 20, 10, 15, 15], m),
                             1.5e6, 5, 4, 96, 140, .12)),
        (25, lambda r, m: _c(r, m, _pick(r, [6667, 6697, 31337, 50001], [50, 20, 15, 15], m),
                             2e7, 40, 35, 70, 80, .5, jit=.4)),
        (15, lambda r, m: _assemble(r, np.full(m, 53), _ln(r, 4e5, .6, m), _ln(r, 6, .3, m),
                                    _ln(r, 6, .3, m), _ln(r, 110, .2, m), _ln(r, 190, .2, m),
                                    syn=0, fin=0, rst=0, psh=0, ack=0, urg=0, iat_cv=_ln(r, .2, .4, m),
                                    wf=0, wb=0, udp=True)),
    ])


# ---------------------------------------------------------------- exfiltration
def gen_exfil(rng, n):
    return _mix(rng, n, [
        (65, lambda r, m: _c(r, m, _pick(r, [443, 22, 21, 8080, 990], [55, 15, 10, 15, 5], m),
                             4e7, 900, 420, 1250, 40, .7, idle=.1, jit=.6)),
        (20, lambda r, m: _assemble(r, np.full(m, 53), _ln(r, 6e6, .7, m), _ln(r, 120, .5, m),
                                    _ln(r, 115, .5, m), _ln(r, 180, .2, m), _ln(r, 200, .2, m),
                                    syn=0, fin=0, rst=0, psh=0, ack=0, urg=0, iat_cv=_ln(r, .6, .3, m),
                                    wf=0, wb=0, udp=True)),
        (15, lambda r, m: _c(r, m, 443, 2e8, 160, 80, 900, 60, .8, idle=.6, jit=.4)),
    ])


# --------------------------------------------------------------- infiltration
def gen_infiltration(rng, n):
    return _mix(rng, n, [
        (50, lambda r, m: _c(r, m, _pick(r, [445, 139, 135], [70, 20, 10], m), 1.5e6, 32, 28, 260, 320,
                             2.2, idle=.2, jit=.6)),
        (35, lambda r, m: _c(r, m, _pick(r, [3389, 5985, 22, 5900], [40, 25, 25, 10], m), 8e6, 60, 55,
                             130, 260, 2.5, idle=.3, jit=.6)),
        (15, lambda r, m: _c(r, m, _pick(r, [389, 88, 636], [50, 35, 15], m), 4e5, 8, 9, 190, 200, 1.5,
                             idle=.1, jit=.5)),
    ])


# -------------------------------------------------- zero-day (never trained on)
def gen_zeroday(rng, n):
    """Behaviour outside every training class: full-size packets, URG/RST storms, odd windows."""
    fp, bp = _ln(rng, 35, .4, n), _ln(rng, 3, .8, n)
    return _assemble(rng, rng.choice([31337, 9001, 50123, 61000, 12345, 2323], n), _ln(rng, 9e4, .6, n),
                     fp, bp, _ln(rng, 1400, .04, n, hi=1460), _ln(rng, 8, .5, n),
                     syn=rng.integers(0, 3, n), fin=np.zeros(n), rst=rng.integers(3, 9, n),
                     psh=rng.integers(20, 40, n), ack=rng.integers(0, 5, n), urg=rng.integers(4, 12, n),
                     iat_cv=_ln(rng, .05, .3, n), wf=rng.choice([0, 1, 7, 65535], n),
                     wb=rng.choice([0, 1, 3], n), idle_frac=0.0)


GENERATORS = {
    "Benign": gen_benign, "DoS/DDoS": gen_dos, "Port Scan": gen_portscan, "Brute Force": gen_bruteforce,
    "Web Attack": gen_web, "Botnet C2": gen_botnet, "Data Exfiltration": gen_exfil,
    "Infiltration": gen_infiltration, "Zero-Day Anomaly": gen_zeroday,
}


def generate(label, n, rng):
    return GENERATORS[label](rng, n)


def generate_dataset(n_total=40000, seed=42, evasive=0.07):
    """Balanced-ish labelled dataset.  `evasive` = share of attack rows blended towards benign."""
    rng = np.random.default_rng(seed)
    share = {"Benign": 0.34, "DoS/DDoS": 0.12, "Port Scan": 0.11, "Brute Force": 0.11,
             "Web Attack": 0.09, "Botnet C2": 0.08, "Data Exfiltration": 0.08, "Infiltration": 0.07}
    Xs, ys = [], []
    for ci, name in enumerate(CLASSES):
        n = max(50, int(n_total * share[name]))
        X = GENERATORS[name](rng, n)
        k = int(n * evasive)
        if name != "Benign" and k > 0:
            B = np.log1p(np.clip(gen_benign(rng, k), 0, None))
            A = np.log1p(np.clip(X[:k], 0, None))
            a = rng.uniform(0.25, 0.65, (k, 1))
            M = np.expm1(A * (1 - a) + B * a)
            M[:, 0] = X[:k, 0]                       # keep the real destination port
            X[:k] = M
        Xs.append(X)
        ys.append(np.full(len(X), ci))
    X, y = np.vstack(Xs), np.concatenate(ys)
    p = rng.permutation(len(X))
    return X[p], y[p]
