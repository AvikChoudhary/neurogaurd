"""
NeuroGuard IDS launcher.

    python run.py                 # start the dashboard on http://127.0.0.1:5000
    python run.py --port 8080 --host 0.0.0.0     # reachable from other devices on your LAN
    python run.py --retrain       # force retraining of the ANN models
"""
import argparse
import os
import sys
import threading
import time
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def main():
    ap = argparse.ArgumentParser(description="NeuroGuard - ANN-powered Intrusion Detection System")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--retrain", action="store_true", help="retrain the ANN before starting")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()

    from backend.detector import Detector
    from backend.train import train_models

    if a.retrain or not Detector.exists():
        print("[NeuroGuard] Training the ANN models (about 10-30 seconds)...")

        def cb(phase, e, E, l, vl, acc, vacc):
            if phase in ("classifier", "autoencoder") and (e % 5 == 0 or e == E):
                extra = f"  val_acc={vacc:.4f}" if vacc is not None else ""
                print(f"    {phase:<11} epoch {e:>2}/{E}  val_loss={vl:.4f}{extra}")

        m = train_models(callback=cb)
        print(f"[NeuroGuard] Model ready: accuracy {m['accuracy']*100:.2f}%  macro-F1 {m['macro_f1']:.3f}")

    from backend.server import create_app
    app = create_app(a.port)
    url = f"http://{'127.0.0.1' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}"
    print(f"\n  NeuroGuard IDS is running  ->  {url}\n  (Press Ctrl+C to stop)\n")
    if not a.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    app.run(host=a.host, port=a.port, threaded=True, use_reloader=False, debug=False)


if __name__ == "__main__":
    main()
