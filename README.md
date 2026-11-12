# NeuroGuard IDS

An intrusion detection system powered by artificial neural networks, delivered as a web dashboard.
It runs on **Windows, macOS and Linux** (it needs only Python and a browser), and includes a built-in
attack simulator so the whole system can be demonstrated on any laptop.

## What it does

| Capability | How |
|---|---|
| Classifies every network flow into 8 classes | Multi-layer perceptron (ANN): 50 inputs, 128-64-32 ReLU hidden layers, softmax output |
| Flags unknown / zero-day behaviour | Autoencoder ANN (distance from normal) plus a class-aware embedding test (distance from every known attack) |
| Explains each verdict | Gradient x input attribution shows which flow features drove the decision |
| Confirms web attacks from content | Signature + heuristic engine (SQLi, XSS, traversal, Log4Shell, reverse shells, 20 rules) |
| Correlates alerts into incidents | Merges thousands of detections into one incident per attacker, with severity scoring |
| Maps to MITRE ATT&CK, gives playbooks | Every incident carries a technique ID and a response checklist |
| Responds | Manual block / quarantine, or auto-response (IPS mode) that drops hostile flows |
| Analyses real traffic (optional) | Live packet capture with Scapy, converted to the same 31 flow features |
| Demonstrates itself | 8 attack scenarios, a narrated guided demo, and a live scoreboard against ground truth |

Attack classes: **Benign, DoS/DDoS, Port Scan, Brute Force, Web Attack, Botnet C2, Data Exfiltration, Infiltration (lateral movement)**, plus **Zero-Day Anomaly** from the autoencoder.

---

## 1. File structure

Create this exact structure (the `models/` folder is created automatically on first run):

```
neuroguard/
├── run.py                      <- launcher (start here)
├── requirements.txt
├── Dockerfile                  (optional)
├── .gitignore
├── README.md
├── backend/
│   ├── __init__.py             (empty file)
│   ├── schema.py               feature list, classes, MITRE intel, pre-processing
│   ├── ann.py                  the neural network (NumPy, from scratch)
│   ├── traffic.py              flow generator (training data + simulator)
│   ├── train.py                training pipeline + evaluation metrics
│   ├── detector.py             hybrid ANN verdict + explainability
│   ├── signatures.py           payload signature engine
│   ├── engine.py               pipeline, incident correlation, stats, response
│   ├── simulator.py            attack scenarios for the demo
│   ├── capture.py              live packet capture (optional, Scapy)
│   └── server.py               Flask REST API + live event stream
└── frontend/
    ├── index.html              marketing landing page
    ├── console.html            the dashboard
    ├── css/
    │   ├── base.css            design system
    │   ├── landing.css
    │   └── console.css
    └── js/
        ├── landing.js          animated neural-network hero
        ├── common.js           shared helpers
        ├── charts.js           canvas charts (no libraries)
        ├── topology.js         live network map
        ├── console.js          state, live stream, router
        ├── views-main.js       Overview, Live traffic, Incidents
        ├── views-demo.js       Simulator, Payload inspector, guided demo
        └── views-system.js     Model lab, Live capture, Settings
```

## 2. Setup in VS Code (any OS)

1. Install **Python 3.9 or newer** (python.org). On Windows tick *Add Python to PATH*.
2. Create the folder structure above, open the `neuroguard` folder in VS Code (*File > Open Folder*), and paste each file's contents.
3. Open a terminal in VS Code (*Terminal > New Terminal*) and create a virtual environment:

   | OS | Commands |
   |---|---|
   | Windows (PowerShell) | `python -m venv venv` then `venv\Scripts\Activate.ps1` |
   | macOS / Linux | `python3 -m venv venv` then `source venv/bin/activate` |

   If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope Process Bypass` first.
4. Install the dependencies: `pip install -r requirements.txt`
5. Start NeuroGuard: `python run.py`

The first run trains the neural networks automatically (about 10 to 30 seconds), then opens
`http://127.0.0.1:5000` in your browser. Press **Ctrl+C** in the terminal to stop it.

Useful options: `python run.py --port 8080`, `--host 0.0.0.0` (reachable from other devices on your network), `--retrain`, `--no-browser`.

## 3. Running the demo

Fastest path: open the console and click **Run guided demo** (top right). It resets the data and runs a
narrated sequence of about two and a half minutes:

1. Normal traffic baseline
2. Port scan (reconnaissance)
3. Credential brute force
4. Web attack, confirmed by the payload signature engine
5. Opens the incident and explains the verdict (feature attribution)
6. Distributed denial of service
7. Botnet C2 beaconing, data exfiltration and lateral movement
8. Zero-day anomaly (a classifier alone would force it into a known family; the novelty detectors flag it as unknown)
9. Auto-response: attackers get blocked
10. Results: measured detection rate and false-positive rate

Or drive it manually from **Attack simulator**: pick a scenario, intensity (1 to 5) and duration, and launch.
Several scenarios can run at once. Use **Settings > Reset all data** before a presentation.

Other places worth showing: **Incidents** (click a row for evidence, explanation and playbook),
**Payload inspector** (paste a SQL injection and see it flagged), **Model lab** (architecture, training
curves, confusion matrix, feature importance, and the *Flow analyzer* where you edit a flow and watch the
ANN respond), and **Settings** (move the confidence slider to demonstrate the detection / false-positive trade-off).

## 4. How the ANN works

```
packets / simulator
       |
       v
 flow assembly --> 31 CICFlowMeter-style features (duration, packet counts, bytes,
       |                                          inter-arrival times, TCP flags, windows, port)
       v
 pre-processing: log1p + z-score, port expanded to one-hot + range flags  ->  50 inputs
       |
       +--> Classifier ANN   50 -> 128 -> 64 -> 32 -> 8 (ReLU, dropout 0.15, softmax)
       |        Adam optimiser, cosine LR decay, class-weighted cross-entropy, early stopping
       |
       +--> Autoencoder ANN  50 -> 32 -> 12 -> 32 -> 50, trained on BENIGN flows only
       |        threshold = 99.9th percentile of benign reconstruction error
       |
       +--> Embedding novelty: Mahalanobis distance from the nearest class cluster in the
                classifier's 32-d hidden layer (threshold = 99.9th percentile on validation data)
       v
 verdict:  far from EVERY known class (embedding)       -> "Zero-Day Anomaly"
           confident known attack (>= confidence setting) -> that class
           otherwise, autoencoder error above threshold    -> "Zero-Day Anomaly"
           otherwise                                       -> Benign
       v
 explain (gradient x input) -> correlate into incidents -> severity, MITRE, playbook -> respond
```

The ANN is written in plain NumPy on purpose: it installs identically on every OS (no TensorFlow or
PyTorch wheels, no GPU), and every step (forward pass, back-propagation, Adam) can be explained line by line.

### Training data: be upfront about this

By default the networks are trained on **synthetic flows** generated by `backend/traffic.py`, modelled on
the documented behaviour of the CIC-IDS2017 attack families, with deliberately overlapping and
"low-and-slow" evasive samples so the model must learn real decision boundaries. This makes the project
self-contained and runnable offline, but it means:

* The reported accuracy (about 98%) is accuracy **on this synthetic distribution**. It is a valid
  demonstration of the pipeline, not a claim about performance on arbitrary real networks.
* The bundled "zero-day" scenario is a deliberately extreme synthetic behaviour (full-size packets, URG/RST
  storms, odd TCP windows). The novelty detectors flag 100% of it, which demonstrates the *mechanism*, not that
  zero-day detection is solved.

### Honest limits

Leave-one-family-out tests (retrain with a whole attack family removed, then replay it) show what happens with
genuinely unseen attacks that look like normal traffic at flow level: only **about 27% to 65% were flagged
at all**, and few were recognised as "unknown"; most were mislabelled as the nearest known family. Flow-level
statistics cannot see inside encrypted payloads or slow, low-volume, human-like attacks. Treat NeuroGuard as a
strong demonstration of ANN-based detection, and as one layer in a defence-in-depth stack, not as a replacement
for a hardened production IDS. At the default 70% confidence threshold, the bundled test measures roughly
2% flow-level false positives (about 98% accuracy and 97 to 100% detection per attack family); because
incidents need at least 3 detections from the same source, isolated false alarms rarely surface.

To train on **real data**, download CIC-IDS2017 (the *MachineLearningCVE* CSVs from the Canadian
Institute for Cybersecurity), `pip install pandas`, and run:

```
python -m backend.train --csv path/to/Wednesday-workingHours.pcap_ISCX.csv
```

The 31 features use the CICFlowMeter column names, so the CSV is loaded directly and its labels are mapped
onto the eight classes. Restart the server afterwards. Classes missing from a CSV are simply skipped.

## 5. Live packet capture (optional)

The **Live capture** page analyses real traffic from this machine's network card with the same ANN.

| OS | One-time setup |
|---|---|
| Windows | Install **Npcap** (npcap.com, tick *WinPcap API-compatible mode*). Run VS Code or PowerShell **as Administrator**. |
| macOS | `sudo venv/bin/python run.py` |
| Linux | `sudo venv/bin/python run.py`, or `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f venv/bin/python)` |

Then `pip install scapy`, restart, open **Live capture**, choose an interface and press *Start capture*.
Simulated traffic pauses while capturing. Flow features are computed in Python, so it is meant for
laptops, labs and demos rather than line-rate links. **Only monitor networks you own or are explicitly
authorised to monitor.**

## 6. Configuration notes

| Setting | Where | Meaning |
|---|---|---|
| Confidence threshold | Settings | Minimum ANN confidence to report an attack (default 70%). Lower = more detections, more false alarms. |
| Zero-day detection | Settings | Turns the autoencoder verdict on or off. |
| Auto-response | Settings | Blocks sources of confirmed attacks (confidence of 90% or more). Servers (10.0.2.x) are never blocked. |
| `MIN_HITS` | `backend/engine.py` | Detections required before an incident is raised (default 3). Suppresses one-off false alarms. |
| `INCIDENT_GAP` | `backend/engine.py` | Seconds of silence before an incident is closed (default 8). |

## 7. REST API (for integration)

`GET /api/status`, `/api/stats`, `/api/incidents`, `/api/incidents/<id>`, `/api/model`, `/api/stream` (Server-Sent Events),
`/api/export/incidents.csv|json`; `POST /api/simulate/start|stop`, `/api/inspect`, `/api/analyze`, `/api/settings`,
`/api/incidents/<id>/action`, `/api/model/train`, `/api/capture/start|stop`, `/api/reset`.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: flask` | The virtual environment is not active. Re-run the activate command, then `pip install -r requirements.txt`. |
| `No module named backend` | Run commands from the `neuroguard` folder (the one containing `run.py`). |
| Port already in use | `python run.py --port 5050` |
| Page says "Cannot reach the server" | `python run.py` is not running, or you opened the page from a different port. |
| Live capture says "Not elevated" | Run as Administrator / with `sudo` (see section 5). |
| Fonts look plain when offline | Fonts load from Google Fonts. Offline, the UI falls back to system fonts; everything else works offline. |
| Want a clean slate | Delete the `models/` folder (it retrains on the next start) or run `python run.py --retrain`. |

The dashboard development server is intended for demos and lab use. For anything exposed beyond your own
network, put it behind a production WSGI server and authentication.
