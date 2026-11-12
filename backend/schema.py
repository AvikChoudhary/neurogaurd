"""
Shared schema: the flow-feature layout, class labels, threat intelligence
(severity, MITRE ATT&CK mapping, response playbooks) and the input pre-processor.

Feature names follow the CICFlowMeter / CIC-IDS2017 convention, so the same
pipeline can be trained on the real CIC-IDS2017 CSVs (see train.py --csv).
"""
import numpy as np

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Mean",
    "Bwd Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Flow IAT Max", "Fwd IAT Mean", "Bwd IAT Mean", "Fwd PSH Flags", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Packet Length Std", "Min Packet Length",
    "Max Packet Length", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Active Mean",
    "Idle Mean",
]
N_RAW = len(FEATURES)

CLASSES = ["Benign", "DoS/DDoS", "Port Scan", "Brute Force", "Web Attack",
           "Botnet C2", "Data Exfiltration", "Infiltration"]
N_CLASSES = len(CLASSES)
ANOMALY = "Zero-Day Anomaly"
ALL_LABELS = CLASSES + [ANOMALY]

SERVICE_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5985, 8080, 8443]
N_PORT_COLS = 4 + len(SERVICE_PORTS)
N_INPUT = N_PORT_COLS + (N_RAW - 1)

SEVERITY = ["Info", "Low", "Medium", "High", "Critical"]

# "base" severity: 0 = info ... 4 = critical
INTEL = {
    "Benign": dict(color="#38D9A9", base=0, mitre="", mitre_name="", desc="Normal business traffic.", playbook=[]),
    "DoS/DDoS": dict(color="#FF5470", base=3, mitre="T1498", mitre_name="Network Denial of Service",
        desc="High-rate or slow-and-low flows intended to exhaust a service's capacity.",
        playbook=["Enable rate limiting / SYN cookies on the targeted service",
                  "Block or null-route the offending sources at the edge firewall",
                  "Engage the upstream provider or CDN scrubbing if the attack is volumetric",
                  "Scale out the service and monitor connection-table usage"]),
    "Port Scan": dict(color="#FFC83D", base=2, mitre="T1046", mitre_name="Network Service Discovery",
        desc="Systematic probing of many ports to map exposed services (reconnaissance).",
        playbook=["Block the scanning source at the perimeter",
                  "Review which ports and services are exposed and close the unnecessary ones",
                  "Watch the source for follow-up exploitation or brute-force attempts"]),
    "Brute Force": dict(color="#FF8A3D", base=2, mitre="T1110", mitre_name="Brute Force",
        desc="Repeated short authentication sessions against SSH, FTP, RDP or web logins.",
        playbook=["Block the source and enable account lockout / fail2ban",
                  "Enforce multi-factor authentication on the targeted service",
                  "Check auth logs for any successful login from the same source",
                  "Restrict the service to a VPN or an allow-list"]),
    "Web Attack": dict(color="#B38CFF", base=3, mitre="T1190", mitre_name="Exploit Public-Facing Application",
        desc="Malicious HTTP requests such as SQL injection, XSS, path traversal or scanner probing.",
        playbook=["Block the source and tune the WAF rules for the application",
                  "Review web and database logs for successful exploitation",
                  "Patch or virtually patch the vulnerable endpoint",
                  "Rotate any credentials or tokens that may have been exposed"]),
    "Botnet C2": dict(color="#FF6FD8", base=4, mitre="T1071", mitre_name="Application Layer Protocol (C2)",
        desc="Highly regular beaconing from an internal host to an external command-and-control server.",
        playbook=["Isolate the infected host from the network immediately",
                  "Block the C2 destination at DNS and the firewall",
                  "Capture memory and disk for forensics, then reimage the host",
                  "Hunt for the same beacon pattern on other hosts"]),
    "Data Exfiltration": dict(color="#4CC2FF", base=4, mitre="T1041", mitre_name="Exfiltration Over C2 Channel",
        desc="Unusually large or sustained outbound transfer from an internal system.",
        playbook=["Cut the outbound session and isolate the source host",
                  "Identify what data was accessed and transferred",
                  "Start the data-breach response and notification process",
                  "Review DLP and egress filtering rules"]),
    "Infiltration": dict(color="#9BE15D", base=4, mitre="T1021", mitre_name="Remote Services (Lateral Movement)",
        desc="Internal host moving laterally over SMB, RDP, WinRM or SSH after a compromise.",
        playbook=["Quarantine the compromised workstation",
                  "Reset the credentials used on the affected hosts",
                  "Audit SMB/RDP/WinRM access and enforce network segmentation",
                  "Search for persistence mechanisms and new admin accounts"]),
    ANOMALY: dict(color="#E6EAF5", base=2, mitre="", mitre_name="Unclassified behaviour",
        desc="Behaviour that matches no known class but deviates strongly from learned normal traffic.",
        playbook=["Investigate the source host and capture packets for analysis",
                  "Compare against recent change windows and new software deployments",
                  "If confirmed malicious, label it and retrain the classifier"]),
}


class Preprocessor:
    """Port block (one-hot + range flags) plus log1p / z-score for the other 30 features."""

    def __init__(self):
        self.mean = None
        self.std = None

    @staticmethod
    def expand(X):
        X = np.asarray(X, dtype=np.float64)
        if X.ndim == 1:
            X = X[None, :]
        port = np.clip(np.nan_to_num(X[:, 0]), 0, 65535).astype(np.int64)
        rest = np.log1p(np.clip(np.nan_to_num(X[:, 1:], nan=0.0, posinf=1e12, neginf=0.0), 0, 1e15))
        p = np.zeros((len(X), N_PORT_COLS))
        p[:, 0] = port / 65535.0
        p[:, 1] = port < 1024
        p[:, 2] = (port >= 1024) & (port < 49152)
        p[:, 3] = port >= 49152
        for j, sp in enumerate(SERVICE_PORTS):
            p[:, 4 + j] = port == sp
        return np.hstack([p, rest])

    def fit(self, X):
        E = self.expand(X)
        self.mean = E.mean(0)
        self.std = E.std(0) + 1e-6
        self.mean[:N_PORT_COLS] = 0.0
        self.std[:N_PORT_COLS] = 1.0
        return self

    def transform(self, X):
        return np.clip((self.expand(X) - self.mean) / self.std, -10, 10)

    def state(self):
        return {"pp_mean": self.mean, "pp_std": self.std}

    @classmethod
    def from_state(cls, d):
        p = cls()
        p.mean, p.std = d["pp_mean"], d["pp_std"]
        return p


def column_groups():
    """Map each expanded input column to a human-readable feature name."""
    return ["Destination Port"] * N_PORT_COLS + FEATURES[1:]
