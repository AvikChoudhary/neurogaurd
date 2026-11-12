"""
Live capture (optional).  Sniffs packets from a network interface with Scapy, assembles them
into bidirectional flows, computes the same 31 CICFlowMeter-style features the ANN was trained on
and feeds them to the engine.

Requirements: `pip install scapy`, plus
    Windows : install Npcap (https://npcap.com, tick "WinPcap API-compatible mode"), run as Administrator
    macOS   : run with sudo
    Linux   : run with sudo, or grant CAP_NET_RAW to the python binary
Only monitor networks you own or are explicitly authorised to monitor.
"""
import platform
import threading
import time
import numpy as np

from .schema import FEATURES

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class Flow:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "ts", "dirs", "lens", "flags", "win_f", "win_b",
                 "last", "closed")

    def __init__(self, src, dst, sport, dport, proto):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.ts, self.dirs, self.lens, self.flags = [], [], [], []
        self.win_f, self.win_b = -1, -1
        self.last = 0.0
        self.closed = False


class FlowTable:
    def __init__(self, idle_timeout=4.0, active_timeout=20.0, max_packets=4000):
        self.flows = {}
        self.idle, self.active, self.max_packets = idle_timeout, active_timeout, max_packets
        self.lock = threading.Lock()

    def add(self, ts, src, dst, sport, dport, proto, length, flags=0, win=-1):
        a, b = (src, sport), (dst, dport)
        key = (proto,) + ((a, b) if a <= b else (b, a))
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                f = self.flows[key] = Flow(src, dst, sport, dport, proto)
            d = 0 if (src == f.src and sport == f.sport) else 1
            if len(f.ts) < self.max_packets:
                f.ts.append(ts); f.dirs.append(d); f.lens.append(length); f.flags.append(flags)
            f.last = ts
            if proto == "TCP" and win >= 0:
                if d == 0 and f.win_f < 0:
                    f.win_f = win
                elif d == 1 and f.win_b < 0:
                    f.win_b = win
            if flags & (FIN | RST):
                f.closed = True

    def expire(self, now, force=False):
        out = []
        with self.lock:
            for key in list(self.flows):
                f = self.flows[key]
                age = (f.ts[-1] - f.ts[0]) if f.ts else 0
                if force or f.closed or now - f.last > self.idle or age > self.active:
                    out.append(self.flows.pop(key))
        return [(features(f), {"src": f.src, "dst": f.dst, "sport": f.sport, "proto": f.proto, "source": "live"})
                for f in out if f.ts]

    def size(self):
        return len(self.flows)


def features(f):
    """31-element feature vector in schema.FEATURES order."""
    ts = np.asarray(f.ts, dtype=float)
    ln = np.asarray(f.lens, dtype=float)
    d = np.asarray(f.dirs)
    fl = np.asarray(f.flags, dtype=int)
    fwd, bwd = d == 0, d == 1
    fp, bp = int(fwd.sum()), int(bwd.sum())
    tp = fp + bp
    dur = max((ts[-1] - ts[0]) * 1e6, 1.0)
    fb, bb = float(ln[fwd].sum()), float(ln[bwd].sum())
    iat = np.diff(ts) * 1e6 if len(ts) > 1 else np.array([0.0])
    fi = np.diff(ts[fwd]) * 1e6 if fp > 1 else np.array([0.0])
    bi = np.diff(ts[bwd]) * 1e6 if bp > 1 else np.array([0.0])
    cnt = lambda bit: float(((fl & bit) > 0).sum())
    idle_gaps = iat[iat > 5e5]
    idle_mean = float(idle_gaps.mean()) if len(idle_gaps) else 0.0
    active_mean = max((dur - idle_gaps.sum()) / (len(idle_gaps) + 1), 1.0)
    avg = (fb + bb) / max(tp, 1)
    v = {
        "Destination Port": f.dport, "Flow Duration": dur, "Total Fwd Packets": fp, "Total Backward Packets": bp,
        "Total Length of Fwd Packets": fb, "Total Length of Bwd Packets": bb,
        "Fwd Packet Length Mean": fb / max(fp, 1), "Bwd Packet Length Mean": bb / max(bp, 1),
        "Flow Bytes/s": (fb + bb) / (dur / 1e6), "Flow Packets/s": tp / (dur / 1e6),
        "Flow IAT Mean": float(iat.mean()), "Flow IAT Std": float(iat.std()), "Flow IAT Max": float(iat.max()),
        "Fwd IAT Mean": float(fi.mean()), "Bwd IAT Mean": float(bi.mean()),
        "Fwd PSH Flags": float(((fl[fwd] & PSH) > 0).sum()), "FIN Flag Count": cnt(FIN), "SYN Flag Count": cnt(SYN),
        "RST Flag Count": cnt(RST), "PSH Flag Count": cnt(PSH), "ACK Flag Count": cnt(ACK), "URG Flag Count": cnt(URG),
        "Down/Up Ratio": float(int(bp / max(fp, 1))), "Average Packet Size": avg,
        "Packet Length Std": float(ln.std()), "Min Packet Length": float(ln.min()), "Max Packet Length": float(ln.max()),
        "Init_Win_bytes_forward": f.win_f, "Init_Win_bytes_backward": f.win_b,
        "Active Mean": active_mean, "Idle Mean": idle_mean,
    }
    return np.array([v[k] for k in FEATURES], dtype=float)


def scapy_available():
    try:
        import scapy  # noqa: F401
        return True, getattr(scapy, "VERSION", "")
    except Exception:
        return False, ""


def is_admin():
    try:
        import os
        if platform.system() == "Windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def list_interfaces():
    try:
        from scapy.all import conf
        out = []
        for i in conf.ifaces.values():
            name = getattr(i, "name", str(i))
            out.append({"id": name, "label": f"{getattr(i, 'description', '') or name}"
                        + (f" ({i.ip})" if getattr(i, "ip", "") else "")})
        return out
    except Exception:
        try:
            from scapy.all import get_if_list
            return [{"id": n, "label": n} for n in get_if_list()]
        except Exception:
            return []


class LiveCapture:
    def __init__(self, engine, dashboard_port=5000):
        self.e = engine
        self.table = FlowTable()
        self.running = False
        self.iface = None
        self.packets = 0
        self.flows_done = 0
        self.error = ""
        self.port = dashboard_port
        self._sniffer = None
        self._thread = None
        self._prev = None

    def status(self):
        ok, ver = scapy_available()
        return {"available": ok, "scapy": ver, "admin": is_admin(), "os": platform.system(), "running": self.running,
                "iface": self.iface, "packets": self.packets, "flows": self.flows_done, "open_flows": self.table.size(),
                "error": self.error}

    def start(self, iface=None):
        ok, _ = scapy_available()
        if not ok:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")
        if self.running:
            return
        from scapy.all import AsyncSniffer
        self.error, self.packets, self.flows_done = "", 0, 0
        self.iface = iface or None
        self._prev = (self.e.settings.get("sim_paused"), self.e.mode)
        self.e.set_settings({"sim_paused": True})
        self.e.mode = "live"
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._on_packet, store=False)
        self._sniffer.start()
        time.sleep(0.6)
        if not getattr(self._sniffer, "running", True):
            self.e.mode = "simulation"
            self.e.set_settings({"sim_paused": False})
            raise RuntimeError("Could not open the interface. Run as Administrator/root and (on Windows) install Npcap.")
        self.running = True
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()
        self.e.publish("capture", self.status())

    def stop(self):
        self.running = False
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self.e.mode = "simulation"
        self.e.set_settings({"sim_paused": False})
        self.e.publish("capture", self.status())

    def _on_packet(self, pkt):
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                return
            if pkt.haslayer(TCP):
                l4, proto, flags, win = pkt[TCP], "TCP", int(pkt[TCP].flags), int(pkt[TCP].window)
                sport, dport, plen = l4.sport, l4.dport, len(l4.payload)
            elif pkt.haslayer(UDP):
                l4, proto, flags, win = pkt[UDP], "UDP", 0, -1
                sport, dport, plen = l4.sport, l4.dport, len(l4.payload)
            elif pkt.haslayer(ICMP):
                proto, flags, win, sport, dport, plen = "ICMP", 0, -1, 0, 0, len(pkt[ICMP].payload)
            else:
                return
            if self.port in (sport, dport):      # never analyse the dashboard's own traffic
                return
            self.packets += 1
            self.table.add(float(pkt.time), src, dst, sport, dport, proto, plen, flags, win)
        except Exception:
            pass

    def _flush_loop(self):
        while self.running:
            time.sleep(1.0)
            done = self.table.expire(time.time())
            if done:
                self.flows_done += len(done)
                X = np.vstack([d[0] for d in done])
                self.e.process(X, [d[1] for d in done])
            self.e.publish("capture", self.status())
