"""
Real-Time Intrusion Detection System Engine
Detects: Port Scanning, DDoS patterns, Abnormal packets
"""

import threading
import time
import smtplib
import json
import logging
from collections import defaultdict, deque
from typing import Any
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, asdict
import random  # used for demo mode simulation

# Scapy import (graceful fallback for demo mode)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP  # noqa: F401
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IDS")

# ─── Config ────────────────────────────────────────────────────────────────────

CONFIG = {
    # Detection thresholds
    "PORT_SCAN_THRESHOLD": 20,        # unique ports within rolling window = port scan
    "PORT_SCAN_WINDOW": 10,           # seconds (rolling)
    "DDOS_PPS_THRESHOLD": 5000,       # packets/sec from single external IP = DDoS
    "DDOS_WINDOW": 5,                 # seconds
    "ABNORMAL_PACKET_SIZE": 65000,    # bytes — suspiciously large
    "SYN_FLOOD_THRESHOLD": 200,       # SYN packets without ACK within window
    "ICMP_FLOOD_THRESHOLD": 100,      # ICMP packets/sec

    # Email config (Gmail SMTP)
    "EMAIL_ENABLED": False,           # set True after configuring credentials
    "EMAIL_SENDER": "your_gmail@gmail.com",
    "EMAIL_PASSWORD": "your_app_password",  # Gmail App Password (not main password)
    "EMAIL_RECIPIENT": "analyst@yourcompany.com",
    "EMAIL_COOLDOWN": 300,            # seconds between same-type alerts

    # Demo mode — generates synthetic traffic (use when not running as root)
    "DEMO_MODE": False,
    "INTERFACE": "en0",
}

# ─── Alert Model ───────────────────────────────────────────────────────────────

@dataclass
class Alert:
    id: str
    timestamp: str
    alert_type: str          # PORT_SCAN | DDOS | SYN_FLOOD | ICMP_FLOOD | ABNORMAL_PACKET
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    source_ip: str
    dest_ip: str
    description: str
    packet_count: int
    details: dict

    def to_dict(self):
        return asdict(self)


# ─── Helpers ──────────────────────────────────────────────────────────────────

import ipaddress as _ipaddress

_PRIVATE_NETS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("169.254.0.0/16"),
    _ipaddress.ip_network("::1/128"),
]

def _is_private(ip: str) -> bool:
    """Return True if ip is a private/loopback address."""
    try:
        addr = _ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

# ─── IDS Engine ────────────────────────────────────────────────────────────────

class IDSEngine:
    def __init__(self, config: dict):
        self.config = config
        self.running = False

        # State tracking
        # Now stores deque of (timestamp, port) tuples per src IP (populated on demand)
        self.port_scan_tracker: dict[str, deque] = {}
        self.packet_rate_tracker = defaultdict(lambda: deque())           # ip -> deque of timestamps
        self.syn_tracker = defaultdict(lambda: deque())                   # ip -> deque of SYN ts
        self.icmp_tracker = defaultdict(lambda: deque())                  # ip -> deque of ts

        # Stats
        self.stats: dict[str, Any] = {
            "total_packets": 0,
            "alerts_triggered": 0,
            "packets_per_sec": 0,
            "start_time": datetime.now().isoformat(),
            "top_talkers": defaultdict(int),
            "protocol_counts": defaultdict(int),
        }

        # Alert storage (in-memory ring buffer)
        self.alerts = deque(maxlen=500)
        self.alert_id_counter = 0

        # Email cooldown tracker
        self.email_cooldown = {}

        # Packet rate sampling
        self._pps_samples = deque(maxlen=10)
        self._last_pps_count = 0
        self._last_pps_time = time.time()

        # Local IP cache (detected from first packet)
        self._local_ips: set[str] = set()

        self._lock = threading.Lock()

        # Batching variables for high-performance sniffing
        self._batch_count = 0
        self._batch_total_packets = 0
        self._batch_top_talkers = defaultdict(int)
        self._batch_protocol_counts = defaultdict(int)

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self):
        self.running = True
        logger.info("IDS Engine starting...")

        if self.config["DEMO_MODE"] or not SCAPY_AVAILABLE:
            logger.info("Running in DEMO MODE — synthetic traffic simulation active")
            t = threading.Thread(target=self._demo_traffic_loop, daemon=True)
            t.start()
        else:
            logger.info(f"Capturing on interface: {self.config['INTERFACE']}")
            t = threading.Thread(target=self._capture_loop, daemon=True)
            t.start()

        # Stats updater
        st = threading.Thread(target=self._stats_loop, daemon=True)
        st.start()

    def stop(self):
        self.running = False
        logger.info("IDS Engine stopped.")

    def get_alerts(self, limit=50, severity=None, alert_type=None):
        with self._lock:
            result = list(self.alerts)
        result.reverse()
        if severity:
            result = [a for a in result if a["severity"] == severity]
        if alert_type:
            result = [a for a in result if a["alert_type"] == alert_type]
        return result[:limit]

    def get_stats(self):
        with self._lock:
            s = dict(self.stats)
            s["top_talkers"] = dict(sorted(s["top_talkers"].items(), key=lambda x: x[1], reverse=True)[:10])
            s["protocol_counts"] = dict(s["protocol_counts"])
            s["alerts_triggered"] = len(self.alerts)
            s["uptime_seconds"] = int((datetime.now() - datetime.fromisoformat(s["start_time"])).total_seconds())
            s["demo_mode"] = self.config.get("DEMO_MODE", True)
            s["interface"] = self.config.get("INTERFACE", "Unknown")
        return s

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()

    # ── Capture ────────────────────────────────────────────────────────────────

    def _capture_loop(self):
        try:
            sniff(
                iface=self.config["INTERFACE"],
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        ts = time.time()

        # Learn local IPs from outbound packets so we can exclude them
        if _is_private(src):
            self._local_ips.add(src)

        # Batch statistics updates to avoid lock contention per-packet
        self._batch_total_packets += 1
        self._batch_top_talkers[src] += 1

        if pkt.haslayer(TCP):
            self._batch_protocol_counts["TCP"] += 1
            # Port scan: only check INBOUND traffic from external IPs
            if not _is_private(src) and (not self._local_ips or dst in self._local_ips):
                self._check_port_scan(src, dst, pkt[TCP].dport, ts)
                self._check_syn_flood(src, dst, pkt, ts)
        elif pkt.haslayer(UDP):
            self._batch_protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            self._batch_protocol_counts["ICMP"] += 1
            # ICMP flood: only flag external sources
            if not _is_private(src):
                self._check_icmp_flood(src, dst, ts)

        # DDoS: only flag external sources
        if not _is_private(src):
            self._check_ddos(src, dst, ts)
        self._check_abnormal_packet(src, dst, size, ts)

        # Flush batches every 50 packets to keep stats near real-time
        self._batch_count += 1
        if self._batch_count >= 50:
            self._flush_batches()

    def _flush_batches(self):
        if self._batch_count == 0:
            return
        with self._lock:
            self.stats["total_packets"] += self._batch_total_packets
            for ip, count in self._batch_top_talkers.items():
                self.stats["top_talkers"][ip] += count
            for proto, count in self._batch_protocol_counts.items():
                self.stats["protocol_counts"][proto] += count

        self._batch_count = 0
        self._batch_total_packets = 0
        self._batch_top_talkers.clear()
        self._batch_protocol_counts.clear()

    # ── Detection Logic ────────────────────────────────────────────────────────

    def _check_port_scan(self, src, dst, dport, ts):
        """True rolling-window port scan detector (inbound, external IPs only)."""
        window = self.config["PORT_SCAN_WINDOW"]
        threshold = self.config["PORT_SCAN_THRESHOLD"]

        # Use a deque of (timestamp, port) tuples per src IP
        key = src
        if key not in self.port_scan_tracker:
            self.port_scan_tracker[key] = deque()

        q = self.port_scan_tracker[key]
        q.append((ts, dport))

        # Evict entries older than the rolling window
        cutoff = ts - window
        while q and q[0][0] < cutoff:
            q.popleft()

        unique_ports = len(set(p for _, p in q))
        if unique_ports >= threshold:
            sample_ports = list(set(p for _, p in q))[:10]
            self._raise_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                src=src, dst=dst,
                description=f"Port scan detected: {unique_ports} unique ports probed in {window}s from external IP",
                packet_count=unique_ports,
                details={"unique_ports": unique_ports, "window_seconds": window,
                         "sample_ports": sample_ports},
            )
            self.port_scan_tracker[key].clear()  # reset to avoid alert storm

    def _check_ddos(self, src, dst, ts):
        window = self.config["DDOS_WINDOW"]
        threshold = self.config["DDOS_PPS_THRESHOLD"]
        q = self.packet_rate_tracker[src]
        q.append(ts)
        cutoff = ts - window
        while q and q[0] < cutoff:
            q.popleft()
        pps = len(q) / window
        if pps >= threshold:
            self._raise_alert(
                alert_type="DDOS",
                severity="CRITICAL",
                src=src, dst=dst,
                description=f"DDoS pattern: {pps:.0f} pkt/s from {src} (threshold: {threshold})",
                packet_count=len(q),
                details={"packets_per_second": round(pps, 1), "window_seconds": window},
            )
            self.packet_rate_tracker[src].clear()

    def _check_syn_flood(self, src, dst, pkt, ts):
        if not (pkt[TCP].flags & 0x02):  # SYN flag
            return
        if pkt[TCP].flags & 0x10:        # ACK flag — normal handshake
            return
        window = self.config["PORT_SCAN_WINDOW"]
        threshold = self.config["SYN_FLOOD_THRESHOLD"]
        q = self.syn_tracker[src]
        q.append(ts)
        cutoff = ts - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= threshold:
            self._raise_alert(
                alert_type="SYN_FLOOD",
                severity="CRITICAL",
                src=src, dst=dst,
                description=f"SYN flood: {len(q)} SYN packets in {window}s (no ACK)",
                packet_count=len(q),
                details={"syn_count": len(q), "window_seconds": window},
            )
            self.syn_tracker[src].clear()

    def _check_icmp_flood(self, src, dst, ts):
        window = self.config["DDOS_WINDOW"]
        threshold = self.config["ICMP_FLOOD_THRESHOLD"]
        q = self.icmp_tracker[src]
        q.append(ts)
        cutoff = ts - window
        while q and q[0] < cutoff:
            q.popleft()
        pps = len(q) / window
        if pps >= threshold:
            self._raise_alert(
                alert_type="ICMP_FLOOD",
                severity="HIGH",
                src=src, dst=dst,
                description=f"ICMP flood: {pps:.0f} pkt/s from {src}",
                packet_count=len(q),
                details={"icmp_per_second": round(pps, 1)},
            )
            self.icmp_tracker[src].clear()

    def _check_abnormal_packet(self, src, dst, size, ts):
        if size > self.config["ABNORMAL_PACKET_SIZE"]:
            self._raise_alert(
                alert_type="ABNORMAL_PACKET",
                severity="MEDIUM",
                src=src, dst=dst,
                description=f"Oversized packet: {size} bytes from {src}",
                packet_count=1,
                details={"packet_size": size, "threshold": self.config["ABNORMAL_PACKET_SIZE"]},
            )

    # ── Alert Dispatch ─────────────────────────────────────────────────────────

    def _raise_alert(self, alert_type, severity, src, dst, description, packet_count, details):
        # Cooldown check (per type+src pair)
        cooldown_key = f"{alert_type}:{src}"
        now = time.time()
        if cooldown_key in self.email_cooldown:
            if now - self.email_cooldown[cooldown_key] < 30:  # 30s between same alerts
                return
        self.email_cooldown[cooldown_key] = now

        with self._lock:
            self.alert_id_counter += 1
            alert = Alert(
                id=f"IDS-{self.alert_id_counter:05d}",
                timestamp=datetime.now().isoformat(),
                alert_type=alert_type,
                severity=severity,
                source_ip=src,
                dest_ip=dst,
                description=description,
                packet_count=packet_count,
                details=details,
            )

            self.alerts.append(alert.to_dict())
            self.stats["alerts_triggered"] = len(self.alerts)
            
        logger.warning(f"[{severity}] {alert_type} — {description}")

        # Email dispatch (non-blocking)
        if self.config["EMAIL_ENABLED"]:
            threading.Thread(target=self._send_email_alert, args=(alert,), daemon=True).start()

    # ── Email ──────────────────────────────────────────────────────────────────

    def _send_email_alert(self, alert: Alert):
        cooldown_key = f"email:{alert.alert_type}"
        now = time.time()
        if cooldown_key in self.email_cooldown:
            if now - self.email_cooldown[cooldown_key] < self.config["EMAIL_COOLDOWN"]:
                return
        self.email_cooldown[cooldown_key] = now

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[IDS ALERT] {alert.severity} — {alert.alert_type} from {alert.source_ip}"
            msg["From"] = self.config["EMAIL_SENDER"]
            msg["To"] = self.config["EMAIL_RECIPIENT"]

            html = f"""
            <html><body style="font-family:monospace;background:#0a0e1a;color:#e0e0e0;padding:20px;">
            <h2 style="color:#ff4444;">⚠ IDS Alert: {alert.alert_type}</h2>
            <table style="border-collapse:collapse;width:100%;">
              <tr><td style="padding:6px;color:#aaa;">Alert ID</td><td style="padding:6px;">{alert.id}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Severity</td><td style="padding:6px;color:#ff4444;font-weight:bold;">{alert.severity}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Timestamp</td><td style="padding:6px;">{alert.timestamp}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Source IP</td><td style="padding:6px;">{alert.source_ip}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Destination</td><td style="padding:6px;">{alert.dest_ip}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Description</td><td style="padding:6px;">{alert.description}</td></tr>
              <tr><td style="padding:6px;color:#aaa;">Details</td><td style="padding:6px;"><pre>{json.dumps(alert.details, indent=2)}</pre></td></tr>
            </table>
            </body></html>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.config["EMAIL_SENDER"], self.config["EMAIL_PASSWORD"])
                server.sendmail(self.config["EMAIL_SENDER"], self.config["EMAIL_RECIPIENT"], msg.as_string())
            logger.info(f"Email alert sent for {alert.alert_type}")
        except Exception as e:
            logger.error(f"Email send failed: {e}")

    # ── Stats Loop ─────────────────────────────────────────────────────────────

    def _stats_loop(self):
        while self.running:
            time.sleep(1)
            self._flush_batches()
            with self._lock:
                now = time.time()
                elapsed = now - self._last_pps_time
                if elapsed >= 1:
                    current = self.stats["total_packets"]
                    pps = (current - self._last_pps_count) / elapsed
                    self._pps_samples.append(pps)
                    self.stats["packets_per_sec"] = round(sum(self._pps_samples) / len(self._pps_samples), 1)
                    self._last_pps_count = current
                    self._last_pps_time = now

    # ── Demo Mode ─────────────────────────────────────────────────────────────

    def _demo_traffic_loop(self):
        """Simulate realistic network traffic with periodic attack bursts."""
        attacker_ips = ["192.168.1.55", "10.0.0.88", "172.16.0.200", "45.33.32.156", "185.220.101.5"]
        normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        our_ip = "192.168.1.1"
        ts = time.time()

        scenario_timer = 0
        scenario_interval = 20  # trigger attack scenario every 20s

        while self.running:
            ts = time.time()
            scenario_timer += 1

            # Normal background traffic (always)
            for _ in range(random.randint(5, 20)):
                src = random.choice(normal_ips)
                with self._lock:
                    self.stats["total_packets"] += 1
                    self.stats["top_talkers"][src] += 1
                    proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
                    self.stats["protocol_counts"][proto] += 1

            # Rotating attack scenarios
            if scenario_timer % scenario_interval == 0:
                scenario = random.choice(["port_scan", "ddos", "syn_flood", "icmp_flood", "abnormal"])
                attacker = random.choice(attacker_ips)

                if scenario == "port_scan":
                    ports = random.sample(range(1, 65535), random.randint(18, 35))
                    for port in ports:
                        with self._lock:
                            self.stats["total_packets"] += 1
                            self.stats["top_talkers"][attacker] += 1
                            self.stats["protocol_counts"]["TCP"] += 1
                            self._check_port_scan(attacker, our_ip, port, ts)

                elif scenario == "ddos":
                    for _ in range(random.randint(600, 900)):
                        with self._lock:
                            self.stats["total_packets"] += 1
                            self.stats["top_talkers"][attacker] += 1
                            self.stats["protocol_counts"]["UDP"] += 1
                            q = self.packet_rate_tracker[attacker]
                            q.append(ts)
                        time.sleep(0.001)
                    with self._lock:
                        pps = len(self.packet_rate_tracker[attacker]) / self.config["DDOS_WINDOW"]
                        if pps >= self.config["DDOS_PPS_THRESHOLD"]:
                            self._raise_alert(
                                "DDOS", "CRITICAL", attacker, our_ip,
                                f"DDoS pattern: {pps:.0f} pkt/s from {attacker}",
                                len(self.packet_rate_tracker[attacker]),
                                {"packets_per_second": round(pps, 1), "window_seconds": self.config["DDOS_WINDOW"]},
                            )
                            self.packet_rate_tracker[attacker].clear()

                elif scenario == "syn_flood":
                    count = random.randint(110, 180)
                    with self._lock:
                        self.stats["total_packets"] += count
                        self.stats["top_talkers"][attacker] += count
                        self.stats["protocol_counts"]["TCP"] += count
                        self._raise_alert(
                            "SYN_FLOOD", "CRITICAL", attacker, our_ip,
                            f"SYN flood: {count} SYN packets in 10s (no ACK)",
                            count,
                            {"syn_count": count, "window_seconds": 10},
                        )

                elif scenario == "icmp_flood":
                    count = random.randint(55, 90)
                    with self._lock:
                        self.stats["total_packets"] += count
                        self.stats["top_talkers"][attacker] += count
                        self.stats["protocol_counts"]["ICMP"] += count
                        self._raise_alert(
                            "ICMP_FLOOD", "HIGH", attacker, our_ip,
                            f"ICMP flood: {count/5:.0f} pkt/s from {attacker}",
                            count,
                            {"icmp_per_second": round(count / 5, 1)},
                        )

                elif scenario == "abnormal":
                    size = random.randint(65001, 65535)
                    with self._lock:
                        self.stats["total_packets"] += 1
                        self.stats["top_talkers"][attacker] += 1
                        self._raise_alert(
                            "ABNORMAL_PACKET", "MEDIUM", attacker, our_ip,
                            f"Oversized packet: {size} bytes from {attacker}",
                            1,
                            {"packet_size": size, "threshold": self.config["ABNORMAL_PACKET_SIZE"]},
                        )

            time.sleep(1)


# Singleton instance
engine = IDSEngine(CONFIG)
