# IDS Engine with Extended Detection (ARP, DNS Spoof, DNS Tunneling, ICMP Tunneling, Fragmented Packets, HTTP Flood/Slowloris, Slow Port Scan)
"""
Real-Time Intrusion Detection System Engine
Detects: Port Scanning, DDoS, SYN Flood, ICMP Flood, Abnormal packets,
          ARP Spoofing, DNS Spoofing, DNS Tunneling, ICMP Tunneling,
          Fragmented Packets, HTTP Flood/Slowloris, Slow Port Scan
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
import random
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Scapy import (graceful fallback for demo mode)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSRR, DHCP, BOOTP  # noqa: F401
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IDS")

# ─── Config ────────────────────────────────────────────────────────────────────
CONFIG = {
    # Detection thresholds
    "PORT_SCAN_THRESHOLD": 100,         # unique ports within rolling window = port scan
    "PORT_SCAN_WINDOW": 10,           # seconds (rolling)
    "SLOW_PORT_SCAN_THRESHOLD": 50,   # same as above but longer window for stealth scans
    "SLOW_PORT_SCAN_WINDOW": 60,
    "DDOS_PPS_THRESHOLD": 5000,       # packets/sec from single external IP = DDoS
    "DDOS_WINDOW": 5,                 # seconds
    "ABNORMAL_PACKET_SIZE": 65000,    # bytes — suspiciously large
    "SYN_FLOOD_THRESHOLD": 1000,      # SYN packets without ACK within window
    "ICMP_FLOOD_THRESHOLD": 500,      # ICMP packets/sec
    "ARP_SPPOOF_THRESHOLD": 5,        # changes within window to trigger ARP spoof alert
    "ARP_WINDOW": 10,                 # seconds
    "DNS_SPOOF_THRESHOLD": 3,        # conflicting answers for same query
    "DNS_WINDOW": 10,
    "DNS_TUNNEL_SIZE": 500,          # bytes – large DNS payload indication
    "DNS_TUNNEL_THRESHOLD": 200,     # queries per window from same src
    "ICMP_TUNNEL_SIZE": 100,         # bytes – large ICMP payload
    "ICMP_TUNNEL_THRESHOLD": 100,    # packets per window
    "FRAGMENTED_PACKET_THRESHOLD": 50, # packets per window
    "HTTP_FLOOD_THRESHOLD": 1000,     # HTTP requests per window from src
    "HTTP_WINDOW": 10,
    "SLOWLORIS_THRESHOLD": 50,       # incomplete connections per window
    "SLOWLORIS_WINDOW": 15,
    # Email config (Gmail SMTP)
    "EMAIL_ENABLED": False,
    "EMAIL_SENDER": "your_gmail@gmail.com",
    "EMAIL_PASSWORD": "your_app_password",
    "EMAIL_RECIPIENT": "analyst@yourcompany.com",
    "EMAIL_COOLDOWN": 300,
    # Webhooks & Advanced Features
    "WEBHOOK_URL": "",
    "IPS_MODE_ENABLED": False,
    "AI_MODE_ENABLED": True,
    # Demo mode — generates synthetic traffic (use when not running as root)
    "DEMO_MODE": False,
    "INTERFACE": "en0",
}

# ─── Alert Model ───────────────────────────────────────────────────────────────

@dataclass
class Alert:
    id: str
    timestamp: str
    alert_type: str          # e.g., PORT_SCAN, DDOS, ARP_SPOOF, DNS_SPOOF, …
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
        self.port_scan_tracker: dict[str, deque] = {}
        self.slow_port_scan_tracker: dict[str, deque] = {}
        self.packet_rate_tracker = defaultdict(lambda: deque())
        self.syn_tracker = defaultdict(lambda: deque())
        self.icmp_tracker = defaultdict(lambda: deque())
        self.arp_tracker: dict[str, dict] = {}
        self.arp_changes = defaultdict(lambda: deque())
        self.dns_tracker = defaultdict(lambda: deque())
        self.dns_query_tracker = defaultdict(lambda: deque())
        self.icmp_tunnel_tracker = defaultdict(lambda: deque())
        self.http_tracker = defaultdict(lambda: deque())
        self.slowloris_tracker = defaultdict(lambda: deque())
        self.frag_tracker = defaultdict(lambda: deque())

        # AI State
        self.ai_buffer = []
        self.ai_model = None
        self.ai_is_training = False
        self.ai_trained = False
        self.ai_packets_processed = 0

        # Advanced spoofing state tracking
        self.host_ip = None
        self.host_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.dhcp_server = None
        self.mac_to_ips_tracker = defaultdict(set)
        self.dns_query_cache = {}
        self.dns_response_cache = {}
        self.anomaly_tracker = defaultdict(deque)
        self.connection_attempt_tracker = {}

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

        # Discover host and gateway network parameters
        self._discover_network_info()

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
        # ARP handling first (layer‑2)
        if pkt.haslayer(ARP):
            self._check_arp_spoof(pkt)
            self._batch_protocol_counts["ARP"] += 1
            self._batch_total_packets += 1
            self._batch_count += 1
            if self._batch_count >= 50:
                self._flush_batches()
            return

        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        size = len(pkt)
        ts = time.time()

        # Learn local IPs from outbound packets
        if _is_private(src):
            self._local_ips.add(src)

        # Batch stats updates
        self._batch_total_packets += 1
        if dst == self.host_ip:
            self._batch_top_talkers[src] += 1

        # Check IP spoofing (Self IP claiming)
        self._check_ip_spoofing(pkt, src, dst, ts)

        if self.config.get("AI_MODE_ENABLED") and SKLEARN_AVAILABLE and src != self.host_ip:
            self._check_ai_anomaly(pkt, src, dst, size, ts)

        # Protocol handling
        if pkt.haslayer(TCP):
            self._batch_protocol_counts["TCP"] += 1
            # Filter out traffic originating from the host itself to prevent self-scans
            if src != self.host_ip:
                self._check_connection_attempt(src, dst, pkt, ts)
                self._check_port_scan(src, dst, pkt[TCP].dport, ts)
                self._check_slow_port_scan(src, dst, pkt[TCP].dport, ts)
                self._check_syn_flood(src, dst, pkt, ts)
                self._check_http_flood(src, dst, pkt, ts)
                self._check_slowloris(src, dst, pkt, ts)
                self._check_tcp_stealth_scan(src, dst, pkt, ts)
                self._check_land_attack(src, dst, pkt, ts)
        elif pkt.haslayer(UDP):
            self._batch_protocol_counts["UDP"] += 1
            if pkt.haslayer(DNS):
                self._check_dns_spoof(pkt, ts)
                self._check_dns_tunnel(pkt, ts)
            elif pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
                self._check_dhcp_spoof(pkt, ts)
        elif pkt.haslayer(ICMP):
            self._batch_protocol_counts["ICMP"] += 1
            if src != self.host_ip:
                self._check_icmp_flood(src, dst, ts)
            self._check_icmp_tunnel(pkt, ts)

        # DDoS detection for all sources (excluding host itself)
        if src != self.host_ip:
            self._check_ddos(src, dst, ts)
        self._check_abnormal_packet(src, dst, size, ts)
        self._check_fragmented(pkt, src, dst, ts)

        # Flush batches periodically
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
        """Standard fast port‑scan detector (inbound, external IPs only)."""
        window = self.config["PORT_SCAN_WINDOW"]
        threshold = self.config["PORT_SCAN_THRESHOLD"]
        key = src
        if key not in self.port_scan_tracker:
            self.port_scan_tracker[key] = deque()
        q = self.port_scan_tracker[key]
        q.append((ts, dport))
        cutoff = ts - window
        while q and q[0][0] < cutoff:
            q.popleft()
        unique_ports = len(set(p for _, p in q))
        if unique_ports >= threshold:
            sample_ports = list(set(p for _, p in q))[:10]
            self._raise_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                src=src,
                dst=dst,
                description=f"Port scan detected: {unique_ports} unique ports probed in {window}s from external IP",
                packet_count=unique_ports,
                details={"unique_ports": unique_ports, "window_seconds": window, "sample_ports": sample_ports},
            )
            self.port_scan_tracker[key].clear()

    def _check_slow_port_scan(self, src, dst, dport, ts):
        """Stealthy port‑scan detector using a longer window."""
        window = self.config["SLOW_PORT_SCAN_WINDOW"]
        threshold = self.config["SLOW_PORT_SCAN_THRESHOLD"]
        key = f"slow:{src}"
        if key not in self.slow_port_scan_tracker:
            self.slow_port_scan_tracker[key] = deque()
        q = self.slow_port_scan_tracker[key]
        q.append((ts, dport))
        cutoff = ts - window
        while q and q[0][0] < cutoff:
            q.popleft()
        unique_ports = len(set(p for _, p in q))
        if unique_ports >= threshold:
            self._raise_alert(
                alert_type="SLOW_PORT_SCAN",
                severity="MEDIUM",
                src=src,
                dst=dst,
                description=f"Slow port scan detected: {unique_ports} ports probed over {window}s",
                packet_count=unique_ports,
                details={"unique_ports": unique_ports, "window_seconds": window},
            )
            self.slow_port_scan_tracker[key].clear()

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
                src=src,
                dst=dst,
                description=f"DDoS pattern: {pps:.0f} pkt/s from {src} (threshold: {threshold})",
                packet_count=len(q),
                details={"packets_per_second": round(pps, 1), "window_seconds": window},
            )
            self.packet_rate_tracker[src].clear()

    def _check_syn_flood(self, src, dst, pkt, ts):
        if not (pkt[TCP].flags & 0x02):
            return
        if pkt[TCP].flags & 0x10:
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
                src=src,
                dst=dst,
                description=f"SYN flood: {len(q)} SYN packets in {window}s (no ACK)",
                packet_count=len(q),
                details={"syn_count": len(q), "window_seconds": window},
            )
            self.syn_tracker[src].clear()

    def _check_connection_attempt(self, src, dst, pkt, ts):
        if not (pkt[TCP].flags & 0x02): # Only SYN packets
            return
        if pkt[TCP].flags & 0x10: # Exclude SYN-ACK
            return
        
        # Debounce alerts per IP (e.g., 1 alert per hour)
        last_alert_time = self.connection_attempt_tracker.get(src, 0)
        if ts - last_alert_time > 3600:
            self.connection_attempt_tracker[src] = ts
            self._raise_alert(
                alert_type="CONNECTION_ATTEMPT",
                severity="MEDIUM",
                src=src,
                dst=dst,
                description=f"Inbound connection attempt (SYN) to port {pkt[TCP].dport}",
                packet_count=1,
                details={"port": pkt[TCP].dport}
            )

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
                src=src,
                dst=dst,
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
                src=src,
                dst=dst,
                description=f"Oversized packet: {size} bytes from {src}",
                packet_count=1,
                details={"packet_size": size, "threshold": self.config["ABNORMAL_PACKET_SIZE"]},
            )

    def _check_fragmented(self, pkt, src, dst, ts):
        if pkt[IP].flags & 0x1 or pkt[IP].frag != 0:
            window = 10
            threshold = self.config["FRAGMENTED_PACKET_THRESHOLD"]
            q = self.frag_tracker[src]
            q.append(ts)
            cutoff = ts - window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= threshold:
                self._raise_alert(
                    alert_type="FRAGMENTED_PACKET",
                    severity="LOW",
                    src=src,
                    dst=dst,
                    description=f"IP fragmentation attack: {len(q)} fragments observed from {src} in {window}s",
                    packet_count=len(q),
                    details={"flags": pkt[IP].flags, "frag_offset": pkt[IP].frag},
                )
                self.frag_tracker[src].clear()

    def _check_ai_anomaly(self, pkt, src, dst, size, ts):
        self.ai_packets_processed += 1
        
        proto_tcp = 1 if pkt.haslayer(TCP) else 0
        proto_udp = 1 if pkt.haslayer(UDP) else 0
        proto_icmp = 1 if pkt.haslayer(ICMP) else 0
        flags = int(pkt[TCP].flags) if pkt.haslayer(TCP) and not isinstance(pkt[TCP].flags, str) else 0
        
        features = [size, proto_tcp, proto_udp, proto_icmp, flags]
        
        if not self.ai_trained:
            self.ai_buffer.append(features)
            if len(self.ai_buffer) >= 500 and not self.ai_is_training:
                self.ai_is_training = True
                def train_model():
                    try:
                        logger.info("Training AI Anomaly Detector on baseline traffic...")
                        self.ai_model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
                        X = np.array(self.ai_buffer)
                        self.ai_model.fit(X)
                        self.ai_trained = True
                        logger.info("AI Anomaly Detector training complete.")
                    except Exception as e:
                        logger.error(f"AI training failed: {e}")
                    finally:
                        self.ai_is_training = False
                        self.ai_buffer.clear()
                threading.Thread(target=train_model, daemon=True).start()
        elif self.ai_model:
            try:
                X_test = np.array([features])
                pred = self.ai_model.predict(X_test)[0]
                if pred == -1:
                    changes = self.anomaly_tracker[f"ai_anomaly_{src}"]
                    changes.append(ts)
                    cutoff = ts - 60
                    while changes and changes[0] < cutoff:
                        changes.popleft()
                    if len(changes) >= 50:
                        self._raise_alert(
                            alert_type="AI_ANOMALY",
                            severity="MEDIUM",
                            src=src,
                            dst=dst,
                            description=f"AI Detection: Anomalous traffic behavior detected from {src}",
                            packet_count=len(changes),
                            details={"features_size": size, "proto_tcp": proto_tcp, "proto_udp": proto_udp}
                        )
                        changes.clear()
            except Exception as e:
                pass

    # ── Discovery & Security Helpers ──────────────────────────────────────────

    def _discover_network_info(self):
        try:
            from scapy.all import conf, get_if_addr, get_if_hwaddr
            iface = self.config.get("INTERFACE", conf.iface)
            self.host_ip = get_if_addr(iface)
            self.host_mac = get_if_hwaddr(iface)
            logger.info(f"Discovered Host IP: {self.host_ip}, Host MAC: {self.host_mac}")
        except Exception as e:
            self.host_ip = None
            self.host_mac = None
            logger.warning(f"Could not discover host IP/MAC: {e}")

        try:
            from scapy.all import conf, getmacbyip
            # Get gateway IP from scapy routing table
            gw_ip = conf.route.route("0.0.0.0")[2]
            if gw_ip and gw_ip != "0.0.0.0":
                self.gateway_ip = gw_ip
                logger.info(f"Discovered Gateway IP: {self.gateway_ip}")
                # Try resolving MAC
                self.gateway_mac = getmacbyip(gw_ip)
                if self.gateway_mac:
                    logger.info(f"Discovered Gateway MAC: {self.gateway_mac}")
                else:
                    self.gateway_mac = None
            else:
                self.gateway_ip = None
                self.gateway_mac = None
        except Exception as e:
            self.gateway_ip = None
            self.gateway_mac = None
            logger.warning(f"Could not discover gateway IP/MAC: {e}")

    def _check_tcp_stealth_scan(self, src, dst, pkt, ts):
        if not pkt.haslayer(TCP):
            return
        flags = pkt[TCP].flags
        scan_type = None
        flags_int = int(flags) if not isinstance(flags, str) else 0
        if isinstance(flags, str):
            if "F" in flags and "P" in flags and "U" in flags:
                scan_type = "Xmas Scan (FIN|PSH|URG)"
            elif flags == "":
                scan_type = "Null Scan (No Flags)"
            elif flags == "F":
                scan_type = "FIN Scan (FIN Only)"
        else:
            if flags_int == 0x29: # FIN (1) + PSH (8) + URG (32) = 41 = 0x29
                scan_type = "Xmas Scan (FIN|PSH|URG)"
            elif flags_int == 0:
                scan_type = "Null Scan (No Flags)"
            elif flags_int == 0x01:
                scan_type = "FIN Scan (FIN Only)"
                
        if scan_type:
            changes = self.anomaly_tracker[f"stealth_scan_{src}"]
            changes.append(ts)
            cutoff = ts - self.config.get("PORT_SCAN_WINDOW", 10)
            while changes and changes[0] < cutoff:
                changes.popleft()
            if len(changes) >= self.config.get("STEALTH_SCAN_THRESHOLD", 3):
                self._raise_alert(
                    alert_type="STEALTH_PORT_SCAN",
                    severity="HIGH",
                    src=src,
                    dst=dst,
                    description=f"Stealth TCP port scan detected: {scan_type} on port {pkt[TCP].dport}",
                    packet_count=len(changes),
                    details={"flags": str(flags), "scan_type": scan_type, "target_port": pkt[TCP].dport}
                )
                changes.clear()

    def _check_land_attack(self, src, dst, pkt, ts):
        if not pkt.haslayer(TCP):
            return
        if src == dst and pkt[TCP].sport == pkt[TCP].dport:
            changes = self.anomaly_tracker[f"land_attack_{src}"]
            changes.append(ts)
            cutoff = ts - self.config.get("PORT_SCAN_WINDOW", 10)
            while changes and changes[0] < cutoff:
                changes.popleft()
            if len(changes) >= self.config.get("LAND_ATTACK_THRESHOLD", 3):
                self._raise_alert(
                    alert_type="LAND_ATTACK",
                    severity="CRITICAL",
                    src=src,
                    dst=dst,
                    description=f"CRITICAL: Land Attack detected: identical source and destination IP/port ({src}:{pkt[TCP].sport})",
                    packet_count=len(changes),
                    details={"port": pkt[TCP].sport}
                )
                changes.clear()

    def _check_ip_spoofing(self, pkt, src, dst, ts):
        if self.host_ip and src == self.host_ip:
            src_mac = pkt.src if hasattr(pkt, 'src') else None
            if src_mac and self.host_mac and src_mac.lower() != self.host_mac.lower():
                changes = self.anomaly_tracker[f"ip_spoof_{src}"]
                changes.append(ts)
                cutoff = ts - self.config.get("ARP_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("IP_SPOOF_THRESHOLD", 3):
                    self._raise_alert(
                        alert_type="IP_SPOOFING",
                        severity="CRITICAL",
                        src=src,
                        dst=dst,
                        description=f"CRITICAL: IP Spoofing detected! Packet claims to come from host IP {self.host_ip} but has MAC {src_mac}",
                        packet_count=len(changes),
                        details={"host_mac": self.host_mac, "spoofed_mac": src_mac}
                    )
                    changes.clear()

    def _check_dhcp_spoof(self, pkt, ts):
        from scapy.all import DHCP
        if not pkt.haslayer(DHCP):
            return
        options = pkt[DHCP].options
        msg_type = None
        server_id = None
        for opt in options:
            if isinstance(opt, tuple):
                if opt[0] == "message-type":
                    msg_type = opt[1]
                elif opt[0] == "server_id":
                    server_id = opt[1]
                    
        if msg_type in (2, 5) and server_id:
            server_ip = str(server_id)
            if not self.dhcp_server:
                self.dhcp_server = server_ip
                logger.info(f"Primary DHCP Server identified: {self.dhcp_server}")
            elif self.dhcp_server != server_ip:
                changes = self.anomaly_tracker[f"rogue_dhcp_{server_ip}"]
                changes.append(ts)
                cutoff = ts - 60
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("ROGUE_DHCP_THRESHOLD", 3):
                    self._raise_alert(
                        alert_type="ROGUE_DHCP",
                        severity="CRITICAL",
                        src=server_ip,
                        dst="255.255.255.255",
                        description=f"CRITICAL: Rogue DHCP Server detected! Multiple DHCP servers active on network: {self.dhcp_server} and {server_ip}",
                        packet_count=len(changes),
                        details={"legitimate_dhcp": self.dhcp_server, "rogue_dhcp": server_ip}
                    )
                    changes.clear()

    # ── ARP Spoof Detection ───────────────────────────────────────────────────

    def _check_arp_spoof(self, pkt):
        arp = pkt[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        if not src_mac or src_mac == "00:00:00:00:00:00" or src_mac.lower() == "ff:ff:ff:ff:ff:ff":
            return
            
        ts = time.time()
        
        # 1. Gateway MAC Spoofing Check
        if self.gateway_ip and src_ip == self.gateway_ip:
            if self.gateway_mac and src_mac.lower() != self.gateway_mac.lower():
                changes = self.anomaly_tracker[f"arp_gw_{src_ip}"]
                changes.append(ts)
                cutoff = ts - self.config.get("ARP_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("ARP_SPOOF_THRESHOLD", 5):
                    self._raise_alert(
                        alert_type="ARP_SPOOF_GATEWAY",
                        severity="CRITICAL",
                        src=src_ip,
                        dst="N/A",
                        description=f"CRITICAL: Gateway ({src_ip}) ARP spoofed! MAC changed from {self.gateway_mac} to {src_mac}",
                        packet_count=len(changes),
                        details={"gateway_ip": self.gateway_ip, "correct_mac": self.gateway_mac, "spoofed_mac": src_mac}
                    )
                    changes.clear()
                return
                
        # 2. Host IP Spoofing Check
        if self.host_ip and src_ip == self.host_ip:
            if self.host_mac and src_mac.lower() != self.host_mac.lower():
                changes = self.anomaly_tracker[f"arp_host_{src_ip}"]
                changes.append(ts)
                cutoff = ts - self.config.get("ARP_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("ARP_SPOOF_THRESHOLD", 5):
                    self._raise_alert(
                        alert_type="ARP_SPOOF_HOST",
                        severity="CRITICAL",
                        src=src_ip,
                        dst="N/A",
                        description=f"CRITICAL: Host IP {self.host_ip} ARP spoofed! MAC {src_mac} is claiming our IP address (our MAC: {self.host_mac})",
                        packet_count=len(changes),
                        details={"host_ip": self.host_ip, "our_mac": self.host_mac, "spoofed_mac": src_mac}
                    )
                    changes.clear()
                return

        # 3. Dynamic ARP Mapping Changes (Clients/Router)
        if src_ip not in self.arp_tracker:
            self.arp_tracker[src_ip] = {"mac": src_mac, "last_ts": ts}
        else:
            old_mac = self.arp_tracker[src_ip]["mac"]
            if old_mac.lower() != src_mac.lower():
                changes = self.arp_changes[src_ip]
                changes.append(ts)
                cutoff = ts - self.config.get("ARP_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("ARP_SPOOF_THRESHOLD", 5):
                    self._raise_alert(
                        alert_type="ARP_SPOOF_CLIENT",
                        severity="HIGH",
                        src=src_ip,
                        dst="N/A",
                        description=f"ARP mapping conflict: IP {src_ip} changed MAC from {old_mac} to {src_mac}",
                        packet_count=len(changes),
                        details={"ip": src_ip, "old_mac": old_mac, "new_mac": src_mac, "total_changes": len(changes)}
                    )
                    self.arp_tracker[src_ip] = {"mac": src_mac, "last_ts": ts}
                    changes.clear()
            else:
                self.arp_tracker[src_ip]["last_ts"] = ts

        # 4. MAC Multiplexing (MitM) Check
        self.mac_to_ips_tracker[src_mac].add(src_ip)
        if len(self.mac_to_ips_tracker[src_mac]) > 1:
            ips_claimed = list(self.mac_to_ips_tracker[src_mac])
            is_mitm = self.gateway_ip in self.mac_to_ips_tracker[src_mac] or len(ips_claimed) >= 2
            if is_mitm:
                changes = self.anomaly_tracker[f"arp_mitm_{src_mac}"]
                changes.append(ts)
                cutoff = ts - self.config.get("ARP_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("ARP_SPOOF_THRESHOLD", 5):
                    self._raise_alert(
                        alert_type="MITM_ARP_SPOOF",
                        severity="CRITICAL",
                        src=src_ip,
                        dst="N/A",
                        description=f"MitM ARP Spoofing: MAC {src_mac} is claiming multiple IP addresses: {ips_claimed}",
                        packet_count=len(changes),
                        details={"attacker_mac": src_mac, "ips_claimed": ips_claimed}
                    )
                    changes.clear()

    # ── DNS Spoof & Tunneling Detection ────────────────────────────────────────

    def _check_dns_spoof(self, pkt, ts):
        dns = pkt[DNS]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if dns.qr == 0:
            qname = dns.qd.qname.decode(errors="ignore") if dns.qd else ""
            if qname:
                self.dns_query_cache[dns.id] = {
                    "qname": qname,
                    "src": src_ip,
                    "dst": dst_ip,
                    "ts": ts
                }
            return
            
        if dns.qr == 1:
            qname = dns.qd.qname.decode(errors="ignore") if dns.qd else ""
            if not qname:
                return
                
            answers = []
            for i in range(dns.ancount):
                rr = dns.an[i]
                if isinstance(rr, DNSRR) and rr.rdata:
                    rdata_str = rr.rdata.decode(errors="ignore") if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    answers.append(rdata_str)
                    
            is_public_domain = not qname.endswith((".local.", ".lan.", ".home.", ".local", ".lan", ".home"))
            for ans in answers:
                if _is_private(ans) and is_public_domain:
                    changes = self.anomaly_tracker[f"dns_rebind_{dns.id}_{qname}"]
                    changes.append(ts)
                    cutoff = ts - self.config.get("DNS_WINDOW", 10)
                    while changes and changes[0] < cutoff:
                        changes.popleft()
                    if len(changes) >= self.config.get("DNS_SPOOF_THRESHOLD", 3):
                        self._raise_alert(
                            alert_type="DNS_REBINDING_SPOOF",
                            severity="HIGH",
                            src=src_ip,
                            dst=dst_ip,
                            description=f"DNS Rebinding / Local Spoofing: Public domain {qname} resolved to local private IP {ans}",
                            packet_count=len(changes),
                            details={"query": qname, "spoofed_ip": ans, "dns_server": src_ip}
                        )
                        changes.clear()

            if dns.id in self.dns_response_cache:
                old_resp = self.dns_response_cache[dns.id]
                if set(old_resp["answers"]) != set(answers):
                    changes = self.anomaly_tracker[f"dns_race_{dns.id}"]
                    changes.append(ts)
                    cutoff = ts - self.config.get("DNS_WINDOW", 10)
                    while changes and changes[0] < cutoff:
                        changes.popleft()
                    if len(changes) >= self.config.get("DNS_SPOOF_THRESHOLD", 3):
                        self._raise_alert(
                            alert_type="DNS_SPOOF",
                            severity="CRITICAL",
                            src=src_ip,
                            dst=dst_ip,
                            description=f"CRITICAL: DNS Spoofing (Racing Response)! Multiple conflicting DNS responses for transaction ID {dns.id} ({qname})",
                            packet_count=len(changes) + 1,
                            details={
                                "query": qname,
                                "transaction_id": dns.id,
                                "first_response": old_resp["answers"],
                                "second_response": answers,
                                "first_dns_server": old_resp["src"],
                                "second_dns_server": src_ip
                            }
                        )
                        changes.clear()
            else:
                self.dns_response_cache[dns.id] = {
                    "qname": qname,
                    "answers": answers,
                    "src": src_ip,
                    "ts": ts
                }

            uptime = time.time() - datetime.fromisoformat(self.stats["start_time"]).timestamp()
            if uptime > 15 and dns.id not in self.dns_query_cache:
                changes = self.anomaly_tracker[f"dns_unsolicited_{dns.id}"]
                changes.append(ts)
                cutoff = ts - self.config.get("DNS_WINDOW", 10)
                while changes and changes[0] < cutoff:
                    changes.popleft()
                if len(changes) >= self.config.get("DNS_SPOOF_THRESHOLD", 3):
                    self._raise_alert(
                        alert_type="DNS_UNSOLICITED_RESPONSE",
                        severity="MEDIUM",
                        src=src_ip,
                        dst=dst_ip,
                        description=f"Unsolicited DNS response: received DNS response for ID {dns.id} ({qname}) without seeing query",
                        packet_count=len(changes),
                        details={"query": qname, "transaction_id": dns.id, "dns_server": src_ip}
                    )
                    changes.clear()

            if len(self.dns_query_cache) > 1000:
                now = time.time()
                self.dns_query_cache = {k: v for k, v in self.dns_query_cache.items() if now - v["ts"] < 10}
            if len(self.dns_response_cache) > 1000:
                now = time.time()
                self.dns_response_cache = {k: v for k, v in self.dns_response_cache.items() if now - v["ts"] < 10}

    def _check_dns_tunnel(self, pkt, ts):
        dns = pkt[DNS]
        src_ip = pkt[IP].src
        if len(dns) > self.config["DNS_TUNNEL_SIZE"]:
            dq = self.dns_query_tracker[src_ip]
            dq.append(ts)
            cutoff = ts - self.config["DNS_WINDOW"]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.config["DNS_TUNNEL_THRESHOLD"]:
                self._raise_alert(
                    alert_type="DNS_TUNNEL",
                    severity="MEDIUM",
                    src=src_ip,
                    dst="N/A",
                    description="Potential DNS tunneling activity (large payloads, high rate)",
                    packet_count=len(dq),
                    details={"query_rate": len(dq), "window_seconds": self.config["DNS_WINDOW"]},
                )
                self.dns_query_tracker[src_ip].clear()

    # ── ICMP Tunneling Detection ───────────────────────────────────────────────

    def _check_icmp_tunnel(self, pkt, ts=None):
        if ts is None:
            ts = time.time()
        src_ip = pkt[IP].src
        if len(pkt[ICMP]) > self.config["ICMP_TUNNEL_SIZE"]:
            dq = self.icmp_tunnel_tracker[src_ip]
            dq.append(ts)
            cutoff = ts - self.config.get("ICMP_TUNNEL_WINDOW", 10)
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.config["ICMP_TUNNEL_THRESHOLD"]:
                self._raise_alert(
                    alert_type="ICMP_TUNNEL",
                    severity="MEDIUM",
                    src=src_ip,
                    dst="N/A",
                    description="Potential ICMP tunneling (large payload, frequent)",
                    packet_count=len(dq),
                    details={"packet_rate": len(dq)},
                )
                self.icmp_tunnel_tracker[src_ip].clear()

    # ── HTTP Flood / Slowloris Detection (TCP port 80/443) ────────────────────

    def _check_http_flood(self, src, dst, pkt, ts):
        if pkt is None or not pkt.haslayer(TCP) or pkt[TCP].dport not in (80, 443):
            return
        dq = self.http_tracker[src]
        dq.append(ts)
        cutoff = ts - self.config["HTTP_WINDOW"]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.config["HTTP_FLOOD_THRESHOLD"]:
            self._raise_alert(
                alert_type="HTTP_FLOOD",
                severity="HIGH",
                src=src,
                dst=dst,
                description=f"High rate of HTTP requests ({len(dq)}) from {src}",
                packet_count=len(dq),
                details={"window_seconds": self.config["HTTP_WINDOW"]},
            )
            self.http_tracker[src].clear()

    def _check_slowloris(self, src, dst, pkt, ts):
        if pkt is None or not pkt.haslayer(TCP):
            return
        if pkt[TCP].flags & 0x02 and not (pkt[TCP].flags & 0x10):
            dq = self.slowloris_tracker[src]
            dq.append(ts)
            cutoff = ts - self.config["SLOWLORIS_WINDOW"]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.config["SLOWLORIS_THRESHOLD"]:
                self._raise_alert(
                    alert_type="SLOWLORIS",
                    severity="HIGH",
                    src=src,
                    dst=dst,
                    description=f"Potential Slowloris attack: {len(dq)} half‑opened connections",
                    packet_count=len(dq),
                    details={"window_seconds": self.config["SLOWLORIS_WINDOW"]},
                )
                self.slowloris_tracker[src].clear()

    # ── Alert Dispatch ────────────────────────────────────────────────────────

    def _raise_alert(self, alert_type, severity, src, dst, description, packet_count, details):
        cooldown_key = f"{alert_type}:{src}"
        now = time.time()
        if cooldown_key in self.email_cooldown:
            if now - self.email_cooldown[cooldown_key] < 30:
                return
        self.email_cooldown[cooldown_key] = now

        import uuid
        with self._lock:
            alert = Alert(
                id=str(uuid.uuid4()),
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
            <html><body style=\"font-family:monospace;background:#0a0e1a;color:#e0e0e0;padding:20px;\">
            <h2 style=\"color:#ff4444;\">⚠ IDS Alert: {alert.alert_type}</h2>
            <table style=\"border-collapse:collapse;width:100%;\">
              <tr><td style=\"padding:6px;color:#aaa;\">Alert ID</td><td style=\"padding:6px;\">{alert.id}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Severity</td><td style=\"padding:6px;color:#ff4444;font-weight:bold;\">{alert.severity}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Timestamp</td><td style=\"padding:6px;\">{alert.timestamp}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Source IP</td><td style=\"padding:6px;\">{alert.source_ip}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Destination</td><td style=\"padding:6px;\">{alert.dest_ip}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Description</td><td style=\"padding:6px;\">{alert.description}</td></tr>
              <tr><td style=\"padding:6px;color:#aaa;\">Details</td><td style=\"padding:6px;\"><pre>{json.dumps(alert.details, indent=2)}</pre></td></tr>
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
        # Custom mock class to run simulation without crashing on scapy references
        class MockPacket:
            def __init__(self, layers, src=None, dst=None, length=64):
                self.layers = layers
                self.src = src or "00:11:22:33:44:55"
                self.dst = dst or "66:77:88:99:aa:bb"
                self.length = length
            def haslayer(self, layer_cls):
                return layer_cls in self.layers
            def __getitem__(self, layer_cls):
                return self.layers[layer_cls]
            def __len__(self):
                return self.length

        attacker_ips = ["192.168.1.55", "10.0.0.88", "172.16.0.200", "45.33.32.156", "185.220.101.5"]
        normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        our_ip = "192.168.1.1"
        ts = time.time()
        scenario_timer = 0
        scenario_interval = 20
        while self.running:
            ts = time.time()
            scenario_timer += 1
            # Normal traffic
            for _ in range(random.randint(5, 20)):
                src = random.choice(normal_ips)
                with self._lock:
                    self.stats["total_packets"] += 1
                    self.stats["top_talkers"][src] += 1
                    proto = random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"])
                    self.stats["protocol_counts"][proto] += 1
                if proto == "TCP" and random.random() < 0.2:
                    self._check_http_flood(src, our_ip, None, ts)

            if scenario_timer % scenario_interval == 0:
                scenario = random.choice(["port_scan", "ddos", "syn_flood", "icmp_flood", "abnormal", "arp_spoof", "dns_spoof", "dns_tunnel", "icmp_tunnel"])
                attacker = random.choice(attacker_ips)
                if scenario == "port_scan":
                    ports = random.sample(range(1, 65535), random.randint(18, 35))
                    for port in ports:
                        with self._lock:
                            self.stats["total_packets"] += 1
                            self.stats["top_talkers"][attacker] += 1
                            self.stats["protocol_counts"]["TCP"] += 1
                        self._check_port_scan(attacker, our_ip, port, ts)
                        self._check_slow_port_scan(attacker, our_ip, port, ts)
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
                elif scenario == "arp_spoof":
                    # Simulate ARP gateway MAC change
                    spoofed_mac = f"00:11:22:33:44:{random.randint(10,99)}"
                    arp_layer = type('arp', (object,), {'psrc': "192.168.1.1", 'hwsrc': spoofed_mac})()
                    pkt = MockPacket({ARP: arp_layer}, src=spoofed_mac)
                    self._check_arp_spoof(pkt)
                elif scenario == "dns_spoof":
                    # Simulate conflicting DNS replies for the same transaction ID
                    dns_id = random.randint(1000, 9999)
                    qname = b"mybank.com."
                    ip_layer = type('ip', (object,), {'src': "8.8.8.8", 'dst': our_ip})()
                    
                    dns_layer1 = type('dns', (object,), {
                        'qr': 1, 'id': dns_id, 'ancount': 1,
                        'qd': type('qd', (object,), {'qname': qname})(),
                        'an': [type('rr', (object,), {'rdata': "104.244.42.1"})()] # Twitter IP
                    })()
                    pkt1 = MockPacket({IP: ip_layer, DNS: dns_layer1})
                    
                    dns_layer2 = type('dns', (object,), {
                        'qr': 1, 'id': dns_id, 'ancount': 1,
                        'qd': type('qd', (object,), {'qname': qname})(),
                        'an': [type('rr', (object,), {'rdata': "192.168.1.99"})()] # Malicious IP
                    })()
                    pkt2 = MockPacket({IP: ip_layer, DNS: dns_layer2})
                    
                    self._check_dns_spoof(pkt1, ts)
                    self._check_dns_spoof(pkt2, ts)
                elif scenario == "dns_tunnel":
                    ip_layer = type('ip', (object,), {'src': attacker, 'dst': our_ip})()
                    dns_layer = type('dns', (object,), {
                        'qr': 0, 'id': 9999,
                        'qd': type('qd', (object,), {'qname': b"verylongquerynameanddnsdatasequencethattravelsthroughthisquery."})(),
                        '__len__': lambda self: 300
                    })()
                    pkt = MockPacket({IP: ip_layer, DNS: dns_layer}, length=350)
                    self._check_dns_tunnel(pkt, ts)
                elif scenario == "icmp_tunnel":
                    ip_layer = type('ip', (object,), {'src': attacker, 'dst': our_ip})()
                    icmp_layer = type('icmp', (object,), {
                        '__len__': lambda self: 150
                    })()
                    pkt = MockPacket({IP: ip_layer, ICMP: icmp_layer}, length=180)
                    self._check_icmp_tunnel(pkt, ts)
            time.sleep(1)

# Singleton instance
engine = IDSEngine(CONFIG)
