"""
Intrusion Detection System (IDS) + Brute Force Detector
Rule-based engine with ML-ready feature extraction.
"""

import time
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
from enum import Enum

from modules.packet_sniffer import Packet


class ThreatCategory(Enum):
    PORT_SCAN = "Port Scan"
    BRUTE_FORCE = "Brute Force"
    DOS = "Denial of Service"
    SUSPICIOUS_PAYLOAD = "Suspicious Payload"
    PROTOCOL_ANOMALY = "Protocol Anomaly"
    UNUSUAL_TRAFFIC = "Unusual Traffic Spike"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"
    DATA_EXFILTRATION = "Potential Data Exfiltration"


@dataclass
class IDSAlert:
    timestamp: float
    category: ThreatCategory
    severity: str           # LOW / MEDIUM / HIGH / CRITICAL
    src_ip: str
    dst_ip: str
    description: str
    evidence: str
    rule_id: str
    mitre_technique: str = ""

    def __str__(self):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return (f"[{ts}] [{self.severity}] {self.category.value} | "
                f"{self.src_ip} -> {self.dst_ip} | {self.description}")


# ─── Rule Engine ────────────────────────────────────────────────────────────

class Rule:
    def __init__(self, rule_id: str, name: str, check_fn: Callable, severity: str,
                 category: ThreatCategory, mitre: str = ""):
        self.rule_id = rule_id
        self.name = name
        self.check = check_fn
        self.severity = severity
        self.category = category
        self.mitre = mitre


class IDSEngine:
    # Thresholds
    PORT_SCAN_THRESHOLD = 15       # distinct ports in time window
    PORT_SCAN_WINDOW = 10          # seconds
    BRUTE_FORCE_THRESHOLD = 8     # failed attempts
    BRUTE_FORCE_WINDOW = 60        # seconds
    DOS_THRESHOLD = 500            # packets from one IP in window
    DOS_WINDOW = 5                 # seconds
    LARGE_TRANSFER_BYTES = 50_000  # bytes threshold for exfil detection

    PAYLOAD_SIGNATURES = [
        (r"union\s+select", "SQL Injection"),
        (r"<script[\s>]", "XSS Attempt"),
        (r"\.\.\/", "Path Traversal"),
        (r"cmd\.exe|/bin/sh|/bin/bash", "Command Injection"),
        (r"eval\s*\(", "Code Injection"),
        (r"passwd|shadow|etc/", "Credential File Access"),
        (r"powershell\s+-enc", "PowerShell Encoded Payload"),
        (r"base64_decode|base64\.b64decode", "Base64 Obfuscation"),
        (r"wget\s+http|curl\s+http", "Remote Download Attempt"),
    ]

    def __init__(self):
        self.alerts: List[IDSAlert] = []
        # Tracking structures
        self._port_access: Dict[str, deque] = defaultdict(deque)   # ip -> [(ts, port)]
        self._auth_fails: Dict[str, deque] = defaultdict(deque)    # ip -> [timestamps]
        self._packet_counts: Dict[str, deque] = defaultdict(deque) # ip -> [timestamps]
        self._transfer_bytes: Dict[str, int] = defaultdict(int)    # ip -> bytes
        self._rules = self._load_rules()

    def _load_rules(self) -> List[Rule]:
        return [
            Rule("IDS-001", "Port Scan Detection",
                 self._rule_port_scan, "HIGH", ThreatCategory.PORT_SCAN,
                 "T1046 - Network Service Scanning"),
            Rule("IDS-002", "Brute Force Detection",
                 self._rule_brute_force, "HIGH", ThreatCategory.BRUTE_FORCE,
                 "T1110 - Brute Force"),
            Rule("IDS-003", "DoS / Flood Detection",
                 self._rule_dos, "CRITICAL", ThreatCategory.DOS,
                 "T1498 - Network Denial of Service"),
            Rule("IDS-004", "Suspicious Payload",
                 self._rule_payload, "MEDIUM", ThreatCategory.SUSPICIOUS_PAYLOAD,
                 "T1059 - Command and Scripting Interpreter"),
            Rule("IDS-005", "Telnet/FTP Usage",
                 self._rule_insecure_protocol, "MEDIUM", ThreatCategory.PROTOCOL_ANOMALY,
                 "T1021 - Remote Services"),
            Rule("IDS-006", "Data Exfiltration",
                 self._rule_exfiltration, "HIGH", ThreatCategory.DATA_EXFILTRATION,
                 "T1041 - Exfiltration Over C2 Channel"),
            Rule("IDS-007", "Dark-IP Scan (ICMP to internal)",
                 self._rule_icmp_sweep, "MEDIUM", ThreatCategory.PORT_SCAN,
                 "T1018 - Remote System Discovery"),
        ]

    # ── Rule Implementations ──────────────────────────────────────────────

    def _rule_port_scan(self, packet: Packet) -> Optional[IDSAlert]:
        now = packet.timestamp
        ip = packet.src_ip
        dq = self._port_access[ip]
        dq.append((now, packet.dst_port))
        # Evict old entries
        while dq and dq[0][0] < now - self.PORT_SCAN_WINDOW:
            dq.popleft()
        distinct_ports = len(set(p for _, p in dq))
        if distinct_ports >= self.PORT_SCAN_THRESHOLD:
            return IDSAlert(
                timestamp=now,
                category=ThreatCategory.PORT_SCAN,
                severity="HIGH",
                src_ip=ip,
                dst_ip=packet.dst_ip,
                description=f"Port scan: {distinct_ports} distinct ports in {self.PORT_SCAN_WINDOW}s",
                evidence=f"Ports: {sorted(set(p for _, p in dq))[:10]}",
                rule_id="IDS-001",
                mitre_technique="T1046"
            )
        return None

    def _rule_brute_force(self, packet: Packet) -> Optional[IDSAlert]:
        """Detect brute force on SSH/FTP/Telnet/RDP."""
        if packet.dst_port not in (22, 21, 23, 3389, 5900, 110, 143):
            return None
        if "SYN" not in packet.flags:
            return None
        now = packet.timestamp
        ip = packet.src_ip
        dq = self._auth_fails[ip]
        dq.append(now)
        while dq and dq[0] < now - self.BRUTE_FORCE_WINDOW:
            dq.popleft()
        count = len(dq)
        if count >= self.BRUTE_FORCE_THRESHOLD:
            service = {22: "SSH", 21: "FTP", 23: "Telnet",
                       3389: "RDP", 5900: "VNC"}.get(packet.dst_port, "service")
            return IDSAlert(
                timestamp=now,
                category=ThreatCategory.BRUTE_FORCE,
                severity="HIGH",
                src_ip=ip,
                dst_ip=packet.dst_ip,
                description=f"Brute force on {service}: {count} attempts in {self.BRUTE_FORCE_WINDOW}s",
                evidence=f"Target port: {packet.dst_port} ({service})",
                rule_id="IDS-002",
                mitre_technique="T1110"
            )
        return None

    def _rule_dos(self, packet: Packet) -> Optional[IDSAlert]:
        now = packet.timestamp
        ip = packet.src_ip
        dq = self._packet_counts[ip]
        dq.append(now)
        while dq and dq[0] < now - self.DOS_WINDOW:
            dq.popleft()
        count = len(dq)
        if count >= self.DOS_THRESHOLD:
            return IDSAlert(
                timestamp=now,
                category=ThreatCategory.DOS,
                severity="CRITICAL",
                src_ip=ip,
                dst_ip=packet.dst_ip,
                description=f"Flood attack: {count} packets in {self.DOS_WINDOW}s",
                evidence=f"Packet rate: ~{count // self.DOS_WINDOW}/s",
                rule_id="IDS-003",
                mitre_technique="T1498"
            )
        return None

    def _rule_payload(self, packet: Packet) -> Optional[IDSAlert]:
        if not packet.payload_preview:
            return None
        for pattern, name in self.PAYLOAD_SIGNATURES:
            if re.search(pattern, packet.payload_preview, re.IGNORECASE):
                return IDSAlert(
                    timestamp=packet.timestamp,
                    category=ThreatCategory.SUSPICIOUS_PAYLOAD,
                    severity="MEDIUM",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    description=f"Payload signature match: {name}",
                    evidence=f"Pattern: {pattern} | Preview: {packet.payload_preview[:40]}",
                    rule_id="IDS-004",
                    mitre_technique="T1059"
                )
        return None

    def _rule_insecure_protocol(self, packet: Packet) -> Optional[IDSAlert]:
        if packet.dst_port in (23, 21) and packet.protocol == "TCP":
            svc = "Telnet" if packet.dst_port == 23 else "FTP"
            return IDSAlert(
                timestamp=packet.timestamp,
                category=ThreatCategory.PROTOCOL_ANOMALY,
                severity="MEDIUM",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Insecure protocol in use: {svc} (cleartext)",
                evidence=f"Port {packet.dst_port} connection detected",
                rule_id="IDS-005",
                mitre_technique="T1021"
            )
        return None

    def _rule_exfiltration(self, packet: Packet) -> Optional[IDSAlert]:
        """Flag large outbound transfers to external IPs."""
        is_internal_src = packet.src_ip.startswith(("192.168.", "10.", "172.16."))
        is_external_dst = not packet.dst_ip.startswith(("192.168.", "10.", "172.16."))
        if not (is_internal_src and is_external_dst):
            return None
        self._transfer_bytes[packet.src_ip] += packet.size
        total = self._transfer_bytes[packet.src_ip]
        if total >= self.LARGE_TRANSFER_BYTES:
            self._transfer_bytes[packet.src_ip] = 0  # reset to avoid repeated alerts
            return IDSAlert(
                timestamp=packet.timestamp,
                category=ThreatCategory.DATA_EXFILTRATION,
                severity="HIGH",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                description=f"Large outbound transfer: {total:,} bytes to external IP",
                evidence=f"Destination: {packet.dst_ip}:{packet.dst_port}",
                rule_id="IDS-006",
                mitre_technique="T1041"
            )
        return None

    def _rule_icmp_sweep(self, packet: Packet) -> Optional[IDSAlert]:
        if packet.protocol != "ICMP":
            return None
        now = packet.timestamp
        ip = packet.src_ip
        dq = self._port_access[ip]
        dq.append((now, 0))
        while dq and dq[0][0] < now - self.PORT_SCAN_WINDOW:
            dq.popleft()
        count = len(dq)
        if count >= 10:
            return IDSAlert(
                timestamp=now,
                category=ThreatCategory.PORT_SCAN,
                severity="MEDIUM",
                src_ip=ip,
                dst_ip=packet.dst_ip,
                description=f"ICMP sweep: {count} ICMP probes in {self.PORT_SCAN_WINDOW}s",
                evidence=f"Possible host discovery scan",
                rule_id="IDS-007",
                mitre_technique="T1018"
            )
        return None

    # ── Public API ────────────────────────────────────────────────────────

    def analyze(self, packets: List[Packet]) -> List[IDSAlert]:
        """Analyze a list of packets and return all alerts generated."""
        new_alerts = []
        seen = set()  # deduplicate
        for pkt in packets:
            for rule in self._rules:
                try:
                    alert = rule.check(pkt)
                    if alert:
                        key = (alert.rule_id, alert.src_ip, int(alert.timestamp // 5))
                        if key not in seen:
                            seen.add(key)
                            new_alerts.append(alert)
                            self.alerts.append(alert)
                except Exception:
                    pass
        return new_alerts

    def get_stats(self) -> dict:
        stats = defaultdict(int)
        for a in self.alerts:
            stats[a.severity] += 1
            stats[a.category.value] += 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": {s: stats[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "by_category": {c.value: stats[c.value] for c in ThreatCategory},
            "unique_attackers": len(set(a.src_ip for a in self.alerts)),
        }
