"""
Packet Sniffer Module
Captures and analyzes network traffic (simulated for portability).
For real capture, requires scapy + root privileges.
"""

import socket
import struct
import time
import threading
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: str = ""
    payload_preview: str = ""


class PacketSniffer:
    PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP"}
    COMMON_PORTS = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
        23: "Telnet", 25: "SMTP", 53: "DNS", 3306: "MySQL",
        5432: "PostgreSQL", 3389: "RDP", 8080: "HTTP-Alt",
        6379: "Redis", 27017: "MongoDB"
    }

    def __init__(self, interface: str = "eth0", max_packets: int = 1000):
        self.interface = interface
        self.max_packets = max_packets
        self.packets: List[Packet] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.stats = defaultdict(int)
        self._lock = threading.Lock()

    def _parse_ip_header(self, raw_data: bytes):
        """Parse IPv4 header from raw bytes."""
        iph = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
        version_ihl = iph[0]
        ihl = (version_ihl & 0xF) * 4
        protocol = iph[6]
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])
        return ihl, protocol, src, dst

    def _parse_tcp_header(self, raw_data: bytes):
        """Parse TCP header."""
        tcph = struct.unpack("!HHLLBBHHH", raw_data[:20])
        src_port = tcph[0]
        dst_port = tcph[1]
        offset = (tcph[4] >> 4) * 4
        flags_byte = tcph[5]
        flags = ""
        if flags_byte & 0x02: flags += "SYN "
        if flags_byte & 0x10: flags += "ACK "
        if flags_byte & 0x01: flags += "FIN "
        if flags_byte & 0x04: flags += "RST "
        if flags_byte & 0x08: flags += "PSH "
        return src_port, dst_port, offset, flags.strip()

    def _parse_udp_header(self, raw_data: bytes):
        """Parse UDP header."""
        udph = struct.unpack("!HHHH", raw_data[:8])
        return udph[0], udph[1]

    def start_live(self):
        """Start live packet capture using raw socket (requires root)."""
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            self.running = True
            print(f"[*] Sniffing on {self.interface} ...")
            while self.running and len(self.packets) < self.max_packets:
                raw_data, _ = s.recvfrom(65535)
                # Ethernet frame: skip first 14 bytes
                ip_data = raw_data[14:]
                try:
                    ihl, proto, src, dst = self._parse_ip_header(ip_data)
                    proto_name = self.PROTOCOLS.get(proto, str(proto))
                    transport = ip_data[ihl:]
                    src_port, dst_port, flags, payload = 0, 0, "", ""

                    if proto == 6:  # TCP
                        src_port, dst_port, tcp_offset, flags = self._parse_tcp_header(transport)
                        payload = transport[tcp_offset:tcp_offset+32].decode("utf-8", errors="replace")
                    elif proto == 17:  # UDP
                        src_port, dst_port = self._parse_udp_header(transport)
                        payload = transport[8:40].decode("utf-8", errors="replace")

                    pkt = Packet(
                        timestamp=time.time(),
                        src_ip=src,
                        dst_ip=dst,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto_name,
                        size=len(raw_data),
                        flags=flags,
                        payload_preview=payload[:32]
                    )
                    with self._lock:
                        self.packets.append(pkt)
                        self.stats[proto_name] += 1
                        self.stats["total"] += 1
                except Exception:
                    pass
        except PermissionError:
            print("[!] Live capture requires root. Using simulation mode.")
            self.start_simulation()

    def start_simulation(self, packet_count: int = 200):
        """Simulate realistic network traffic for demo/testing."""
        print("[*] Starting packet simulation...")
        internal_ips = [f"192.168.1.{i}" for i in range(1, 20)]
        external_ips = ["8.8.8.8", "1.1.1.1", "104.18.22.46", "13.107.42.14",
                        "185.60.216.35", "151.101.1.140", "198.51.100.22"]
        all_ips = internal_ips + external_ips

        protocols = ["TCP"] * 60 + ["UDP"] * 25 + ["ICMP"] * 10 + ["IGMP"] * 5
        port_pairs = [
            (random.randint(49152, 65535), 80),
            (random.randint(49152, 65535), 443),
            (random.randint(49152, 65535), 22),
            (random.randint(49152, 65535), 53),
            (random.randint(49152, 65535), 21),
            (random.randint(49152, 65535), 3389),
        ]

        for _ in range(packet_count):
            proto = random.choice(protocols)
            src = random.choice(all_ips)
            dst = random.choice(all_ips)
            while dst == src:
                dst = random.choice(all_ips)

            sp, dp = random.choice(port_pairs)
            flags = ""
            if proto == "TCP":
                flags = random.choice(["SYN", "ACK", "SYN ACK", "FIN ACK", "PSH ACK"])

            pkt = Packet(
                timestamp=time.time() - random.uniform(0, 300),
                src_ip=src,
                dst_ip=dst,
                src_port=sp,
                dst_port=dp,
                protocol=proto,
                size=random.randint(40, 1500),
                flags=flags,
                payload_preview=f"{''.join(random.choices('abcdefghijklmnop0123456789', k=16))}"
            )
            with self._lock:
                self.packets.append(pkt)
                self.stats[proto] += 1
                self.stats["total"] += 1

        print(f"[+] Simulated {packet_count} packets.")

    def stop(self):
        self.running = False

    def get_summary(self) -> dict:
        with self._lock:
            return {
                "total": self.stats["total"],
                "by_protocol": {k: v for k, v in self.stats.items() if k != "total"},
                "unique_src_ips": len(set(p.src_ip for p in self.packets)),
                "unique_dst_ips": len(set(p.dst_ip for p in self.packets)),
                "avg_packet_size": (
                    sum(p.size for p in self.packets) / len(self.packets)
                    if self.packets else 0
                ),
                "top_talkers": self._top_talkers(),
                "top_services": self._top_services(),
            }

    def _top_talkers(self, n: int = 5) -> list:
        counts = defaultdict(int)
        for p in self.packets:
            counts[p.src_ip] += 1
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def _top_services(self, n: int = 5) -> list:
        counts = defaultdict(int)
        for p in self.packets:
            svc = self.COMMON_PORTS.get(p.dst_port, str(p.dst_port))
            counts[svc] += 1
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
