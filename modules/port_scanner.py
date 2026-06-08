"""
Port Scanner Module
Scans target hosts for open ports and identifies exposed services.
"""

import socket
import threading
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum


class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    SYN = "SYN Stealth"
    UDP = "UDP"
    PING = "Ping"


@dataclass
class PortResult:
    port: int
    state: str        # open / closed / filtered
    service: str
    banner: str = ""
    response_time_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    scan_type: ScanType
    start_time: float
    end_time: float
    open_ports: List[PortResult]
    closed_count: int
    filtered_count: int
    os_guess: str = "Unknown"

    @property
    def duration(self):
        return self.end_time - self.start_time


SERVICE_DB: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch", 2181: "Zookeeper",
    6443: "Kubernetes", 2379: "etcd", 4567: "Sinatra",
    11211: "Memcached", 5672: "RabbitMQ", 9092: "Kafka",
}

RISKY_PORTS = {21, 23, 445, 3389, 5900, 1433, 3306, 27017, 9200, 6379, 11211}


class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def _grab_banner(self, sock: socket.socket) -> str:
        """Attempt to grab service banner."""
        try:
            sock.settimeout(2)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:80]
        except Exception:
            return ""

    def _probe_port(self, target: str, port: int) -> PortResult:
        """TCP connect scan a single port."""
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((target, port))
            elapsed = (time.time() - start) * 1000

            if result == 0:
                service = SERVICE_DB.get(port, "unknown")
                banner = ""
                try:
                    # Send probe for banner
                    if port in (80, 8080, 8443):
                        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = self._grab_banner(s)
                except Exception:
                    pass
                s.close()
                return PortResult(port, "open", service, banner, round(elapsed, 2))
            else:
                s.close()
                return PortResult(port, "closed", SERVICE_DB.get(port, ""), "", round(elapsed, 2))

        except socket.timeout:
            return PortResult(port, "filtered", SERVICE_DB.get(port, ""), "", self.timeout * 1000)
        except OSError:
            return PortResult(port, "closed", SERVICE_DB.get(port, ""), "", 0.0)

    def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_type: ScanType = ScanType.TCP_CONNECT,
        simulate: bool = True
    ) -> ScanResult:
        """
        Scan a target host. If simulate=True, returns realistic fake results
        without actual network I/O (safe for demos).
        """
        if simulate:
            return self._simulate_scan(target, ports, scan_type)

        # Validate target
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve host: {target}")

        if ports is None:
            ports = self._common_ports()

        start_time = time.time()
        open_ports = []
        closed_count = 0
        filtered_count = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._probe_port, target, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result.state == "open":
                    open_ports.append(result)
                elif result.state == "closed":
                    closed_count += 1
                else:
                    filtered_count += 1

        open_ports.sort(key=lambda x: x.port)
        end_time = time.time()

        return ScanResult(
            target=target,
            scan_type=scan_type,
            start_time=start_time,
            end_time=end_time,
            open_ports=open_ports,
            closed_count=closed_count,
            filtered_count=filtered_count,
            os_guess=self._guess_os(open_ports),
        )

    def _simulate_scan(
        self,
        target: str,
        ports: Optional[List[int]],
        scan_type: ScanType
    ) -> ScanResult:
        """Generate realistic simulated scan results for demonstration."""
        import random

        if ports is None:
            ports = self._common_ports()

        start_time = time.time()
        time.sleep(0.5)  # Simulate scan time

        # Decide which ports are "open" based on target type
        open_port_nums = set()
        if target.startswith("192.168") or target.startswith("10."):
            # Internal host - more services exposed
            candidates = [22, 80, 443, 3306, 5432, 8080, 6379]
            open_port_nums = set(random.sample(candidates, k=random.randint(2, 5)))
        else:
            # External host - fewer services
            candidates = [80, 443, 22]
            open_port_nums = set(random.sample(candidates, k=random.randint(1, 3)))

        open_ports = []
        closed_count = 0
        filtered_count = 0

        for port in ports:
            if port in open_port_nums:
                service = SERVICE_DB.get(port, "unknown")
                banners = {
                    22: "OpenSSH_8.4p1 Ubuntu",
                    80: "Apache/2.4.51",
                    443: "nginx/1.21.6",
                    3306: "5.7.36-MySQL Community Server",
                    5432: "PostgreSQL 13.5",
                    6379: "Redis 6.2.6",
                    8080: "Jetty/9.4.43",
                }
                open_ports.append(PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banners.get(port, ""),
                    response_time_ms=round(random.uniform(0.5, 15), 2)
                ))
            else:
                if random.random() < 0.1:
                    filtered_count += 1
                else:
                    closed_count += 1

        open_ports.sort(key=lambda x: x.port)

        return ScanResult(
            target=target,
            scan_type=scan_type,
            start_time=start_time,
            end_time=time.time(),
            open_ports=open_ports,
            closed_count=closed_count,
            filtered_count=filtered_count,
            os_guess=self._guess_os(open_ports),
        )

    def _guess_os(self, open_ports: List[PortResult]) -> str:
        """Heuristic OS fingerprinting based on open services."""
        port_nums = {p.port for p in open_ports}
        if 3389 in port_nums or 445 in port_nums:
            return "Windows"
        if 22 in port_nums:
            for p in open_ports:
                if p.port == 22 and "Ubuntu" in p.banner:
                    return "Linux (Ubuntu)"
                if p.port == 22 and "Debian" in p.banner:
                    return "Linux (Debian)"
            return "Linux / Unix"
        if 80 in port_nums or 443 in port_nums:
            return "Unknown (Web server)"
        return "Unknown"

    def _common_ports(self) -> List[int]:
        """Return the top 100 commonly scanned ports."""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
            995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 6379, 5432,
            1433, 1521, 9200, 11211, 5672, 9092, 2181, 6443, 2379, 4567,
        ]

    def risk_assessment(self, result: ScanResult) -> dict:
        """Assess risk of exposed ports."""
        risky = [p for p in result.open_ports if p.port in RISKY_PORTS]
        risk_level = "LOW"
        if len(risky) >= 3:
            risk_level = "CRITICAL"
        elif len(risky) >= 1:
            risk_level = "HIGH"
        elif len(result.open_ports) >= 5:
            risk_level = "MEDIUM"

        recommendations = []
        for p in risky:
            recs = {
                21: "Disable FTP — use SFTP instead.",
                23: "Disable Telnet — use SSH.",
                445: "Restrict SMB access; patch EternalBlue.",
                3389: "Limit RDP to VPN; enable NLA.",
                5900: "Disable VNC or use strong auth + encryption.",
                1433: "Firewall MSSQL port from public access.",
                3306: "Restrict MySQL to localhost.",
                27017: "Enable MongoDB auth; restrict network access.",
                9200: "Enable Elasticsearch security features.",
                6379: "Add Redis password; bind to localhost.",
                11211: "Bind Memcached to localhost only.",
            }
            if p.port in recs:
                recommendations.append(recs[p.port])

        return {
            "risk_level": risk_level,
            "risky_open_ports": [(p.port, p.service) for p in risky],
            "recommendations": recommendations,
        }
