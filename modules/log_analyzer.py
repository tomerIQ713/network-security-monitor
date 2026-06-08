"""
Log Analyzer Module
Parses system/application logs and detects anomalies.
"""

import re
import time
import os
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum


class LogSource(Enum):
    SYSLOG = "syslog"
    AUTH = "auth.log"
    APACHE = "apache"
    NGINX = "nginx"
    SSH = "ssh"
    CUSTOM = "custom"


@dataclass
class LogEntry:
    timestamp: float
    level: str       # INFO / WARN / ERROR / CRITICAL
    source: str
    message: str
    raw_line: str
    ip: str = ""
    user: str = ""


@dataclass
class LogAnomaly:
    timestamp: float
    anomaly_type: str
    severity: str
    description: str
    evidence: List[str]
    count: int = 1


# ── Regex Patterns ──────────────────────────────────────────────────────────

PATTERNS = {
    LogSource.SYSLOG: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+"
        r"(?P<proc>[^:]+):\s+(?P<msg>.+)"
    ),
    LogSource.AUTH: re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.+)"
    ),
    LogSource.APACHE: re.compile(
        r"(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<dt>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
    ),
    LogSource.NGINX: re.compile(
        r"(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<dt>[^\]]+)\]\s+"
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)'
    ),
}

# Keyword → (severity, anomaly_type)
ANOMALY_KEYWORDS: Dict[str, tuple] = {
    "Failed password":           ("HIGH",     "Brute Force"),
    "Invalid user":              ("HIGH",     "Brute Force"),
    "authentication failure":    ("HIGH",     "Auth Failure"),
    "Accepted password":         ("INFO",     "Successful Auth"),
    "sudo":                      ("MEDIUM",   "Privilege Escalation"),
    "NOPASSWD":                  ("HIGH",     "SUDO Misconfiguration"),
    "segfault":                  ("MEDIUM",   "Application Crash"),
    "Out of memory":             ("HIGH",     "Resource Exhaustion"),
    "connection refused":        ("LOW",      "Connection Refused"),
    "permission denied":         ("MEDIUM",   "Unauthorized Access"),
    "POSSIBLE BREAK-IN ATTEMPT": ("CRITICAL", "Break-In Attempt"),
    "kernel: BUG":               ("CRITICAL", "Kernel Panic"),
    "oom-kill":                  ("HIGH",     "OOM Kill"),
    "disk quota exceeded":       ("MEDIUM",   "Disk Quota"),
    "repeated login failures":   ("HIGH",     "Repeated Auth Failure"),
    "Connection closed":         ("LOW",      "Connection Drop"),
}

HTTP_ATTACK_PATHS = [
    (r"\.\./", "Path Traversal"),
    (r"union.*select", "SQL Injection"),
    (r"<script", "XSS Attempt"),
    (r"etc/passwd", "LFI Attempt"),
    (r"cmd=|shell=|exec=", "Command Injection"),
    (r"\.php\?.*=http", "RFI Attempt"),
    (r"wp-login\.php", "WordPress Brute Force"),
    (r"\.git/", "Git Exposure"),
    (r"\.env", "Env File Exposure"),
]


class LogAnalyzer:
    AUTH_FAIL_THRESHOLD = 5
    AUTH_FAIL_WINDOW = 300   # 5 minutes
    ERROR_SPIKE_THRESHOLD = 20
    ERROR_SPIKE_WINDOW = 60

    def __init__(self):
        self.entries: List[LogEntry] = []
        self.anomalies: List[LogAnomaly] = []
        self._fail_tracker: Dict[str, list] = defaultdict(list)

    def parse_file(self, filepath: str, source: LogSource = LogSource.SYSLOG) -> List[LogEntry]:
        """Parse a log file and return structured entries."""
        if not os.path.exists(filepath):
            return []
        entries = []
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                entry = self._parse_line(line.rstrip(), source)
                if entry:
                    entries.append(entry)
        self.entries.extend(entries)
        return entries

    def parse_lines(self, lines: List[str], source: LogSource = LogSource.CUSTOM) -> List[LogEntry]:
        """Parse in-memory log lines."""
        entries = []
        for line in lines:
            entry = self._parse_line(line, source)
            if entry:
                entries.append(entry)
        self.entries.extend(entries)
        return entries

    def _parse_line(self, line: str, source: LogSource) -> Optional[LogEntry]:
        if not line.strip():
            return None
        # Determine level
        level = "INFO"
        if any(w in line for w in ("ERROR", "FAIL", "fail", "error", "CRITICAL")):
            level = "ERROR"
        elif any(w in line for w in ("WARN", "WARNING", "warn")):
            level = "WARN"
        elif any(w in line for w in ("CRIT", "CRITICAL", "BREAK-IN")):
            level = "CRITICAL"

        # Extract IP
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        ip = ip_match.group(1) if ip_match else ""

        # Extract user
        user_match = re.search(r"user[=\s](\w+)", line, re.IGNORECASE)
        user = user_match.group(1) if user_match else ""

        return LogEntry(
            timestamp=time.time(),
            level=level,
            source=source.value,
            message=line[:200],
            raw_line=line,
            ip=ip,
            user=user,
        )

    def detect_anomalies(self, entries: Optional[List[LogEntry]] = None) -> List[LogAnomaly]:
        """Run all anomaly detection rules."""
        if entries is None:
            entries = self.entries
        anomalies = []

        # Rule 1: Keyword-based detection
        anomalies.extend(self._detect_keywords(entries))

        # Rule 2: Auth brute force
        anomalies.extend(self._detect_auth_bruteforce(entries))

        # Rule 3: HTTP attack signatures
        anomalies.extend(self._detect_http_attacks(entries))

        # Rule 4: Error spike
        anomalies.extend(self._detect_error_spikes(entries))

        # Rule 5: User enumeration
        anomalies.extend(self._detect_user_enum(entries))

        self.anomalies.extend(anomalies)
        return anomalies

    def _detect_keywords(self, entries: List[LogEntry]) -> List[LogAnomaly]:
        found = []
        seen = defaultdict(list)
        for entry in entries:
            for keyword, (sev, atype) in ANOMALY_KEYWORDS.items():
                if keyword.lower() in entry.message.lower() and sev != "INFO":
                    seen[(keyword, atype, sev)].append(entry.message[:80])
        for (kw, atype, sev), msgs in seen.items():
            found.append(LogAnomaly(
                timestamp=time.time(),
                anomaly_type=atype,
                severity=sev,
                description=f"{atype} keyword detected: '{kw}'",
                evidence=msgs[:3],
                count=len(msgs)
            ))
        return found

    def _detect_auth_bruteforce(self, entries: List[LogEntry]) -> List[LogAnomaly]:
        ip_fails = defaultdict(list)
        for entry in entries:
            if any(k in entry.message for k in ("Failed password", "Invalid user", "authentication failure")):
                if entry.ip:
                    ip_fails[entry.ip].append(entry.timestamp)

        anomalies = []
        for ip, timestamps in ip_fails.items():
            if len(timestamps) >= self.AUTH_FAIL_THRESHOLD:
                anomalies.append(LogAnomaly(
                    timestamp=time.time(),
                    anomaly_type="Brute Force Attack",
                    severity="CRITICAL",
                    description=f"Auth brute force from {ip}: {len(timestamps)} failures",
                    evidence=[f"{len(timestamps)} failed auth attempts from {ip}"],
                    count=len(timestamps)
                ))
        return anomalies

    def _detect_http_attacks(self, entries: List[LogEntry]) -> List[LogAnomaly]:
        found = defaultdict(list)
        for entry in entries:
            for pattern, name in HTTP_ATTACK_PATHS:
                if re.search(pattern, entry.message, re.IGNORECASE):
                    found[name].append(entry.message[:80])

        return [
            LogAnomaly(
                timestamp=time.time(),
                anomaly_type=name,
                severity="HIGH",
                description=f"HTTP attack pattern: {name} ({len(msgs)} hits)",
                evidence=msgs[:3],
                count=len(msgs)
            )
            for name, msgs in found.items()
        ]

    def _detect_error_spikes(self, entries: List[LogEntry]) -> List[LogAnomaly]:
        error_entries = [e for e in entries if e.level in ("ERROR", "CRITICAL")]
        if len(error_entries) >= self.ERROR_SPIKE_THRESHOLD:
            return [LogAnomaly(
                timestamp=time.time(),
                anomaly_type="Error Spike",
                severity="HIGH",
                description=f"Unusually high error rate: {len(error_entries)} errors detected",
                evidence=[e.message[:60] for e in error_entries[:3]],
                count=len(error_entries)
            )]
        return []

    def _detect_user_enum(self, entries: List[LogEntry]) -> List[LogAnomaly]:
        users = Counter()
        for entry in entries:
            if "Invalid user" in entry.message:
                m = re.search(r"Invalid user (\S+)", entry.message)
                if m:
                    users[m.group(1)] += 1
        if len(users) >= 5:
            return [LogAnomaly(
                timestamp=time.time(),
                anomaly_type="User Enumeration",
                severity="HIGH",
                description=f"Multiple invalid usernames tried: {len(users)} unique usernames",
                evidence=[f"{u}: {c} attempts" for u, c in users.most_common(5)],
                count=sum(users.values())
            )]
        return []

    def generate_sample_logs(self, n: int = 100) -> List[str]:
        """Generate realistic sample log lines for demo."""
        import random
        ips = [f"192.168.1.{i}" for i in range(1, 10)] + \
              ["10.0.0.5", "203.0.113.42", "198.51.100.7", "45.33.32.156"]
        users = ["admin", "root", "ubuntu", "postgres", "john", "deploy", "backup"]
        lines = []
        base_time = time.time() - 3600

        templates = [
            lambda: f"sshd[1234]: Failed password for {random.choice(users)} from {random.choice(ips)} port {random.randint(10000,60000)} ssh2",
            lambda: f"sshd[1234]: Invalid user {random.choice(users)} from {random.choice(ips)}",
            lambda: f"sshd[2345]: Accepted password for ubuntu from 192.168.1.5 port 52341 ssh2",
            lambda: f"sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
            lambda: f"kernel: Out of memory: Kill process 1234 ({random.choice(['nginx','postgres','java'])})",
            lambda: f"sshd[3456]: POSSIBLE BREAK-IN ATTEMPT from {random.choice(ips)}",
            lambda: f'nginx: {random.choice(ips)} - - [01/Jun/2025:12:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 0',
            lambda: f'apache: {random.choice(ips)} - - [01/Jun/2025:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 1234',
            lambda: f"syslog: Connection from {random.choice(ips)} port {random.randint(1024,65535)}",
            lambda: f"cron[999]: (root) CMD (/usr/bin/backup.sh)",
            lambda: f"systemd: service nginx.service failed",
            lambda: f"kernel: disk quota exceeded for uid 1001",
        ]
        weights = [15, 15, 5, 3, 2, 1, 3, 4, 8, 5, 3, 2]

        for _ in range(n):
            fn = random.choices(templates, weights=weights)[0]
            lines.append(fn())

        return lines

    def summary(self) -> dict:
        return {
            "total_entries": len(self.entries),
            "total_anomalies": len(self.anomalies),
            "by_severity": Counter(a.severity for a in self.anomalies),
            "by_type": Counter(a.anomaly_type for a in self.anomalies),
            "top_offending_ips": Counter(
                e.ip for e in self.entries if e.ip and e.level in ("ERROR", "CRITICAL")
            ).most_common(5),
        }
