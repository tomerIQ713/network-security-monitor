# Cybersecurity Lab Tool

A modular Python-based network security monitoring system for controlled-environment simulation, analysis, and visualization of cyber threats.

---

## Features

| Module | Description |
|--------|-------------|
| **Packet Sniffer** | Captures live traffic or simulates realistic packet flows; extracts IPs, protocols, flags |
| **Port Scanner** | Multi-threaded TCP connect scanner with banner grabbing and OS fingerprinting |
| **IDS Engine** | 7 rule-based detection rules (port scan, brute force, DoS, payload inspection, exfil) |
| **Brute Force Detector** | Built into IDS; sliding-window auth failure tracking per IP |
| **Log Analyzer** | Parses syslog / auth.log / Apache / Nginx; detects anomalies via keywords + patterns |
| **Alert Engine** | Normalizes, deduplicates, scores, and dispatches alerts to console + JSONL file |
| **HTML Dashboard** | Self-contained report with Chart.js bar/doughnut/radar charts and alert tables |

---

## Project Structure

```
cybersec_lab/
├── main.py                  # Orchestrator — run this
├── modules/
│   ├── packet_sniffer.py    # PacketSniffer class
│   ├── port_scanner.py      # PortScanner class
│   ├── ids_engine.py        # IDSEngine + 7 detection rules
│   ├── log_analyzer.py      # LogAnalyzer + anomaly detection
│   ├── alert_engine.py      # AlertEngine (normalizes, deduplicates)
│   └── dashboard.py         # HTML dashboard generator
├── logs/                    # Alert JSONL + sample log files (auto-created)
└── reports/                 # HTML dashboard + JSON report (auto-created)
```

---

## Quickstart

```bash
# Clone / enter project dir
cd cybersec_lab

# No extra dependencies needed for simulation mode
python main.py

# Custom targets and packet count
python main.py --targets 192.168.1.1 10.0.0.5 --packets 300

# Skip dashboard
python main.py --no-dashboard

# Custom dashboard output path
python main.py --dashboard /tmp/my_report.html
```

---

## Live Capture (optional)

Live packet capture uses raw sockets and requires root:

```bash
python main.py <seconds>
```

If run without root, the sniffer automatically falls back to simulation mode.

---

## IDS Detection Rules

| Rule ID | Name | Threshold | MITRE |
|---------|------|-----------|-------|
| IDS-001 | Port Scan | 15 ports / 10s | T1046 |
| IDS-002 | Brute Force | 8 attempts / 60s | T1110 |
| IDS-003 | DoS / Flood | 500 pkts / 5s | T1498 |
| IDS-004 | Payload Signatures | Regex match | T1059 |
| IDS-005 | Insecure Protocol | Telnet/FTP detected | T1021 |
| IDS-006 | Data Exfiltration | 50KB outbound | T1041 |
| IDS-007 | ICMP Sweep | 10 ICMP / 10s | T1018 |

---

## Log Anomaly Detection

- Auth brute force (≥5 failures from one IP)
- HTTP attack patterns (SQLi, XSS, LFI, RFI, path traversal)
- Error rate spikes (≥20 errors)
- User enumeration (≥5 distinct invalid usernames)
- Keyword rules: BREAK-IN ATTEMPT, sudo misuse, OOM kills, etc.

---

## Output Files

| File | Description |
|------|-------------|
| `logs/alerts.jsonl` | One JSON alert per line (machine-readable) |
| `logs/sample_auth.log` | Generated syslog for demo |
| `reports/security_report.json` | Full JSON report with summary + all alerts |
| `reports/dashboard.html` | Interactive HTML dashboard — open in browser |

---

## Extending

**Add an IDS rule:**
```python
# In modules/ids_engine.py, add to _load_rules()
Rule("IDS-008", "My Rule", self._my_rule_fn, "HIGH",
     ThreatCategory.SUSPICIOUS_PAYLOAD, "T1XXX")

def _my_rule_fn(self, packet: Packet) -> Optional[IDSAlert]:
    if some_condition(packet):
        return IDSAlert(...)
    return None
```

**Add a log pattern:**
```python
# In modules/log_analyzer.py
ANOMALY_KEYWORDS["my keyword"] = ("HIGH", "My Anomaly Type")
```

**Add an alert handler (e.g. Slack webhook):**
```python
# In main.py
def slack_handler(alert):
    requests.post(WEBHOOK_URL, json={"text": str(alert)})
alert_engine.register_handler(slack_handler)
```

---

## Requirements

- Python 3.8+
- No third-party packages required for simulation mode
- `scapy` 
- Root / Administrator privileges for raw socket capture

---

*Built for educational and research use in controlled environments.*
