"""
Central Alert Engine
Aggregates alerts from all modules, deduplicates, assigns severity scores,
and dispatches notifications.
"""

import time
import json
import os
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import List, Callable, Optional
from enum import Enum

from modules.ids_engine import IDSAlert, ThreatCategory
from modules.log_analyzer import LogAnomaly


class AlertChannel(Enum):
    CONSOLE = "console"
    FILE = "file"
    SIEM = "siem"     # placeholder for real SIEM integration


@dataclass
class NormalizedAlert:
    id: str
    timestamp: float
    source: str          # "IDS" / "LogAnalyzer" / "PortScanner"
    category: str
    severity: str
    severity_score: int  # 1–10
    src_ip: str
    dst_ip: str
    description: str
    evidence: str
    rule_id: str
    mitre: str
    acknowledged: bool = False
    false_positive: bool = False


SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


class AlertEngine:
    def __init__(self, log_dir: str = "logs"):
        self.alerts: List[NormalizedAlert] = []
        self.handlers: List[Callable] = []
        self._id_counter = 0
        self._log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self._dedup_cache: set = set()

        # Register default handlers
        self.register_handler(self._handler_console)
        self.register_handler(self._handler_file)

    def register_handler(self, fn: Callable):
        self.handlers.append(fn)

    def _next_id(self) -> str:
        self._id_counter += 1
        return f"ALERT-{self._id_counter:05d}"

    def _dedup_key(self, alert: NormalizedAlert) -> str:
        return f"{alert.rule_id}:{alert.src_ip}:{int(alert.timestamp // 30)}"

    def ingest_ids_alert(self, ids_alert: IDSAlert) -> Optional[NormalizedAlert]:
        norm = NormalizedAlert(
            id=self._next_id(),
            timestamp=ids_alert.timestamp,
            source="IDS",
            category=ids_alert.category.value,
            severity=ids_alert.severity,
            severity_score=SEVERITY_SCORES.get(ids_alert.severity, 0),
            src_ip=ids_alert.src_ip,
            dst_ip=ids_alert.dst_ip,
            description=ids_alert.description,
            evidence=ids_alert.evidence,
            rule_id=ids_alert.rule_id,
            mitre=ids_alert.mitre_technique,
        )
        return self._dispatch(norm)

    def ingest_log_anomaly(self, anomaly: LogAnomaly, src_ip: str = "") -> Optional[NormalizedAlert]:
        norm = NormalizedAlert(
            id=self._next_id(),
            timestamp=anomaly.timestamp,
            source="LogAnalyzer",
            category=anomaly.anomaly_type,
            severity=anomaly.severity,
            severity_score=SEVERITY_SCORES.get(anomaly.severity, 0),
            src_ip=src_ip or "unknown",
            dst_ip="localhost",
            description=anomaly.description,
            evidence="; ".join(anomaly.evidence[:2]),
            rule_id=f"LOG-{anomaly.anomaly_type[:8].upper().replace(' ', '_')}",
            mitre="",
        )
        return self._dispatch(norm)

    def ingest_raw(self, source: str, category: str, severity: str,
                   src_ip: str, dst_ip: str, description: str,
                   evidence: str = "", rule_id: str = "", mitre: str = "") -> Optional[NormalizedAlert]:
        norm = NormalizedAlert(
            id=self._next_id(),
            timestamp=time.time(),
            source=source,
            category=category,
            severity=severity,
            severity_score=SEVERITY_SCORES.get(severity, 0),
            src_ip=src_ip,
            dst_ip=dst_ip,
            description=description,
            evidence=evidence,
            rule_id=rule_id or f"{source[:3].upper()}-AUTO",
            mitre=mitre,
        )
        return self._dispatch(norm)

    def _dispatch(self, alert: NormalizedAlert) -> Optional[NormalizedAlert]:
        key = self._dedup_key(alert)
        if key in self._dedup_cache:
            return None  # Deduplicated
        self._dedup_cache.add(key)
        self.alerts.append(alert)
        for handler in self.handlers:
            try:
                handler(alert)
            except Exception as e:
                print(f"[AlertEngine] Handler error: {e}")
        return alert

    def acknowledge(self, alert_id: str):
        for a in self.alerts:
            if a.id == alert_id:
                a.acknowledged = True
                return True
        return False

    def mark_false_positive(self, alert_id: str):
        for a in self.alerts:
            if a.id == alert_id:
                a.false_positive = True
                return True
        return False

    # ── Handlers ─────────────────────────────────────────────────────────

    def _handler_console(self, alert: NormalizedAlert):
        COLORS = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[93m",
            "MEDIUM":   "\033[94m",
            "LOW":      "\033[92m",
        }
        RESET = "\033[0m"
        color = COLORS.get(alert.severity, "")
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        print(f"{color}[{ts}] [{alert.severity}] {alert.source} | {alert.category} | "
              f"{alert.src_ip} -> {alert.dst_ip} | {alert.description}{RESET}")

    def _handler_file(self, alert: NormalizedAlert):
        path = os.path.join(self._log_dir, "alerts.jsonl")
        with open(path, "a") as f:
            f.write(json.dumps(asdict(alert)) + "\n")

    # ── Statistics & Reports ──────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict:
        active = [a for a in self.alerts if not a.false_positive]
        unacked = [a for a in active if not a.acknowledged]
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        by_src = defaultdict(int)
        timeline = defaultdict(int)

        for a in active:
            by_sev[a.severity] += 1
            by_cat[a.category] += 1
            by_src[a.src_ip] += 1
            # Bucket by hour
            hour = int(a.timestamp // 3600) * 3600
            timeline[hour] += 1

        return {
            "total_alerts": len(active),
            "unacknowledged": len(unacked),
            "critical_count": by_sev["CRITICAL"],
            "high_count": by_sev["HIGH"],
            "medium_count": by_sev["MEDIUM"],
            "low_count": by_sev["LOW"],
            "by_category": dict(sorted(by_cat.items(), key=lambda x: x[1], reverse=True)),
            "top_attackers": sorted(by_src.items(), key=lambda x: x[1], reverse=True)[:10],
            "timeline": sorted(timeline.items()),
            "avg_severity_score": (
                sum(a.severity_score for a in active) / len(active) if active else 0
            ),
        }

    def export_report(self, path: str):
        """Export all alerts to a JSON report."""
        report = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": self.get_dashboard_stats(),
            "alerts": [asdict(a) for a in self.alerts],
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report exported to {path}")
