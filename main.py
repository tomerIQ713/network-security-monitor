# Cybersecurity Lab Tool
"""
Usage:
    python main.py <seconds>  [--targets IP ...]

Runs silent monitoring for <seconds>, then prints a full report to the
terminal sorted: CRITICAL → HIGH → MEDIUM → LOW, with every alert explained.

Example:
    python main.py 1200          # 20 minutes
    python main.py 60            # quick 1-minute test
"""

import time
import os
import sys
import json
import random
import threading
import argparse
from dataclasses import asdict
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.packet_sniffer import PacketSniffer, Packet
from modules.port_scanner import PortScanner, RISKY_PORTS
from modules.ids_engine import IDSEngine
from modules.log_analyzer import LogAnalyzer, LogSource
from modules.alert_engine import AlertEngine

# ── ANSI ──────────────────────────────────────────────────────────────────────
R    = "\033[91m"
Y    = "\033[93m"
B    = "\033[94m"
G    = "\033[92m"
C    = "\033[96m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

SEV_CLR   = {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# ── Shared State ──────────────────────────────────────────────────────────────
state = {
    "start_time":    time.time(),
    "total_packets": 0,
    "proto_counts":  {"TCP": 0, "UDP": 0, "ICMP": 0, "IGMP": 0},
    "running":       True,
}
state_lock = threading.Lock()

# ── Attack / Traffic Pool ─────────────────────────────────────────────────────
INTERNAL = [f"192.168.1.{i}" for i in range(1, 20)]
EXTERNAL = ["45.33.32.156", "198.51.100.77", "203.0.113.99",
            "185.220.101.45", "91.108.4.1", "8.8.8.8", "104.18.22.46"]
ALL_IPS  = INTERNAL + EXTERNAL

ATTACK_POOL = [
    ("port_scan",  lambda: [
        Packet(time.time(), "45.33.32.156", random.choice(INTERNAL),
               random.randint(50000, 60000), p, "TCP", 60, "SYN")
        for p in random.sample([21,22,23,25,53,80,110,139,143,443,445,993,3306,3389,5900,8080], 16)
    ]),
    ("brute_ssh",  lambda: [
        Packet(time.time(), "198.51.100.77", random.choice(INTERNAL),
               random.randint(50000, 60000), 22, "TCP", 60, "SYN")
        for _ in range(10)
    ]),
    ("brute_rdp",  lambda: [
        Packet(time.time(), "91.108.4.1", random.choice(INTERNAL),
               random.randint(50000, 60000), 3389, "TCP", 60, "SYN")
        for _ in range(10)
    ]),
    ("sqli",       lambda: [
        Packet(time.time(), "203.0.113.99", random.choice(INTERNAL),
               54321, 80, "TCP", 250, "PSH ACK",
               "GET /index.php?id=1 UNION SELECT * FROM users--")
    ]),
    ("exfil",      lambda: [
        Packet(time.time(), random.choice(INTERNAL), "185.220.101.45",
               55000, 443, "TCP", 14000, "PSH ACK")
        for _ in range(5)
    ]),
    ("telnet",     lambda: [
        Packet(time.time(), random.choice(INTERNAL), random.choice(INTERNAL),
               45678, 23, "TCP", 80, "SYN")
    ]),
    ("icmp_sweep", lambda: [
        Packet(time.time(), "45.33.32.156", random.choice(INTERNAL),
               0, 0, "ICMP", 28, "")
        for _ in range(12)
    ]),
    ("xss",        lambda: [
        Packet(time.time(), "203.0.113.99", random.choice(INTERNAL),
               54321, 80, "TCP", 200, "PSH ACK",
               'GET /search?q=<script>alert(1)</script>')
    ]),
    ("normal",     lambda: [
        Packet(time.time(), random.choice(ALL_IPS), random.choice(ALL_IPS),
               random.randint(1024, 65535),
               random.choice([80, 443, 53, 22, 8080]),
               random.choice(["TCP", "UDP"]),
               random.randint(40, 1500),
               random.choice(["SYN", "ACK", "PSH ACK", "FIN ACK"]))
    ] * random.randint(3, 10)),
]

# ── Worker Threads ────────────────────────────────────────────────────────────

def traffic_generator(sniffer: PacketSniffer, ids: IDSEngine, engine: AlertEngine):
    while state["running"]:
        if random.random() < 0.30:
            _, builder = random.choice(ATTACK_POOL)
        else:
            _, builder = ATTACK_POOL[-1]

        new_pkts = builder()
        for a in ids.analyze(new_pkts):
            engine.ingest_ids_alert(a)

        with sniffer._lock:
            sniffer.packets.extend(new_pkts)
            if len(sniffer.packets) > 5000:
                sniffer.packets = sniffer.packets[-5000:]

        with state_lock:
            state["total_packets"] += len(new_pkts)
            for p in new_pkts:
                state["proto_counts"][p.protocol] = (
                    state["proto_counts"].get(p.protocol, 0) + 1
                )

        time.sleep(random.uniform(0.05, 0.2))


def log_generator(analyzer: LogAnalyzer, engine: AlertEngine):
    while state["running"]:
        lines   = analyzer.generate_sample_logs(random.randint(8, 20))
        entries = analyzer.parse_lines(lines, LogSource.AUTH)
        for anomaly in analyzer.detect_anomalies(entries):
            engine.ingest_log_anomaly(anomaly)
        time.sleep(random.uniform(3, 8))


# ── Progress bar ──────────────────────────────────────────────────────────────

def show_progress(duration: int):
    bar_w = 40
    start = time.time()
    while True:
        elapsed = time.time() - start
        done    = elapsed >= duration
        if done:
            elapsed = duration
        frac    = elapsed / duration
        filled  = int(frac * bar_w)
        bar     = "█" * filled + "░" * (bar_w - filled)
        rem     = max(0, duration - int(elapsed))
        m, s    = divmod(rem, 60)
        with state_lock:
            pkts = state["total_packets"]
        print(
            f"\r  {C}[{bar}]{RST} {frac*100:5.1f}%  "
            f"elapsed {int(elapsed):>5}s  remaining {m:02d}:{s:02d}  "
            f"packets {pkts:,}",
            end="", flush=True
        )
        if done:
            print()
            break
        time.sleep(1)


# ── Port Scanner ──────────────────────────────────────────────────────────────

def initial_scan(targets: list, engine: AlertEngine) -> list:
    scanner = PortScanner(timeout=0.8)
    results = []
    print(f"  {C}[*] Port scanning {len(targets)} target(s)…{RST}")
    for target in targets:
        result = scanner.scan(target, simulate=True)
        risk   = scanner.risk_assessment(result)
        for p in result.open_ports:
            if p.port in RISKY_PORTS:
                engine.ingest_raw(
                    source="PortScanner",
                    category="Exposed Service",
                    severity="HIGH",
                    src_ip=target,
                    dst_ip="scanner",
                    description=f"Risky port open: {p.port}/{p.service} on {target}",
                    evidence=p.banner or "no banner grabbed",
                    rule_id="SCAN-001",
                )
        results.append({
            "target":     target,
            "os_guess":   result.os_guess,
            "open_ports": [{"port": p.port, "service": p.service, "banner": p.banner}
                           for p in result.open_ports],
            "risk":       risk,
        })
        rc = {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}.get(risk["risk_level"], RST)
        ports_str = ", ".join(f"{p.port}/{p.service}" for p in result.open_ports) or "none"
        print(f"      {G}✔{RST}  {target:<18}  {result.os_guess:<24}"
              f"  risk={rc}{risk['risk_level']}{RST}  open=[{ports_str}]")
    return results


# ── Report Printer ────────────────────────────────────────────────────────────

def print_report(engine: AlertEngine, scan_results: list,
                 elapsed: int, proto_counts: dict, total_packets: int):

    alerts  = engine.alerts
    stats   = engine.get_dashboard_stats()
    W       = 90
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    def rule(ch="─", clr=C): print(clr + ch * W + RST)
    def blank(): print()

    # ── Header ────────────────────────────────────────────────────────────────
    blank()
    rule("═", R)
    print(f"{R}{BOLD}  🛡  CYBERLAB SECURITY REPORT  ─  {now_str}{RST}")
    m, s = divmod(elapsed, 60)
    h, m = divmod(m, 60)
    dur_str = f"{h}h {m:02d}m {s:02d}s" if h else (f"{m}m {s:02d}s" if m else f"{s}s")
    print(f"{DIM}  Monitoring duration : {dur_str}   "
          f"Packets captured: {total_packets:,}   "
          f"Total alerts: {stats['total_alerts']}{RST}")
    rule("═", R)

    # ── Traffic breakdown ─────────────────────────────────────────────────────
    blank()
    rule("─", C)
    print(f"{C}{BOLD}  NETWORK TRAFFIC{RST}")
    rule("─", C)
    for proto in ["TCP", "UDP", "ICMP", "IGMP"]:
        cnt = proto_counts.get(proto, 0)
        pct = cnt / total_packets * 100 if total_packets else 0
        bar = "█" * int(pct / 100 * 35) + "░" * (35 - int(pct / 100 * 35))
        print(f"  {proto:<6}  {C}{bar}{RST}  {cnt:>8,}  ({pct:5.1f}%)")

    # ── Port scan ─────────────────────────────────────────────────────────────
    if scan_results:
        blank()
        rule("─", G)
        print(f"{G}{BOLD}  PORT SCAN RESULTS{RST}")
        rule("─", G)
        for s in scan_results:
            lvl = s["risk"]["risk_level"]
            rc  = SEV_CLR.get(lvl, RST)
            blank()
            print(f"  {C}Target:{RST} {BOLD}{s['target']}{RST}   "
                  f"{DIM}OS: {s['os_guess']}{RST}   "
                  f"Risk: {rc}{BOLD}{lvl}{RST}")
            for p in s["open_ports"]:
                risky  = p["port"] in RISKY_PORTS
                tag    = f"{R}[RISKY]{RST}" if risky else f"{G}[ ok ]{RST}"
                banner = f"  {DIM}{p['banner'][:50]}{RST}" if p.get("banner") else ""
                print(f"    {tag}  {p['port']:<6}  {p['service']:<16}{banner}")
            if not s["open_ports"]:
                print(f"    {DIM}No open ports detected{RST}")
            for rec in s["risk"].get("recommendations", []):
                print(f"    {Y}⚠  {rec}{RST}")

    # ── Alert overview ────────────────────────────────────────────────────────
    blank()
    rule("─", Y)
    print(f"{Y}{BOLD}  ALERT OVERVIEW{RST}")
    rule("─", Y)
    total_a = stats["total_alerts"]
    avg_s   = stats.get("avg_severity_score", 0)
    blank()
    for sev, key, clr in [
        ("CRITICAL", "critical_count", R),
        ("HIGH",     "high_count",     Y),
        ("MEDIUM",   "medium_count",   B),
        ("LOW",      "low_count",      G),
    ]:
        cnt = stats[key]
        bar = "█" * min(cnt, 50)
        print(f"  {clr}{BOLD}{sev:<10}{RST}  {bar}  {cnt}")
    print(f"\n  Total: {BOLD}{total_a}{RST}   Avg severity score: {BOLD}{avg_s:.2f}/10{RST}")

    # Category counts
    by_cat = stats.get("by_category", {})
    if by_cat:
        blank()
        print(f"  {DIM}Alerts by category:{RST}")
        for cat, cnt in sorted(by_cat.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(cnt, 40)
            print(f"  {C}{cat:<30}{RST}  {bar}  {cnt}")

    # Top attackers
    top_atk = stats.get("top_attackers", [])
    if top_atk:
        blank()
        print(f"  {DIM}Top attacker IPs:{RST}")
        max_a = top_atk[0][1] if top_atk else 1
        for ip, cnt in top_atk[:10]:
            bar = "█" * int(cnt / max_a * 30)
            pct = cnt / total_a * 100 if total_a else 0
            print(f"  {R}{ip:<22}{RST}  {bar}  {cnt}  ({pct:.1f}% of alerts)")

    # ── Per-alert detail grouped by severity then category ────────────────────
    by_sev = defaultdict(list)
    for a in alerts:
        by_sev[a.severity].append(a)

    for sev in SEV_ORDER:
        group = by_sev.get(sev, [])
        if not group:
            continue

        clr = SEV_CLR.get(sev, RST)
        blank()
        rule("═", clr)
        print(f"{clr}{BOLD}  {sev} ALERTS  ──  {len(group)} total{RST}")
        rule("═", clr)

        # Group by category
        by_cat_g = defaultdict(list)
        for a in group:
            by_cat_g[a.category].append(a)

        for cat, cat_alerts in sorted(by_cat_g.items(),
                                       key=lambda x: len(x[1]), reverse=True):
            blank()
            print(f"  {clr}{BOLD}▸  {cat}{RST}  {DIM}({len(cat_alerts)} alerts){RST}")
            print(f"  {DIM}{'─' * (W - 4)}{RST}")

            for a in sorted(cat_alerts, key=lambda x: x.timestamp):
                ts      = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
                src     = a.src_ip     or "unknown"
                dst     = a.dst_ip     or "unknown"
                desc    = a.description
                evid    = a.evidence   or ""
                rule_id = a.rule_id    or "—"
                mitre   = a.mitre      or ""
                source  = a.source     or ""

                print()
                print(f"  {DIM}[{ts}]{RST}  {clr}{BOLD}{sev}{RST}  "
                      f"{DIM}rule: {rule_id}   source: {source}{RST}")
                print(f"    {BOLD}What:    {RST}{desc}")
                print(f"    {BOLD}From:    {RST}{R}{src}{RST}  →  {dst}")
                if evid:
                    print(f"    {BOLD}Evidence:{RST} {DIM}{evid}{RST}")
                if mitre:
                    print(f"    {BOLD}MITRE:   {RST}{Y}{mitre}{RST}")

    # ── Footer ────────────────────────────────────────────────────────────────
    blank()
    rule("═", C)
    print(f"{C}{BOLD}  END OF REPORT  ─  {now_str}{RST}")
    rule("═", C)
    blank()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Run for N seconds then print a full security report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python main.py 1200    # 20 minutes\n  python main.py 60      # quick test"
    )
    parser.add_argument("seconds", type=int,
                        help="How many seconds to monitor before printing the report")
    parser.add_argument("--targets", nargs="+",
                        default=["192.168.1.10", "192.168.1.20", "10.0.0.5"],
                        help="Hosts to port-scan at startup (default: 3 internal hosts)")
    args = parser.parse_args()

    duration = args.seconds
    os.makedirs("logs",    exist_ok=True)
    os.makedirs("reports", exist_ok=True)

    sniffer  = PacketSniffer()
    ids      = IDSEngine()
    analyzer = LogAnalyzer()
    engine   = AlertEngine(log_dir="logs")

    # ── Startup banner ────────────────────────────────────────────────────────
    print(f"\n{C}{'═' * 60}{RST}")
    print(f"{BOLD}  🛡  CYBERLAB SECURITY MONITOR{RST}")
    print(f"{C}{'═' * 60}{RST}")
    m, s = divmod(duration, 60)
    h, m = divmod(m, 60)
    dur_str = f"{h}h {m:02d}m {s:02d}s" if h else (f"{m}m {s:02d}s" if m else f"{s}s")
    print(f"  Duration : {BOLD}{dur_str}{RST}  ({duration}s)")
    print(f"  Targets  : {', '.join(args.targets)}")
    print(f"  Report   : printed to terminal when monitoring ends")
    print()

    scan_results = initial_scan(args.targets, engine)

    threads = [
        threading.Thread(target=traffic_generator, args=(sniffer, ids, engine), daemon=True),
        threading.Thread(target=log_generator,      args=(analyzer, engine),     daemon=True),
    ]
    for t in threads:
        t.start()

    print()
    print(f"  {G}Monitoring…  (Ctrl+C to abort and get the report with data so far){RST}")
    print()

    start = time.time()
    try:
        show_progress(duration)
    except KeyboardInterrupt:
        print(f"\n\n  {Y}Interrupted — generating report from data collected so far…{RST}")

    state["running"] = False
    time.sleep(0.5)   # let last in-flight alerts land

    engine.export_report("reports/security_report.json")

    with state_lock:
        proto_counts  = dict(state["proto_counts"])
        total_packets = state["total_packets"]

    print_report(engine, scan_results, int(time.time() - start),
                 proto_counts, total_packets)

    print(f"  {DIM}Full JSON report also saved → reports/security_report.json{RST}\n")


if __name__ == "__main__":
    main()