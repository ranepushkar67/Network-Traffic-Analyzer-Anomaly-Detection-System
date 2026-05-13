"""
=============================================================
  Network Traffic Analyzer & Anomaly Detection System
  Author : Pushkar Rane
  Tools  : Python, Scapy, CSV logging, Console alerting
  Detects: Port Scans | SYN Floods | DNS Anomalies | ICMP Floods
=============================================================
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
from collections import defaultdict
from datetime import datetime
import threading
import time
import logger
import detector

# ─── CONFIG ──────────────────────────────────────────────────
INTERFACE       = None        # None = auto-select default interface
PACKET_COUNT    = 0           # 0 = sniff indefinitely
STATS_INTERVAL  = 10          # Print summary every N seconds
# ─────────────────────────────────────────────────────────────

# Shared state (thread-safe via detector module)
stats = {
    "total"     : 0,
    "tcp"       : 0,
    "udp"       : 0,
    "icmp"      : 0,
    "dns"       : 0,
    "alerts"    : 0,
}


def process_packet(packet):
    """Callback fired for every captured packet."""
    if not packet.haslayer(IP):
        return                          # Ignore non-IP traffic

    stats["total"] += 1
    src = packet[IP].src
    dst = packet[IP].dst
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── TCP Analysis ─────────────────────────────────────────
    if packet.haslayer(TCP):
        stats["tcp"] += 1
        flags   = packet[TCP].flags
        dport   = packet[TCP].dport
        sport   = packet[TCP].sport

        # SYN Flood Detection
        if flags == "S":                # Pure SYN (no ACK)
            alert = detector.check_syn_flood(src, ts)
            if alert:
                logger.log_alert(alert)
                stats["alerts"] += 1

        # Port Scan Detection
        alert = detector.check_port_scan(src, dport, ts)
        if alert:
            logger.log_alert(alert)
            stats["alerts"] += 1

    # ── UDP / DNS Analysis ───────────────────────────────────
    elif packet.haslayer(UDP):
        stats["udp"] += 1

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            stats["dns"] += 1
            query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dst_ip = dst                # DNS server being queried

            # Unauthorized DNS Server & Suspicious Domain
            alert = detector.check_dns_anomaly(src, dst_ip, query, ts)
            if alert:
                logger.log_alert(alert)
                stats["alerts"] += 1

    # ── ICMP Analysis ────────────────────────────────────────
    elif packet.haslayer(ICMP):
        stats["icmp"] += 1
        alert = detector.check_icmp_flood(src, ts)
        if alert:
            logger.log_alert(alert)
            stats["alerts"] += 1


def print_stats():
    """Periodically prints a live traffic summary to console."""
    while True:
        time.sleep(STATS_INTERVAL)
        print("\n" + "="*55)
        print(f"  [STATS]  {datetime.now().strftime('%H:%M:%S')}")
        print(f"  Total Packets : {stats['total']}")
        print(f"  TCP           : {stats['tcp']}")
        print(f"  UDP           : {stats['udp']}")
        print(f"  ICMP          : {stats['icmp']}")
        print(f"  DNS Queries   : {stats['dns']}")
        print(f"  Alerts Fired  : {stats['alerts']}")
        print("="*55 + "\n")


def main():
    logger.init()
    print("""
╔══════════════════════════════════════════════════════╗
║   Network Traffic Analyzer & Anomaly Detector        ║
║   By: Pushkar Rane  |  github.com/pushkarrane        ║
╚══════════════════════════════════════════════════════╝
  [*] Starting packet capture... Press Ctrl+C to stop.
    """)

    # Start stats printer in background thread
    t = threading.Thread(target=print_stats, daemon=True)
    t.start()

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            count=PACKET_COUNT,
            store=False             # Don't store packets in memory
        )
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
        print(f"[*] Alerts saved to: alerts.csv")


if __name__ == "__main__":
    main()
