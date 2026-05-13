"""
test_offline.py — Offline Simulation (No Root / No Live Interface Needed)
Feeds crafted packets directly into the detector to verify all rules fire
correctly. Run this first to confirm everything works before live capture.

Usage:
    python test_offline.py
"""

import detector
import logger
from datetime import datetime

logger.init()

TS = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
alerts_fired = 0


def run(alert):
    global alerts_fired
    if alert:
        logger.log_alert(alert)
        alerts_fired += 1


print("=" * 55)
print("  Running offline attack simulations...")
print("=" * 55)

# ── Test 1: SYN Flood ────────────────────────────────────────
print("\n[TEST 1] Simulating SYN Flood from 192.168.1.100")
for _ in range(25):                         # 25 SYN packets → exceeds threshold of 20
    run(detector.check_syn_flood("192.168.1.100", TS))

# ── Test 2: Port Scan ────────────────────────────────────────
print("\n[TEST 2] Simulating Port Scan from 10.0.0.55")
for port in range(1, 25):                   # 24 ports → exceeds threshold of 15
    run(detector.check_port_scan("10.0.0.55", port, TS))

# ── Test 3: Unauthorized DNS ─────────────────────────────────
print("\n[TEST 3] Simulating query to rogue DNS server")
run(detector.check_dns_anomaly("192.168.1.50", "185.220.101.5", "google.com", TS))

# ── Test 4: Suspicious Domain ────────────────────────────────
print("\n[TEST 4] Simulating suspicious DNS query")
run(detector.check_dns_anomaly("192.168.1.50", "8.8.8.8", "update-flash.xyz", TS))

# ── Test 5: ICMP Flood ───────────────────────────────────────
print("\n[TEST 5] Simulating ICMP Flood from 172.16.0.9")
for _ in range(35):                         # 35 ICMP packets → exceeds threshold of 30
    run(detector.check_icmp_flood("172.16.0.9", TS))

# ── Summary ──────────────────────────────────────────────────
print("\n" + "=" * 55)
print(f"  Simulation complete. Total alerts fired: {alerts_fired}")
print(f"  Check alerts.csv for full log.")
print("=" * 55)
