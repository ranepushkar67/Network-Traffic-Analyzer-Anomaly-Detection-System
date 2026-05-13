# Network Traffic Analyzer & Anomaly Detection System
**By: Pushkar Rane | SOC / Network Security Project**

---

## What This Project Does

Captures live network traffic and automatically detects four attack types:

| Detection Rule       | Attack Type               | Severity |
|----------------------|---------------------------|----------|
| SYN Flood            | DoS / DDoS                | HIGH     |
| Port Scan            | Reconnaissance (Nmap etc) | HIGH     |
| Unauthorized DNS     | DNS Hijack / Rogue Server | MEDIUM   |
| Suspicious Domain    | Malware C2 / Phishing     | MEDIUM   |
| ICMP Flood           | Ping Flood / Smurf        | MEDIUM   |

All alerts are printed **colour-coded** in the terminal and saved to **alerts.csv**
for post-incident forensic review.

---

## Project Structure

```
network_analyzer/
├── analyzer.py       ← Main script (packet capture + orchestration)
├── detector.py       ← Detection rules & thresholds
├── logger.py         ← CSV logging + coloured console output
├── test_offline.py   ← Offline test (no root needed, no live traffic)
├── requirements.txt  ← Python dependencies
└── README.md         ← This file
```

---

## How to Perform / Run This Project

### Step 1 — Set Up Your Environment

You need **Python 3.8+** and a Linux/Windows machine (Kali Linux recommended for live capture).

```bash
# Create a virtual environment (optional but clean)
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

### Step 2 — Run the Offline Test First (No Root Needed)

This simulates all 5 attack types using crafted data — no network interface required.
Great for verifying everything works before going live.

```bash
python test_offline.py
```

**Expected output:**
```
[ALERT] [HIGH]   SYN FLOOD     → 192.168.1.100 — 25 SYN packets in 5s
[ALERT] [HIGH]   PORT SCAN     → 10.0.0.55     — 24 unique ports probed in 10s
[ALERT] [MEDIUM] UNAUTHORIZED DNS → 192.168.1.50 — query to 185.220.101.5
[ALERT] [MEDIUM] SUSPICIOUS DOMAIN → update-flash.xyz
[ALERT] [MEDIUM] ICMP FLOOD    → 172.16.0.9    — 35 ICMP packets in 5s
```

Check `alerts.csv` to see the structured log file.

---

### Step 3 — Run Live Capture (Root / Admin Required)

```bash
# Linux (Kali / Ubuntu)
sudo python3 analyzer.py

# Windows (run terminal as Administrator)
python analyzer.py
```

The tool auto-selects your default network interface.
To specify a custom interface, edit `INTERFACE` in `analyzer.py`:

```python
INTERFACE = "eth0"     # Linux example
INTERFACE = "Wi-Fi"    # Windows example
```

---

### Step 4 — Simulate Real Attacks Against Your Lab

In a **separate terminal or VM**, generate attack traffic to trigger alerts:

```bash
# ── Port Scan (requires nmap) ──────────────────────────────
nmap -sS 192.168.1.1              # SYN scan (triggers port scan + SYN flood)
nmap -p 1-1000 192.168.1.1        # Full port range scan

# ── ICMP Flood ─────────────────────────────────────────────
ping -f 192.168.1.1               # Linux flood ping (root required)
hping3 --icmp --flood 192.168.1.1 # hping3 flood

# ── SYN Flood ──────────────────────────────────────────────
hping3 -S --flood -p 80 192.168.1.1

# ── Unauthorized DNS query ─────────────────────────────────
nslookup google.com 185.220.101.5   # Query a rogue DNS server
```

Watch alerts fire in real time in your `analyzer.py` terminal.

---

### Step 5 — Analyse the Alert Log

After capturing traffic, open `alerts.csv`:

```
timestamp,           type,              severity, source_ip,      detail
2025-03-01 14:22:01, SYN FLOOD,         HIGH,     192.168.1.100,  20 SYN packets in 5s
2025-03-01 14:22:05, PORT SCAN,         HIGH,     10.0.0.55,      18 unique ports probed
2025-03-01 14:22:11, UNAUTHORIZED DNS,  MEDIUM,   192.168.1.50,   query to 185.220.101.5
```

You can import this into **Splunk** or **Wazuh** for dashboard visualisation,
which is exactly what the project bullet point on your resume refers to.

---

## Tuning the Thresholds

Edit the top of `detector.py` to adjust sensitivity:

```python
SYN_THRESHOLD       = 20    # Raise to reduce false positives in busy networks
PORT_SCAN_THRESHOLD = 15    # Lower for stricter detection
ICMP_THRESHOLD      = 30
```

---

## Extending the Project (Resume Bonus Points)

- Add **email alerts** using Python's `smtplib`
- Export alerts to **Splunk** via the HTTP Event Collector (HEC) API
- Add **GeoIP lookups** using `geoip2` to map attacker IPs to countries
- Build a **Flask dashboard** to view alerts in a browser in real time

---

## Requirements

```
scapy>=2.5.0
```

Install with:
```bash
pip install -r requirements.txt
```
