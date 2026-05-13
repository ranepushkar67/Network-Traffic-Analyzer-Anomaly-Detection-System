"""
detector.py — Anomaly Detection Rules
Each function tracks state internally and returns an alert dict
when a threshold is breached, or None if traffic is normal.
"""

from collections import defaultdict
import time

# ─── THRESHOLDS (tune these for your lab) ────────────────────
SYN_THRESHOLD       = 20    # SYN packets from one IP within window
SYN_WINDOW          = 5     # seconds

PORT_SCAN_THRESHOLD = 15    # unique destination ports from one IP
PORT_SCAN_WINDOW    = 10    # seconds

ICMP_THRESHOLD      = 30    # ICMP packets from one IP
ICMP_WINDOW         = 5     # seconds

# Legitimate DNS servers (whitelist)
ALLOWED_DNS = {
    "8.8.8.8",          # Google
    "8.8.4.4",          # Google secondary
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare secondary
    "9.9.9.9",          # Quad9
    "208.67.222.222",   # OpenDNS
}

# Suspicious domain keywords
SUSPICIOUS_KEYWORDS = [
    ".ru", ".cn", ".tk", ".xyz", ".top",
    "malware", "phish", "bot", "c2", "rat",
    "update-flash", "secure-login", "verify-account",
]
# ─────────────────────────────────────────────────────────────

# Internal state stores
_syn_tracker    = defaultdict(list)   # src_ip -> [timestamps]
_scan_tracker   = defaultdict(dict)   # src_ip -> {port: timestamp}
_icmp_tracker   = defaultdict(list)   # src_ip -> [timestamps]
_alerted        = defaultdict(dict)   # cooldown store to avoid alert spam


def _within_window(timestamps, window):
    """Returns timestamps that fall within the last `window` seconds."""
    now = time.time()
    return [t for t in timestamps if now - t < window]


def _on_cooldown(category, key, cooldown=30):
    """Returns True if an alert for this (category, key) was sent recently."""
    last = _alerted[category].get(key, 0)
    if time.time() - last < cooldown:
        return True
    _alerted[category][key] = time.time()
    return False


# ──────────────────────────────────────────────────────────────
#  RULE 1 — SYN Flood Detection
# ──────────────────────────────────────────────────────────────
def check_syn_flood(src_ip, timestamp):
    """
    Fires when a single source sends too many TCP SYN packets
    in a short window — classic SYN flood / DDoS signature.
    """
    _syn_tracker[src_ip].append(time.time())
    _syn_tracker[src_ip] = _within_window(_syn_tracker[src_ip], SYN_WINDOW)

    count = len(_syn_tracker[src_ip])
    if count >= SYN_THRESHOLD and not _on_cooldown("syn", src_ip):
        return {
            "timestamp" : timestamp,
            "type"      : "SYN FLOOD",
            "severity"  : "HIGH",
            "source_ip" : src_ip,
            "detail"    : f"{count} SYN packets in {SYN_WINDOW}s — possible DoS attack",
        }
    return None


# ──────────────────────────────────────────────────────────────
#  RULE 2 — Port Scan Detection
# ──────────────────────────────────────────────────────────────
def check_port_scan(src_ip, dport, timestamp):
    """
    Fires when a single source probes too many distinct destination
    ports — typical behaviour of Nmap or automated scanners.
    """
    now = time.time()
    # Record this port with current time
    _scan_tracker[src_ip][dport] = now

    # Prune stale entries outside the window
    _scan_tracker[src_ip] = {
        p: t for p, t in _scan_tracker[src_ip].items()
        if now - t < PORT_SCAN_WINDOW
    }

    unique_ports = len(_scan_tracker[src_ip])
    if unique_ports >= PORT_SCAN_THRESHOLD and not _on_cooldown("scan", src_ip):
        return {
            "timestamp" : timestamp,
            "type"      : "PORT SCAN",
            "severity"  : "HIGH",
            "source_ip" : src_ip,
            "detail"    : f"{unique_ports} unique ports probed in {PORT_SCAN_WINDOW}s",
        }
    return None


# ──────────────────────────────────────────────────────────────
#  RULE 3 — DNS Anomaly Detection
# ──────────────────────────────────────────────────────────────
def check_dns_anomaly(src_ip, dns_server, query, timestamp):
    """
    Fires on:
      a) Queries sent to a non-whitelisted DNS server (DNS hijack / rogue resolver)
      b) Domains containing suspicious keywords (malware C2, phishing, DGA-like TLDs)
    """
    # (a) Unauthorized DNS server
    if dns_server not in ALLOWED_DNS and not _on_cooldown("dns_server", f"{src_ip}-{dns_server}"):
        return {
            "timestamp" : timestamp,
            "type"      : "UNAUTHORIZED DNS",
            "severity"  : "MEDIUM",
            "source_ip" : src_ip,
            "detail"    : f"Query to non-whitelisted DNS server {dns_server} | domain: {query}",
        }

    # (b) Suspicious domain keyword
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in query.lower():
            key = f"{src_ip}-{query}"
            if not _on_cooldown("dns_domain", key):
                return {
                    "timestamp" : timestamp,
                    "type"      : "SUSPICIOUS DOMAIN",
                    "severity"  : "MEDIUM",
                    "source_ip" : src_ip,
                    "detail"    : f"Query matches suspicious pattern '{keyword}': {query}",
                }
    return None


# ──────────────────────────────────────────────────────────────
#  RULE 4 — ICMP Flood Detection
# ──────────────────────────────────────────────────────────────
def check_icmp_flood(src_ip, timestamp):
    """
    Fires when a single source sends an excessive number of ICMP
    (ping) packets — common in ping-flood / Smurf attacks.
    """
    _icmp_tracker[src_ip].append(time.time())
    _icmp_tracker[src_ip] = _within_window(_icmp_tracker[src_ip], ICMP_WINDOW)

    count = len(_icmp_tracker[src_ip])
    if count >= ICMP_THRESHOLD and not _on_cooldown("icmp", src_ip):
        return {
            "timestamp" : timestamp,
            "type"      : "ICMP FLOOD",
            "severity"  : "MEDIUM",
            "source_ip" : src_ip,
            "detail"    : f"{count} ICMP packets in {ICMP_WINDOW}s — possible ping flood",
        }
    return None
