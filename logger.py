"""
logger.py — Alert Logging
Writes alerts to alerts.csv and prints colour-coded output to terminal.
"""

import csv
import os
from datetime import datetime

ALERT_FILE = "alerts.csv"
COLUMNS    = ["timestamp", "type", "severity", "source_ip", "detail"]

# ANSI colour codes for terminal output
COLOURS = {
    "HIGH"   : "\033[91m",   # Red
    "MEDIUM" : "\033[93m",   # Yellow
    "LOW"    : "\033[94m",   # Blue
    "RESET"  : "\033[0m",
}


def init():
    """Create the CSV file with headers (overwrite on each run)."""
    with open(ALERT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
    print(f"[*] Alert log initialised → {os.path.abspath(ALERT_FILE)}\n")


def log_alert(alert: dict):
    """
    1. Append alert to CSV
    2. Print colour-coded banner to console
    """
    # — Write to CSV —
    with open(ALERT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writerow({col: alert.get(col, "") for col in COLUMNS})

    # — Console output —
    sev    = alert.get("severity", "LOW")
    colour = COLOURS.get(sev, "")
    reset  = COLOURS["RESET"]

    print(
        f"{colour}"
        f"[ALERT] [{sev}] {alert['timestamp']}\n"
        f"        Type      : {alert['type']}\n"
        f"        Source IP : {alert['source_ip']}\n"
        f"        Detail    : {alert['detail']}"
        f"{reset}"
    )
