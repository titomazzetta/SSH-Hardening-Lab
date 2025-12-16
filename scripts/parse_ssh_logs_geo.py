#!/usr/bin/env python3
"""
Role: BLUE TEAM

Purpose:
  Parse SSH authentication logs and export structured CSV telemetry
  for SIEM / Splunk ingestion.

Features:
  - Supports --logfile and --output (no hardcoded paths)
  - Designed to be run with sudo ONLY for log access
  - Writes output exactly where the wrapper specifies
  - No side effects (no symlinks, no directories created)
"""

import argparse
import re
import csv
import os
from datetime import datetime

# ---------------- REGEX PATTERNS ---------------- #

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)",
    re.IGNORECASE
)

FAILED_PUBLICKEY_RE = re.compile(
    r"Failed publickey for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

PAM_AUTH_FAILURE_RE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*user=(?P<user>\S+)",
    re.IGNORECASE
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)

TIMESTAMP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:\.\-+]+)"
)

SSH_PORT = 22

# ---------------- UTILS ---------------- #

def danger_score(fails: int) -> int:
    if fails >= 10:
        return 90
    if fails >= 6:
        return 70
    if fails >= 3:
        return 50
    return 10

# ---------------- MAIN ---------------- #

def main():
    parser = argparse.ArgumentParser(description="Parse SSH auth logs to CSV")
    parser.add_argument(
        "--logfile",
        default="/var/log/auth.log",
        help="Path to SSH auth log (default: /var/log/auth.log)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Full path to output CSV file"
    )

    args = parser.parse_args()

    logfile = args.logfile
    output_csv = args.output

    if not os.path.exists(logfile):
        raise FileNotFoundError(logfile)

    fail_counts = {}
    total_attempts = {}
    rows = []

    with open(logfile, "r", errors="ignore") as f:
        for line in f:
            ts_match = TIMESTAMP_RE.search(line)
            timestamp = ts_match.group("ts") if ts_match else ""

            src_ip = None
            src_port = 0
            user = ""
            event_type = ""
            status = ""

            if (m := FAILED_PASSWORD_RE.search(line)):
                event_type = "failed_password"
                status = "failed"
                user = m["user"]
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])

            elif (m := FAILED_PUBLICKEY_RE.search(line)):
                event_type = "failed_publickey"
                status = "failed"
                user = m["user"]
                src_ip = m["src_ip"]

            elif (m := PAM_AUTH_FAILURE_RE.search(line)):
                event_type = "pam_auth_failure"
                status = "failed"
                user = m["user"]
                src_ip = m["src_ip"]

            elif (m := ACCEPTED_PASSWORD_RE.search(line)):
                event_type = "accepted_password"
                status = "success"
                user = m["user"]
                src_ip = m["src_ip"]

            else:
                continue

            total_attempts[src_ip] = total_attempts.get(src_ip, 0) + 1
            if status == "failed":
                fail_counts[src_ip] = fail_counts.get(src_ip, 0) + 1

            rows.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": SSH_PORT,
                "username": user,
                "event_status": status,
                "event_type": event_type,
                "fail_count": fail_counts.get(src_ip, 0),
                "total_attempts": total_attempts.get(src_ip, 0),
                "src_country": "",
                "src_city": "",
                "danger_score": danger_score(fail_counts.get(src_ip, 0))
            })

    if not rows:
        print("[!] No SSH events matched. CSV not written.")
        return

    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("[+] Parsing complete")
    print(f"    CSV:  {output_csv}")
    print(f"    Rows: {len(rows)}")

if __name__ == "__main__":
    main()
