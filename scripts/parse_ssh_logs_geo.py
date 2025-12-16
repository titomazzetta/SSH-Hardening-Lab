#!/usr/bin/env python3
"""
Role: BLUE TEAM
Purpose:
  Parse SSH authentication logs from /var/log/auth.log,
  extract key security fields, compute a danger score,
  and export results to CSV for SIEM/Splunk ingestion.
"""

import re
import csv
import os
import hashlib
from datetime import datetime

LOGFILE = "/var/log/auth.log"
OUTPUT_DIR = "/root/ssh_reports"
SSH_PORT = 22

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

# ---------------- UTILS ---------------- #

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def danger_score(fails):
    if fails >= 10:
        return 90
    if fails >= 6:
        return 70
    if fails >= 3:
        return 50
    return 10

# ---------------- MAIN ---------------- #

def main():
    if not os.path.exists(LOGFILE):
        raise FileNotFoundError(LOGFILE)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"{OUTPUT_DIR}/ssh_events_{now}.csv"
    latest_path = f"{OUTPUT_DIR}/ssh_events_latest.csv"

    fail_counts = {}
    total_attempts = {}
    rows = []

    with open(LOGFILE, "r", errors="ignore") as f:
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

    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    sha = compute_sha256(csv_path)
    with open(csv_path + ".sha256", "w") as f:
        f.write(sha)

    if os.path.islink(latest_path):
        os.unlink(latest_path)
    os.symlink(os.path.basename(csv_path), latest_path)

    print("[+] Parsing complete")
    print(f"    CSV:  {csv_path}")
    print(f"    Rows: {len(rows)}")

if __name__ == "__main__":
    main()
