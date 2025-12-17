#!/usr/bin/env python3
"""
Role: BLUE TEAM
Purpose:
  Parse SSH authentication logs (e.g., /var/log/auth.log) into SIEM-ready CSV.
  The parser extracts authentication events, normalizes fields, applies lightweight
  geo-IP enrichment, and computes a simple per-IP risk score (danger_score).

Design goals:
  - Lab-friendly and resilient to minor log format differences
  - Works with password-only, key-only, and key+TOTP MFA SSH profiles
  - Produces consistent event_type values for Splunk queries/dashboards

Geo enrichment:
  - Uses ip-api.com (free, no key). In offline labs geo fields remain blank.
  - Caches lookups to avoid repeated API calls.

Output:
  CSV fields (stable schema):
    timestamp, src_ip, src_port, dst_port, username,
    event_status, event_type, fail_count, total_attempts,
    src_country, src_city, danger_score
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime
from urllib import request, parse

# --- Regex patterns (Debian/OpenSSH typical) ---

FAILED_PASSWORD_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user\s+)?'
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

FAILED_PUBLICKEY_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed publickey for (invalid user\s+)?'
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

ACCEPTED_PASSWORD_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted password for '
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

ACCEPTED_PUBLICKEY_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted publickey for '
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

# MFA success commonly logs as "Accepted keyboard-interactive/pam"
ACCEPTED_MFA_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted keyboard-interactive/pam for '
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

# PAM auth failures (covers google-authenticator failures + general PAM failures)
PAM_FAILURE_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+pam\S*\(sshd:auth\):\s+authentication failure;.*\brhost=(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?:\s+.*\buser=(?P<user>\S+))?'
)

INVALID_USER_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from '
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)'
)

MONTHS = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4,
    'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
    'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

GEO_API_URL = "http://ip-api.com/json/"


def parse_args():
    p = argparse.ArgumentParser(description="Parse SSH auth logs to CSV with optional geo enrichment.")
    p.add_argument("--logfile", default="/var/log/auth.log", help="Path to auth log file (default: /var/log/auth.log)")
    p.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--output", default="ssh_events.csv", help="Output CSV file path")
    p.add_argument("--year", type=int, default=datetime.now().year, help="Year to assume for syslog timestamps")
    p.add_argument("--geo-cache", default="", help="Path for geo cache JSON (default: alongside script)")
    p.add_argument("--disable-geo", action="store_true", help="Disable geo lookups (offline / privacy)")
    return p.parse_args()


def parse_timestamp(month: str, day: str, time_str: str, year: int) -> str:
    tz = datetime.now().astimezone().tzinfo
    dt = datetime(year, MONTHS.get(month, 1), int(day), tzinfo=tz)
    h, m, s = (int(x) for x in time_str.split(":"))
    dt = dt.replace(hour=h, minute=m, second=s)
    return dt.isoformat()


def load_geo_cache(cache_path: str) -> dict:
    if not cache_path:
        return {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_geo_cache(cache: dict, cache_path: str) -> None:
    if not cache_path:
        return
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
    except Exception:
        pass


def lookup_geo(ip: str, cache: dict, disable_geo: bool) -> dict:
    if disable_geo:
        return {"country": "", "city": ""}

    if ip in cache:
        return cache[ip]

    geo = {"country": "", "city": ""}
    try:
        url = GEO_API_URL + parse.quote(ip)
        with request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                geo["country"] = data.get("country", "") or ""
                geo["city"] = data.get("city", "") or ""
    except Exception:
        pass

    cache[ip] = geo
    return geo


def danger_score(fail_count: int) -> int:
    # Intentionally simple (lab-friendly):
    # increases with failures; caps at 100; remains visible even after a success.
    return max(0, min(20 + (2 * fail_count), 100))


def emit_row(rows: list, *, ts: str, src_ip: str, src_port: int, dst_port: int, username: str,
             status: str, event_type: str, ip_fail: int, ip_total: int, geo: dict) -> None:
    rows.append({
        "timestamp": ts,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "username": username,
        "event_status": status,
        "event_type": event_type,
        "fail_count": ip_fail,
        "total_attempts": ip_total,
        "src_country": geo.get("country", ""),
        "src_city": geo.get("city", ""),
        "danger_score": danger_score(ip_fail),
    })


def main():
    args = parse_args()

    logfile = args.logfile
    dst_port = args.ssh_port
    output = args.output
    year = args.year

    script_dir = os.path.dirname(os.path.abspath(__file__))
    geo_cache_path = args.geo_cache or os.path.join(script_dir, "geo_cache.json")
    geo_cache = load_geo_cache(geo_cache_path)

    ip_fail = {}   # src_ip -> failed attempts count
    ip_total = {}  # src_ip -> total auth events (fail + success)

    fieldnames = [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_port",
        "username",
        "event_status",
        "event_type",
        "fail_count",
        "total_attempts",
        "src_country",
        "src_city",
        "danger_score",
    ]

    rows = []

    with open(logfile, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")

            # Failed public key
            m = FAILED_PUBLICKEY_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])
                user = m["user"]

                ip_fail[src_ip] = ip_fail.get(src_ip, 0) + 1
                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="failed", event_type="failed_publickey",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # Failed password
            m = FAILED_PASSWORD_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])
                user = m["user"]

                ip_fail[src_ip] = ip_fail.get(src_ip, 0) + 1
                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="failed", event_type="failed_password",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # PAM authentication failures (often MFA failures)
            m = PAM_FAILURE_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                user = (m.group("user") or "").strip() or "unknown"
                src_port = 0

                ip_fail[src_ip] = ip_fail.get(src_ip, 0) + 1
                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="failed", event_type="pam_auth_failure",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # Invalid user enumeration
            m = INVALID_USER_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                user = m["user"]
                src_port = 0

                ip_fail[src_ip] = ip_fail.get(src_ip, 0) + 1
                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="failed", event_type="invalid_user",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # Accepted MFA (final success in key+TOTP flows)
            m = ACCEPTED_MFA_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])
                user = m["user"]

                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1
                ip_fail.setdefault(src_ip, 0)

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="success", event_type="accepted_mfa",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # Accepted password
            m = ACCEPTED_PASSWORD_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])
                user = m["user"]

                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1
                ip_fail.setdefault(src_ip, 0)

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="success", event_type="accepted_password",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

            # Accepted public key (key-only or step 1 of key+MFA)
            m = ACCEPTED_PUBLICKEY_RE.match(line)
            if m:
                ts = parse_timestamp(m["month"], m["day"], m["time"], year)
                src_ip = m["src_ip"]
                src_port = int(m["src_port"])
                user = m["user"]

                ip_total[src_ip] = ip_total.get(src_ip, 0) + 1
                ip_fail.setdefault(src_ip, 0)

                geo = lookup_geo(src_ip, geo_cache, args.disable_geo)
                emit_row(rows, ts=ts, src_ip=src_ip, src_port=src_port, dst_port=dst_port,
                         username=user, status="success", event_type="accepted_publickey",
                         ip_fail=ip_fail[src_ip], ip_total=ip_total[src_ip], geo=geo)
                continue

    os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)
    with open(output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    save_geo_cache(geo_cache, geo_cache_path)


if __name__ == "__main__":
    main()
