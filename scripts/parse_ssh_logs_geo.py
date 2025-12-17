#!/usr/bin/env python3
"""
Role: BLUE TEAM
Purpose:
  Parse SSH authentication logs (e.g., /var/log/auth.log) into SIEM-ready CSV.
  Extracts authentication events, normalizes fields, performs lightweight geo-IP
  enrichment, and computes a simple per-IP risk score (danger_score).

Works with:
  - Password-only SSH
  - Public-key SSH
  - Public-key + TOTP MFA (keyboard-interactive/pam + pam_google_authenticator)
  - Debian/OpenSSH with RFC3339 timestamps (2025-12-17T...) and syslog timestamps (Dec 17 ...)

Geo enrichment:
  - Uses ip-api.com (free, no key). If offline/unreachable, geo fields remain blank.
  - Caches lookups in a JSON file to avoid repeated calls.

Output CSV schema (stable):
  timestamp, src_ip, src_port, dst_port, username,
  event_status, event_type, fail_count, total_attempts,
  src_country, src_city, danger_score
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import sys
from datetime import datetime
from urllib import request


# ----------------------------
# Timestamp + prefix handling
# ----------------------------

# Matches BOTH formats:
#   Dec 17 14:54:16 host sshd[123]: ...
#   2025-12-17T16:09:37.699297-05:00 host sshd-session[123]: ...
PREFIX = (
    r'^(?:'
    r'(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})'
    r'|'
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r')\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<proc>sshd(?:-session)?)\[(?P<pid>\d+)\]:\s+'
)

IPV4 = r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)'
PORT = r'(?P<src_port>\d+)'
DSTPORT = r'(?P<dst_port>\d+)'


def extract_timestamp(m: re.Match) -> str:
    """Return ISO-like timestamp string for the event."""
    gd = m.groupdict()
    if gd.get("iso"):
        return gd["iso"]
    # Classic syslog has no year; assume current year for lab purposes.
    year = datetime.now().year
    ts_str = f"{gd['month']} {gd['day']} {gd['time']} {year}"
    try:
        return datetime.strptime(ts_str, "%b %d %H:%M:%S %Y").isoformat()
    except Exception:
        # Best-effort fallback
        return ts_str


# ----------------------------
# Regex patterns (SSH events)
# ----------------------------

# Public key signals
ACCEPTED_KEY_RE = re.compile(
    PREFIX + r'Accepted key \S+ \S+ found at .+ for (?P<username>\S+)'
)
POSTPONED_PUBKEY_RE = re.compile(
    PREFIX + rf'Postponed publickey for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)
PARTIAL_PUBKEY_RE = re.compile(
    PREFIX + rf'Partial publickey for (?P<username>\S+) from {IPV4} port {PORT} ssh2:'
)

# Keyboard-interactive / PAM (MFA step typically)
POSTPONED_KI_RE = re.compile(
    PREFIX + rf'Postponed keyboard-interactive for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)
POSTPONED_KI_PAM_RE = re.compile(
    PREFIX + rf'Postponed keyboard-interactive/pam for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)
FAILED_KI_PAM_RE = re.compile(
    PREFIX + rf'Failed keyboard-interactive/pam for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)
ACCEPTED_KI_PAM_RE = re.compile(
    PREFIX + rf'Accepted keyboard-interactive/pam for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)

# PAM google authenticator module logs (no src_ip on the module line)
PAM_GOOGLE_ACCEPTED_RE = re.compile(
    PREFIX + r'sshd\(pam_google_authenticator\)\[\d+\]: Accepted google_authenticator for (?P<username>\S+)'
)
PAM_GOOGLE_INVALID_RE = re.compile(
    PREFIX + r'sshd\(pam_google_authenticator\)\[\d+\]: Invalid verification code for (?P<username>\S+)'
)

# Generic PAM auth failure (has src_ip)
PAM_AUTH_FAILURE_RE = re.compile(
    PREFIX + rf'error: PAM: Authentication failure for (?P<username>\S+) from {IPV4}'
)

# Password failures (some distros still log these even when PasswordAuthentication=no via PAM paths)
FAILED_PASSWORD_RE = re.compile(
    PREFIX + rf'Failed password for (invalid user\s+)?(?P<username>\S+) from {IPV4} port {PORT} ssh2'
)

# Generic “Accepted password” (not expected in your hardened profile, but supported)
ACCEPTED_PASSWORD_RE = re.compile(
    PREFIX + rf'Accepted password for (?P<username>\S+) from {IPV4} port {PORT} ssh2'
)

# Connection line includes dst_port
CONNECTION_RE = re.compile(
    PREFIX + rf'Connection from {IPV4} port {PORT} on \S+ port {DSTPORT}'
)

# kex reset/identification (often shows once banned or rate-limited; no username)
KEX_RESET_RE = re.compile(
    PREFIX + r'kex_exchange_identification:'
)

# Timeout before authentication (has src_ip but not always username)
TIMEOUT_RE = re.compile(
    PREFIX + rf'Timeout before authentication for connection from {IPV4} to \S+, pid = \d+'
)


# ----------------------------
# Geo enrichment (ip-api.com)
# ----------------------------

def load_geo_cache(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_geo_cache(path: str, cache: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def looks_private_ip(ip: str) -> bool:
    # Basic RFC1918 + localhost
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.") and (16 <= int(ip.split(".")[1]) <= 31)
        or ip.startswith("127.")
    )


def geo_lookup_ip(ip: str, cache: dict, timeout: float = 2.5) -> tuple[str, str]:
    """
    Returns (country, city). Uses cache first.
    For private IPs, returns blank fields.
    """
    if not ip or looks_private_ip(ip):
        return ("", "")

    if ip in cache:
        entry = cache[ip]
        return (entry.get("country", ""), entry.get("city", ""))

    url = f"http://ip-api.com/json/{ip}?fields=status,country,city,message"
    try:
        with request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if data.get("status") == "success":
            cache[ip] = {"country": data.get("country", ""), "city": data.get("city", "")}
            return (cache[ip]["country"], cache[ip]["city"])
        else:
            # cache negative result to avoid repeated calls
            cache[ip] = {"country": "", "city": ""}
            return ("", "")
    except Exception:
        # offline / blocked / DNS fail
        cache[ip] = {"country": "", "city": ""}
        return ("", "")


# ----------------------------
# Risk scoring
# ----------------------------

def compute_danger_score(event_type: str, event_status: str, fail_count: int, total_attempts: int) -> int:
    """
    Simple lab-friendly heuristic.
    """
    score = 0

    # Base by status/type
    if event_status == "fail":
        score += 20
    if event_type in ("password", "pam", "mfa_totp"):
        score += 10
    if event_type in ("kex", "timeout"):
        score += 5
    if event_type in ("publickey",):
        score += 3

    # Escalate with volume
    score += min(30, fail_count * 3)
    score += min(20, max(0, total_attempts - 5))

    return min(100, score)


# ----------------------------
# Parsing core
# ----------------------------

def parse_events(log_path: str) -> list[dict]:
    """
    Parses log file and returns normalized events.
    Also keeps per-IP counters for fail_count / total_attempts.
    """
    events: list[dict] = []

    # Track last-seen src_ip per sshd session pid (so PAM google lines can inherit it)
    pid_to_last_src: dict[str, str] = {}

    # Track per-IP counters
    ip_fail_count: dict[str, int] = {}
    ip_total_count: dict[str, int] = {}

    def bump(ip: str, status: str) -> tuple[int, int]:
        if not ip:
            return (0, 0)
        ip_total_count[ip] = ip_total_count.get(ip, 0) + 1
        if status == "fail":
            ip_fail_count[ip] = ip_fail_count.get(ip, 0) + 1
        return (ip_fail_count.get(ip, 0), ip_total_count.get(ip, 0))

    def add_event(ts: str, src_ip: str, src_port: str, dst_port: str, username: str,
                  status: str, e_type: str, pid: str) -> None:
        if pid and src_ip:
            pid_to_last_src[pid] = src_ip

        fail_count, total_attempts = bump(src_ip, status)

        events.append({
            "timestamp": ts,
            "src_ip": src_ip or "",
            "src_port": src_port or "",
            "dst_port": dst_port or "",
            "username": username or "",
            "event_status": status,
            "event_type": e_type,
            "fail_count": fail_count,
            "total_attempts": total_attempts,
        })

    # Best-effort read
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Connection line (captures dst_port)
            m = CONNECTION_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                pid = m.group("pid")
                add_event(ts, m.group("src_ip"), m.group("src_port"), m.group("dst_port"), "", "info", "connection", pid)
                continue

            # Accepted key (no src_ip in that line in your logs)
            m = ACCEPTED_KEY_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                pid = m.group("pid")
                src_ip = pid_to_last_src.get(pid, "")
                add_event(ts, src_ip, "", "", m.group("username"), "info", "publickey", pid)
                continue

            m = POSTPONED_PUBKEY_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "info", "publickey", m.group("pid"))
                continue

            m = PARTIAL_PUBKEY_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "info", "publickey", m.group("pid"))
                continue

            # Keyboard-interactive / PAM MFA step
            m = FAILED_KI_PAM_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "fail", "mfa", m.group("pid"))
                continue

            m = ACCEPTED_KI_PAM_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "success", "mfa", m.group("pid"))
                continue

            m = POSTPONED_KI_PAM_RE.search(line) or POSTPONED_KI_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "info", "mfa", m.group("pid"))
                continue

            # Google Authenticator module lines (inherit src_ip from pid)
            m = PAM_GOOGLE_INVALID_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                pid = m.group("pid")
                src_ip = pid_to_last_src.get(pid, "")
                add_event(ts, src_ip, "", "", m.group("username"), "fail", "mfa_totp", pid)
                continue

            m = PAM_GOOGLE_ACCEPTED_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                pid = m.group("pid")
                src_ip = pid_to_last_src.get(pid, "")
                add_event(ts, src_ip, "", "", m.group("username"), "success", "mfa_totp", pid)
                continue

            # PAM auth failure includes src_ip
            m = PAM_AUTH_FAILURE_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), "", "", m.group("username"), "fail", "pam", m.group("pid"))
                continue

            # Password accepted/failed (supported generically)
            m = FAILED_PASSWORD_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "fail", "password", m.group("pid"))
                continue

            m = ACCEPTED_PASSWORD_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), m.group("src_port"), "", m.group("username"), "success", "password", m.group("pid"))
                continue

            # Timeout and KEX reset signals
            m = TIMEOUT_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                add_event(ts, m.group("src_ip"), "", "", "", "fail", "timeout", m.group("pid"))
                continue

            m = KEX_RESET_RE.search(line)
            if m:
                ts = extract_timestamp(m)
                pid = m.group("pid")
                src_ip = pid_to_last_src.get(pid, "")
                add_event(ts, src_ip, "", "", "", "fail", "kex", pid)
                continue

    return events


def write_csv(events: list[dict], out_path: str, geo_cache_path: str) -> int:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    cache = load_geo_cache(geo_cache_path)

    fieldnames = [
        "timestamp", "src_ip", "src_port", "dst_port", "username",
        "event_status", "event_type", "fail_count", "total_attempts",
        "src_country", "src_city", "danger_score"
    ]

    rows_written = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()

        for ev in events:
            ip = ev.get("src_ip", "")
            country, city = geo_lookup_ip(ip, cache)

            fail_count = int(ev.get("fail_count", 0) or 0)
            total_attempts = int(ev.get("total_attempts", 0) or 0)

            danger = compute_danger_score(
                event_type=ev.get("event_type", ""),
                event_status=ev.get("event_status", ""),
                fail_count=fail_count,
                total_attempts=total_attempts
            )

            row = dict(ev)
            row["src_country"] = country
            row["src_city"] = city
            row["danger_score"] = danger

            w.writerow(row)
            rows_written += 1

    save_geo_cache(geo_cache_path, cache)
    return rows_written


def main() -> int:
    p = argparse.ArgumentParser(description="Parse SSH auth.log into SIEM-ready CSV with geo enrichment.")
    p.add_argument("--log", default="/var/log/auth.log", help="Path to auth.log")
    p.add_argument("--out", required=True, help="Output CSV path")
    p.add_argument("--geo-cache", default="scripts/geo_cache.json", help="Geo cache JSON path (relative or absolute)")
    args = p.parse_args()

    log_path = args.log
    out_path = args.out

    geo_cache_path = args.geo_cache
    if not os.path.isabs(geo_cache_path):
        # resolve relative to repo root if run from repo root
        geo_cache_path = os.path.abspath(geo_cache_path)

    if not os.path.exists(log_path):
        print(f"[!] Log file not found: {log_path}", file=sys.stderr)
        return 2

    events = parse_events(log_path)

    rows = write_csv(events, out_path, geo_cache_path)

    print(f"[+] Parsed {rows} events -> {out_path}")
    if rows == 0:
        print("[!] No events matched. Verify log format and patterns.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
