#!/usr/bin/env python3
"""
Role: BLUE TEAM
Purpose:
  Parse SSH authentication logs from /var/log/auth.log,
  extract key security fields, enrich with basic geo-IP information,
  compute a simple danger_score, and export results to CSV for SIEM/Splunk.

Notes:
  - This script is designed for lab/demo use.
  - Geo lookups use the free ip-api.com HTTP API (no key required).
  - In an offline lab, geo fields will simply remain empty.
"""

import argparse
import csv
import json
import os
import re
from datetime import datetime
from urllib import request, parse

FAILED_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for (invalid user\s+)?'
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
)

ACCEPTED_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted (password|publickey) for '
    r'(?P<user>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<src_port>\d+)'
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
    parser = argparse.ArgumentParser(
        description="Parse SSH auth logs to CSV with basic geo enrichment.",
    )
    parser.add_argument(
        "--logfile", default="/var/log/auth.log",
        help="Path to auth.log file (default: /var/log/auth.log)"
    )
    parser.add_argument(
        "--server-ip", required=False,
        help="Destination SSH server IP (this host's IP) - optional for parsing"
    )
    parser.add_argument(
        "--ssh-port", type=int, default=22,
        help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--output", default="ssh_events.csv",
        help="Output CSV file path"
    )
    parser.add_argument(
        "--year", type=int, default=datetime.now().year,
        help="Year to assume for log timestamps (default: current year)"
    )
    return parser.parse_args()


def parse_timestamp(month, day, time_str, year):
    dt = datetime(year, MONTHS.get(month, 1), int(day))
    h, m, s = [int(x) for x in time_str.split(":")]
    dt = dt.replace(hour=h, minute=m, second=s)
    return dt.isoformat()


def load_geo_cache(cache_path):
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_geo_cache(cache, cache_path):
    try:
        with open(cache_path, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def lookup_geo(ip, cache):
    if ip in cache:
        return cache[ip]

    geo = {'country': '', 'city': ''}
    try:
        url = GEO_API_URL + parse.quote(ip)
        with request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                geo['country'] = data.get('country', '') or ''
                geo['city'] = data.get('city', '') or ''
    except Exception:
        # In lab/offline environments, we simply leave geo fields empty
        pass

    cache[ip] = geo
    return geo


def compute_danger_score(event_type, status, username, fail_count):
    score = 0
    if status == 'fail':
        score += 30
    if event_type in ('failed_login', 'invalid_user'):
        score += 20
    if fail_count >= 5:
        score += 30
    if username.lower() in {'root', 'admin', 'test', 'user', 'guest'}:
        score += 10
    return min(score, 100)


def main():
    args = parse_args()

    logfile = args.logfile
    ssh_port = args.ssh_port
    output = args.output
    year = args.year

    geo_cache_path = 'geo_cache.json'
    geo_cache = load_geo_cache(geo_cache_path)

    fail_counters = {}

    fieldnames = [
        'timestamp',
        'src_ip',
        'src_port',
        'dst_port',
        'username',
        'event_status',
        'event_type',
        'fail_count',
        'total_attempts',
        'src_country',
        'src_city',
        'danger_score',
    ]

    rows = []

    with open(logfile, 'r', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')

            m = FAILED_RE.match(line)
            if m:
                ts = parse_timestamp(m['month'], m['day'], m['time'], year)
                username = m['user']
                src_ip = m['src_ip']
                src_port = int(m['src_port'])
                key = (src_ip, username)
                fail_counters[key] = fail_counters.get(key, 0) + 1
                fail_count = fail_counters[key]
                total_attempts = fail_count

                geo = lookup_geo(src_ip, geo_cache)
                event_type = 'failed_login'
                status = 'fail'
                danger = compute_danger_score(event_type, status, username, fail_count)

                rows.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_port': ssh_port,
                    'username': username,
                    'event_status': status,
                    'event_type': event_type,
                    'fail_count': fail_count,
                    'total_attempts': total_attempts,
                    'src_country': geo.get('country', ''),
                    'src_city': geo.get('city', ''),
                    'danger_score': danger,
                })
                continue

            m = ACCEPTED_RE.match(line)
            if m:
                ts = parse_timestamp(m['month'], m['day'], m['time'], year)
                username = m['user']
                src_ip = m['src_ip']
                src_port = int(m['src_port'])
                key = (src_ip, username)
                total_attempts = fail_counters.get(key, 0) + 1
                geo = lookup_geo(src_ip, geo_cache)
                event_type = 'successful_login'
                status = 'success'
                danger = 0

                rows.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_port': ssh_port,
                    'username': username,
                    'event_status': status,
                    'event_type': event_type,
                    'fail_count': fail_counters.get(key, 0),
                    'total_attempts': total_attempts,
                    'src_country': geo.get('country', ''),
                    'src_city': geo.get('city', ''),
                    'danger_score': danger,
                })
                continue

            m = INVALID_USER_RE.match(line)
            if m:
                ts = parse_timestamp(m['month'], m['day'], m['time'], year)
                username = m['user']
                src_ip = m['src_ip']
                src_port = 0
                key = (src_ip, username)
                fail_counters[key] = fail_counters.get(key, 0) + 1
                fail_count = fail_counters[key]
                total_attempts = fail_count

                geo = lookup_geo(src_ip, geo_cache)
                event_type = 'invalid_user'
                status = 'fail'
                danger = compute_danger_score(event_type, status, username, fail_count)

                rows.append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_port': ssh_port,
                    'username': username,
                    'event_status': status,
                    'event_type': event_type,
                    'fail_count': fail_count,
                    'total_attempts': total_attempts,
                    'src_country': geo.get('country', ''),
                    'src_city': geo.get('city', ''),
                    'danger_score': danger,
                })
                continue

    with open(output, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    save_geo_cache(geo_cache, geo_cache_path)


if __name__ == '__main__':
    main()
