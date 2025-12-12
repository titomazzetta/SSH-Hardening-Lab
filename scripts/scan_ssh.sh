#!/usr/bin/env bash
#
# Role: RED TEAM
# Purpose:
#   Run common Nmap SSH scans against a target to validate hardening.
#
# Usage:
#   ./scripts/scan_ssh.sh <TARGET_IP>
#

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <TARGET_IP>"
  exit 1
fi

TARGET="$1"

echo "[*] Basic SSH version scan on ${TARGET}..."
nmap -sV -p 22 "${TARGET}"

echo
echo "[*] Aggressive SSH script scan on ${TARGET} (safe scripts)..."
nmap -sC -sV -p 22 "${TARGET}"

echo
echo "[*] Full TCP connect scan of common ports (top 1000) on ${TARGET}..."
nmap -sT "${TARGET}"

echo
echo "[+] Nmap scanning complete. Review results to confirm SSH exposure and banners."
