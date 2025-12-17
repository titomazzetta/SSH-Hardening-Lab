#!/usr/bin/env bash
#
# Role: RED TEAM
# Purpose:
#   Run common Nmap SSH scans against a target to validate hardening posture.
#
# Usage:
#   ./scripts/scan_ssh.sh <TARGET_IP> [SSH_PORT]
#

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <TARGET_IP> [SSH_PORT]"
  exit 1
fi

TARGET="$1"
PORT="${2:-22}"

echo "[*] Basic SSH version scan on ${TARGET}:${PORT}..."
nmap -sV -p "${PORT}" "${TARGET}"

echo
echo "[*] SSH safe scripts (-sC) + version detection on ${TARGET}:${PORT}..."
nmap -sC -sV -p "${PORT}" "${TARGET}"

echo
echo "[*] SSH algorithm enumeration (crypto validation) on ${TARGET}:${PORT}..."
nmap --script ssh2-enum-algos -p "${PORT}" "${TARGET}"

echo
echo "[*] SSH auth methods probe (best-effort) on ${TARGET}:${PORT}..."
nmap --script ssh-auth-methods --script-args="ssh.user=secadmin" -p "${PORT}" "${TARGET}" || true

echo
echo "[*] TCP connect scan (top 1000 ports) on ${TARGET}..."
nmap -sT "${TARGET}"

echo
echo "[+] Nmap scanning complete."
