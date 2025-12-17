#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Parse SSH authentication logs into SIEM-ready CSV + SHA256 integrity file.
#
# Output model (best practice):
#   1) Authoritative store (server-side, not in repo):
#        ~/ssh_reports/
#      - timestamped CSV + .sha256
#      - maintains ssh_events_latest.csv symlinks
#
#   2) UX / demo copies (repo-tracked):
#        ./screenshots/ssh_reports/
#      - copies of the newest CSV + .sha256
#      - also writes ssh_events_latest.csv (+ .sha256) as real files (no symlinks)
#
# Usage (run on the hardened server):
#   cd ~/SSH-Hardening-Lab
#   ./scripts/run_ssh_parser.sh
#
# Optional overrides:
#   LOGFILE=/var/log/auth.log ./scripts/run_ssh_parser.sh
#   REPORT_DIR=/some/path     ./scripts/run_ssh_parser.sh   # authoritative store override
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PARSER="${SCRIPT_DIR}/parse_ssh_logs_geo.py"

if [[ ! -f "${PARSER}" ]]; then
  echo "[!] Parser not found: ${PARSER}"
  exit 1
fi

# --- directories ---
DEFAULT_AUTHORITATIVE_DIR="${HOME}/ssh_reports"
AUTHORITATIVE_DIR="${REPORT_DIR:-${DEFAULT_AUTHORITATIVE_DIR}}"
mkdir -p "${AUTHORITATIVE_DIR}"

UX_DIR="${PROJECT_ROOT}/screenshots/ssh_reports"
mkdir -p "${UX_DIR}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_CSV="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv.sha256"

# --- logfile detection / override ---
if [[ -n "${LOGFILE:-}" ]]; then
  DETECTED_LOGFILE="${LOGFILE}"
elif [[ -f /var/log/auth.log ]]; then
  DETECTED_LOGFILE="/var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
  DETECTED_LOGFILE="/var/log/secure"
else
  echo "[!] Could not find auth log at /var/log/auth.log or /var/log/secure."
  echo "[!] Set manually, e.g.: LOGFILE=/path/to/log ./scripts/run_ssh_parser.sh"
  exit 1
fi

echo "[*] Running SSH log parser..."
echo "    Parser:      ${PARSER}"
echo "    Logfile:     ${DETECTED_LOGFILE}"
echo "    Authoritative output: ${OUT_CSV}"
echo "    UX copies:   ${UX_DIR}"

# Prefer non-interactive sudo if available
SUDO=(sudo -n)
if ! sudo -n true 2>/dev/null; then
  echo "[!] Non-interactive sudo not configured (NOPASSWD not set)."
  echo "[*] Falling back to interactive sudo (you may be prompted)..."
  SUDO=(sudo)
fi

# Run parser with sudo (needed to read auth logs), write output to user-owned path
"${SUDO[@]}" python3 "${PARSER}" --output "${OUT_CSV}" --logfile "${DETECTED_LOGFILE}"

if [[ ! -f "${OUT_CSV}" ]]; then
  echo "[!] Expected CSV not found: ${OUT_CSV}"
  exit 1
fi

echo "[*] Computing SHA-256 hash (portable verification on Mac/Linux)..."
(
  cd "${AUTHORITATIVE_DIR}"
  # IMPORTANT: write hash with basename only so `shasum -a 256 -c` works after SCP
  sha256sum "$(basename "${OUT_CSV}")" > "$(basename "${OUT_HASH}")"
)

# Maintain "latest" symlinks in the authoritative directory
ln -sf "$(basename "${OUT_CSV}")"  "${AUTHORITATIVE_DIR}/ssh_events_latest.csv"
ln -sf "$(basename "${OUT_HASH}")" "${AUTHORITATIVE_DIR}/ssh_events_latest.csv.sha256"

# Copy newest artifacts into repo screenshots/ for UX / demos (real files, no symlinks)
cp -f "${OUT_CSV}" "${UX_DIR}/"
cp -f "${OUT_HASH}" "${UX_DIR}/"
cp -f "${OUT_CSV}" "${UX_DIR}/ssh_events_latest.csv"
cp -f "${OUT_HASH}" "${UX_DIR}/ssh_events_latest.csv.sha256"

echo "[+] Done."
echo "    Authoritative CSV: ${OUT_CSV}"
echo "    Authoritative Hash: ${OUT_HASH}"
echo "    UX CSV:            ${UX_DIR}/ssh_events_latest.csv"
echo "    UX Hash:           ${UX_DIR}/ssh_events_latest.csv.sha256"
echo
echo "[*] Verification tip (Mac Studio):"
echo "    cd ${UX_DIR} && shasum -a 256 -c ssh_events_latest.csv.sha256"
