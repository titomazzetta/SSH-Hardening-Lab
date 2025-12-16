#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Run SSH log parsing as the non-root user (secadmin) and write reports to:
#     ~/ssh_reports/
#
#   Elevate ONLY the parser execution to read privileged auth logs.
#   Works in two modes:
#     1) Non-interactive sudo (best for automation) if NOPASSWD is configured
#     2) Interactive sudo fallback (prompts for password) if not configured
#
# Usage (as secadmin):
#   cd ~/SSH-Hardening-Lab
#   ./scripts/run_ssh_parser.sh
#
# Optional:
#   LOGFILE=/var/log/auth.log ./scripts/run_ssh_parser.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="${SCRIPT_DIR}/parse_ssh_logs_geo.py"

if [[ ! -f "${PARSER}" ]]; then
  echo "[!] Parser not found: ${PARSER}"
  exit 1
fi

# Reports live here (secadmin-owned)
REPORT_DIR="${HOME}/ssh_reports"
mkdir -p "${REPORT_DIR}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_CSV="${REPORT_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${OUT_CSV}.sha256"

# Logfile detection / override
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
echo "    Parser:  ${PARSER}"
echo "    Logfile: ${DETECTED_LOGFILE}"
echo "    Output:  ${OUT_CSV}"

# Choose sudo mode
SUDO=(sudo -n)
if ! sudo -n true 2>/dev/null; then
  echo "[!] Non-interactive sudo not configured (NOPASSWD not set)."
  echo "[*] Falling back to interactive sudo (you may be prompted for your password)..."
  SUDO=(sudo)
fi

# Run parser with sudo, but write output to secadmin-owned path
"${SUDO[@]}" python3 "${PARSER}" --output "${OUT_CSV}" --logfile "${DETECTED_LOGFILE}"

if [[ ! -f "${OUT_CSV}" ]]; then
  echo "[!] Expected CSV not found: ${OUT_CSV}"
  exit 1
fi

echo "[*] Computing SHA-256 hash..."
sha256sum "${OUT_CSV}" > "${OUT_HASH}"

# Maintain "latest" symlinks
ln -sf "$(basename "${OUT_CSV}")"  "${REPORT_DIR}/ssh_events_latest.csv"
ln -sf "$(basename "${OUT_HASH}")" "${REPORT_DIR}/ssh_events_latest.csv.sha256"

echo "[+] Done."
echo "    CSV:  ${OUT_CSV}"
echo "    Hash: ${OUT_HASH}"
echo "    Latest symlink: ${REPORT_DIR}/ssh_events_latest.csv"
