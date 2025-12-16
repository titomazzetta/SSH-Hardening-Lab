#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Run SSH log parsing as the non-root user (secadmin) and write reports to:
#     /home/secadmin/ssh_reports/
#   Elevate ONLY the parser execution to read /var/log/auth.log.
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

# Where reports should live (secadmin-owned)
REPORT_DIR="${HOME}/ssh_reports"
mkdir -p "${REPORT_DIR}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_CSV="${REPORT_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${OUT_CSV}.sha256"

# Allow overriding logfile path without editing code (parser must support --logfile to use this)
LOGFILE="${LOGFILE:-/var/log/auth.log}"

echo "[*] Running SSH log parser (sudo only for auth.log read)..."
echo "    Parser:  ${PARSER}"
echo "    Logfile: ${LOGFILE}"
echo "    Output:  ${OUT_CSV}"

# Prefer non-interactive sudo; fail fast with a clear message if NOPASSWD isn't set
if ! sudo -n true 2>/dev/null; then
  echo "[!] sudo requires a password (non-interactive sudo not configured)."
  echo "[!] Fix: add a visudo rule for the parser (recommended), or run manually with sudo."
  echo "    Example (visudo):"
  echo "      secadmin ALL=(root) NOPASSWD: /usr/bin/python3 /home/secadmin/SSH-Hardening-Lab/scripts/parse_ssh_logs_geo.py *"
  exit 1
fi

# Run parser with sudo, but write output to secadmin-owned path
# NOTE: parser must support --output, and optionally --logfile.
sudo -n python3 "${PARSER}" --output "${OUT_CSV}" --logfile "${LOGFILE}"

if [[ ! -f "${OUT_CSV}" ]]; then
  echo "[!] Expected CSV not found: ${OUT_CSV}"
  exit 1
fi

echo "[*] Computing SHA-256 hash..."
sha256sum "${OUT_CSV}" > "${OUT_HASH}"

# Maintain "latest" symlinks (in secadmin-owned directory)
ln -sf "$(basename "${OUT_CSV}")"  "${REPORT_DIR}/ssh_events_latest.csv"
ln -sf "$(basename "${OUT_HASH}")" "${REPORT_DIR}/ssh_events_latest.csv.sha256"

echo "[+] Done."
echo "    CSV:  ${OUT_CSV}"
echo "    Hash: ${OUT_HASH}"
echo "    Latest symlink: ${REPORT_DIR}/ssh_events_latest.csv"
