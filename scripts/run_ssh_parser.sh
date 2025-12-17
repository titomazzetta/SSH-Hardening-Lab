#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Run SSH log parser, generate SIEM-ready CSV reports,
#   compute SHA-256 integrity hashes, and maintain
#   authoritative + UX/demo copies.
#
# Usage:
#   cd ~/SSH-Hardening-Lab
#   ./scripts/run_ssh_parser.sh
#
# Optional:
#   LOGFILE=/path/to/auth.log ./scripts/run_ssh_parser.sh
#

set -euo pipefail

# ----------------------------
# Paths
# ----------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PARSER="${SCRIPT_DIR}/parse_ssh_logs_geo.py"
GEO_CACHE="${SCRIPT_DIR}/geo_cache.json"

AUTHORITATIVE_DIR="${HOME}/ssh_reports"
UX_DIR="${PROJECT_ROOT}/screenshots/ssh_reports"

mkdir -p "${AUTHORITATIVE_DIR}"
mkdir -p "${UX_DIR}"

# ----------------------------
# Timestamped output
# ----------------------------

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_CSV="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv.sha256"

# ----------------------------
# Logfile detection
# ----------------------------

if [[ -n "${LOGFILE:-}" ]]; then
  DETECTED_LOGFILE="${LOGFILE}"
elif [[ -f /var/log/auth.log ]]; then
  DETECTED_LOGFILE="/var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
  DETECTED_LOGFILE="/var/log/secure"
else
  echo "[!] Could not find auth log."
  echo "[!] Set manually: LOGFILE=/path/to/log ./scripts/run_ssh_parser.sh"
  exit 1
fi

# ----------------------------
# Status output
# ----------------------------

echo "[*] Running SSH log parser..."
echo "    Parser:      ${PARSER}"
echo "    Logfile:     ${DETECTED_LOGFILE}"
echo "    Output CSV:  ${OUT_CSV}"
echo "    UX copies:   ${UX_DIR}"

# ----------------------------
# sudo handling
# ----------------------------

SUDO=(sudo -n)
if ! sudo -n true 2>/dev/null; then
  echo "[!] Non-interactive sudo not available."
  echo "[*] Falling back to interactive sudo..."
  SUDO=(sudo)
fi

# ----------------------------
# Run parser
# ----------------------------

"${SUDO[@]}" python3 "${PARSER}" \
  --log "${DETECTED_LOGFILE}" \
  --out "${OUT_CSV}" \
  --geo-cache "${GEO_CACHE}"

if [[ ! -f "${OUT_CSV}" ]]; then
  echo "[!] Parser did not produce expected CSV."
  exit 1
fi

# ----------------------------
# Hash generation (portable)
# ----------------------------

echo "[*] Computing SHA-256 hash..."
(
  cd "${AUTHORITATIVE_DIR}"
  sha256sum "$(basename "${OUT_CSV}")" > "$(basename "${OUT_HASH}")"
)

# ----------------------------
# Maintain authoritative symlinks
# ----------------------------

ln -sf "$(basename "${OUT_CSV}")"  "${AUTHORITATIVE_DIR}/ssh_events_latest.csv"
ln -sf "$(basename "${OUT_HASH}")" "${AUTHORITATIVE_DIR}/ssh_events_latest.csv.sha256"

# ----------------------------
# Copy UX/demo artifacts (real files)
# ----------------------------

cp -f "${OUT_CSV}"  "${UX_DIR}/ssh_events_${TIMESTAMP}.csv"
cp -f "${OUT_HASH}" "${UX_DIR}/ssh_events_${TIMESTAMP}.csv.sha256"

cp -f "${OUT_CSV}"  "${UX_DIR}/ssh_events_latest.csv"
cp -f "${OUT_HASH}" "${UX_DIR}/ssh_events_latest.csv.sha256"

# ----------------------------
# Final output
# ----------------------------

echo "[+] Done."
echo "    Authoritative CSV: ${OUT_CSV}"
echo "    Authoritative Hash: ${OUT_HASH}"
echo "    UX CSV:            ${UX_DIR}/ssh_events_latest.csv"
echo "    UX Hash:           ${UX_DIR}/ssh_events_latest.csv.sha256"
echo
echo "[*] Verification tip (Mac/Linux):"
echo "    cd screenshots/ssh_reports && shasum -a 256 -c ssh_events_latest.csv.sha256"

