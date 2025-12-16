#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Run the SSH log parser reliably and produce Splunk-ready CSV telemetry.
#   - Runs parser with sudo (required to read /var/log/auth.log)
#   - Extracts the actual CSV path from parser output (no timestamp mismatch)
#   - Computes SHA-256 hash for integrity
#   - Maintains "latest" symlinks in the same output directory
#
# Usage:
#   cd ~/SSH-Hardening-Lab
#   sudo ./scripts/run_ssh_parser.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="${SCRIPT_DIR}/parse_ssh_logs_geo.py"

if [[ ! -f "$PARSER" ]]; then
  echo "[!] Parser not found: $PARSER"
  exit 1
fi

echo "[*] Running SSH log parser..."

# Run parser as root to access /var/log/auth.log. Capture stdout so we can parse the CSV path.
OUT="$(sudo -E python3 "$PARSER")"
echo "$OUT"

# Extract the CSV path from the parser's stdout line: "    CSV:  /path/to/file.csv"
CSV_PATH="$(echo "$OUT" | awk -F':  ' '/^    CSV:/{print $2}')"

if [[ -z "${CSV_PATH}" ]]; then
  echo "[!] Could not determine CSV path from parser output."
  echo "[!] Expected a line like: '    CSV:  /root/ssh_reports/ssh_events_YYYYMMDD_HHMMSS.csv'"
  exit 1
fi

if [[ ! -f "${CSV_PATH}" ]]; then
  echo "[!] CSV file not found at reported path: ${CSV_PATH}"
  exit 1
fi

echo "[*] Computing SHA-256 hash..."
sudo sha256sum "${CSV_PATH}" | sudo tee "${CSV_PATH}.sha256" >/dev/null

DIR="$(dirname "${CSV_PATH}")"
CSV_FILE="$(basename "${CSV_PATH}")"
HASH_FILE="$(basename "${CSV_PATH}.sha256")"

# Maintain latest symlinks in the output directory
sudo ln -sf "${CSV_FILE}" "${DIR}/ssh_events_latest.csv"
sudo ln -sf "${HASH_FILE}" "${DIR}/ssh_events_latest.csv.sha256"

echo "[+] Done."
echo "    CSV:  ${CSV_PATH}"
echo "    Hash: ${CSV_PATH}.sha256"
echo "    Latest symlink: ${DIR}/ssh_events_latest.csv"
