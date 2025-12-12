#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Wrapper script to run the SSH log parser in a safe, repeatable way.
#   - Ensures output directory exists
#   - Adds a timestamp to each CSV
#   - Computes a SHA-256 hash for integrity
#   - Maintains a 'latest' symlink for convenience
#
# Usage:
#   Edit SERVER_IP below, then run:
#     ./scripts/run_ssh_parser.sh
#

set -euo pipefail

# >>> EDIT THIS <<<
# Set this to the IP address of your SSH server (the Debian VM running sshd)
SERVER_IP="127.0.0.1"
SSH_PORT="22"

# Directory to store reports (for secadmin user)
REPORT_DIR="${HOME}/ssh_reports"
mkdir -p "${REPORT_DIR}"

# Resolve script directory so we can call the Python parser reliably
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_CSV="${REPORT_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${OUT_CSV}.sha256"

echo "[*] Running SSH log parser..."
python3 "${SCRIPT_DIR}/parse_ssh_logs_geo.py"     --server-ip "${SERVER_IP}"     --ssh-port "${SSH_PORT}"     --output "${OUT_CSV}"

echo "[*] Computing SHA-256 hash..."
sha256sum "${OUT_CSV}" > "${OUT_HASH}"

cd "${REPORT_DIR}"

# Update "latest" symlinks
ln -sf "$(basename "${OUT_CSV}")" ssh_events_latest.csv
ln -sf "$(basename "${OUT_HASH}")" ssh_events_latest.csv.sha256

echo "[+] Parsing complete."
echo "    CSV:  ${OUT_CSV}"
echo "    Hash: ${OUT_HASH}"
echo "    Latest symlink: ${REPORT_DIR}/ssh_events_latest.csv"
