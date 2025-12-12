#!/usr/bin/env bash
#
# Role: BLUE TEAM
# Purpose:
#   Bootstrap script to install and configure core components for the
#   SSH Hardening Lab on a Debian-based system.
#
# What this does:
#   - Installs OpenSSH server, Fail2Ban, UFW, Python 3
#   - Lets you choose an sshd_config hardening profile
#   - Copies Fail2Ban SSH jail config into place
#   - Enables and starts services
#   - Marks helper scripts as executable
#
# Usage:
#   sudo ./deploy.sh
#

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run this script with sudo or as root."
  exit 1
fi

echo "[*] Updating package index..."
apt update -y

echo "[*] Installing required packages (openssh-server, fail2ban, ufw, python3)..."
apt install -y openssh-server fail2ban ufw python3

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo
echo "[*] Available SSH hardening profiles:"
echo "  1) Lab secure defaults      (configs/sshd_config.example.lab_secure)"
echo "  2) MFA-enabled profile      (configs/sshd_config.example.mfa_profile)"
echo "  3) Production-style hardened (configs/sshd_config.example.production_hardened)"
echo
read -rp "Select profile [1-3, default=1]: " PROFILE_CHOICE
PROFILE_CHOICE=${PROFILE_CHOICE:-1}

case "${PROFILE_CHOICE}" in
  1) SSH_PROFILE="${PROJECT_ROOT}/configs/sshd_config.example.lab_secure" ;;
  2) SSH_PROFILE="${PROJECT_ROOT}/configs/sshd_config.example.mfa_profile" ;;
  3) SSH_PROFILE="${PROJECT_ROOT}/configs/sshd_config.example.production_hardened" ;;
  *) echo "[!] Invalid choice, defaulting to lab_secure"
     SSH_PROFILE="${PROJECT_ROOT}/configs/sshd_config.example.lab_secure" ;;
esac

echo "[*] Backing up and applying sshd_config from: ${SSH_PROFILE}"
if [[ -f /etc/ssh/sshd_config ]]; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)
fi
cp "${SSH_PROFILE}" /etc/ssh/sshd_config

echo "[*] Applying Fail2Ban sshd jail example..."
mkdir -p /etc/fail2ban/jail.d
cp "${PROJECT_ROOT}/configs/jail_sshd.conf.example" /etc/fail2ban/jail.d/sshd.conf

echo "[*] Enabling and starting ssh and fail2ban services..."
systemctl enable ssh
systemctl restart ssh

systemctl enable fail2ban
systemctl restart fail2ban

echo "[*] Optional: review and apply UFW rules from configs/ufw_rules_example.txt"
echo "    You can run those commands manually to enable the firewall."

echo "[*] Marking helper scripts as executable..."
chmod +x "${PROJECT_ROOT}/deploy.sh"
chmod +x "${PROJECT_ROOT}/scripts/"*.sh

echo
echo "[+] Deployment complete."
echo "    Next steps:"
echo "      - Verify SSH is reachable"
echo "      - Adjust /etc/ssh/sshd_config as needed"
echo "      - Restart ssh: sudo systemctl restart ssh"
echo "      - Check Fail2Ban status: sudo fail2ban-client status sshd"
