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
#   - If MFA profile selected:
#       * installs libpam-google-authenticator
#       * patches /etc/pam.d/sshd to require TOTP (idempotent)
#       * prompts you to enroll secadmin using google-authenticator
#   - Copies Fail2Ban SSH jail config into place
#   - Validates sshd config (sshd -t) and rolls back on failure
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

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"

SSHD_CONFIG="/etc/ssh/sshd_config"
PAM_SSHD="/etc/pam.d/sshd"

SSHD_BACKUP="${SSHD_CONFIG}.backup.${TS}"
PAM_BACKUP="${PAM_SSHD}.backup.${TS}"

# ---------- helpers ----------

die() {
  echo "[!] $*" >&2
  exit 1
}

backup_file_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$dst"
    echo "[*] Backup created: $dst"
  fi
}

restore_backup_if_exists() {
  local backup="$1"
  local target="$2"
  if [[ -f "$backup" ]]; then
    cp "$backup" "$target"
    echo "[*] Restored backup: $backup -> $target"
  fi
}

validate_sshd_or_rollback() {
  # Validate sshd_config syntax before restart.
  if ! sshd -t 2>/dev/null; then
    echo "[!] sshd -t failed. Rolling back sshd_config..."
    restore_backup_if_exists "$SSHD_BACKUP" "$SSHD_CONFIG"
    sshd -t || true
    die "sshd_config validation failed; rollback attempted. Check ${SSHD_CONFIG}."
  fi
}

restart_sshd_or_rollback() {
  # Restart and verify active; rollback if restart fails.
  if ! systemctl restart ssh; then
    echo "[!] Failed to restart ssh. Rolling back sshd_config..."
    restore_backup_if_exists "$SSHD_BACKUP" "$SSHD_CONFIG"
    systemctl restart ssh || true
    die "ssh restart failed; rollback attempted."
  fi

  if ! systemctl is-active --quiet ssh; then
    echo "[!] ssh service is not active after restart. Rolling back..."
    restore_backup_if_exists "$SSHD_BACKUP" "$SSHD_CONFIG"
    systemctl restart ssh || true
    die "ssh not active; rollback attempted."
  fi
}

pam_has_google_authenticator_line() {
  # Match common variants; keep it simple but robust.
  grep -Eq '^\s*auth\s+required\s+pam_google_authenticator\.so\b' "$PAM_SSHD"
}

patch_pam_for_mfa_idempotent() {
  # Adds:
  #   auth required pam_google_authenticator.so
  #
  # NOTE: We do NOT use "nullok" here because the goal is MFA enforcement
  # once you enroll the user. If you want phased rollout, add "nullok".
  local line='auth required pam_google_authenticator.so'

  if [[ ! -f "$PAM_SSHD" ]]; then
    die "Expected PAM file not found: $PAM_SSHD"
  fi

  if pam_has_google_authenticator_line; then
    echo "[*] PAM already configured for Google Authenticator in $PAM_SSHD (no changes)."
    return
  fi

  backup_file_if_exists "$PAM_SSHD" "$PAM_BACKUP"

  # Insert before "@include common-auth" if present; otherwise append at end.
  if grep -qE '^\s*@include\s+common-auth\b' "$PAM_SSHD"; then
    # Insert above the first @include common-auth line
    awk -v ins="$line" '
      BEGIN{done=0}
      {
        if(!done && $0 ~ /^\s*@include\s+common-auth\b/) {
          print ins
          done=1
        }
        print $0
      }
      END{
        if(!done){
          print ins
        }
      }
    ' "$PAM_SSHD" > "${PAM_SSHD}.tmp.${TS}"
    mv "${PAM_SSHD}.tmp.${TS}" "$PAM_SSHD"
  else
    echo "$line" >> "$PAM_SSHD"
  fi

  echo "[*] Patched $PAM_SSHD for MFA (Google Authenticator)."
}

# ---------- main ----------

echo "[*] Updating package index..."
apt update -y

echo "[*] Installing required packages (openssh-server, fail2ban, ufw, python3)..."
apt install -y openssh-server fail2ban ufw python3

echo
echo "[*] Available SSH hardening profiles:"
echo "  1) Lab secure defaults       (configs/sshd_config.example.lab_secure)"
echo "  2) MFA-enabled profile       (configs/sshd_config.example.mfa_profile)"
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

[[ -f "$SSH_PROFILE" ]] || die "Profile not found: $SSH_PROFILE"

echo "[*] Backing up and applying sshd_config from: ${SSH_PROFILE}"
backup_file_if_exists "$SSHD_CONFIG" "$SSHD_BACKUP"
cp "${SSH_PROFILE}" "$SSHD_CONFIG"

# Validate sshd_config syntax before attempting restart
echo "[*] Validating sshd_config (sshd -t)..."
validate_sshd_or_rollback

# MFA automation steps (Problems 1-4)
if [[ "${PROFILE_CHOICE}" == "2" ]]; then
  echo
  echo "[*] MFA profile selected. Installing PAM Google Authenticator module..."
  apt install -y libpam-google-authenticator

  echo "[*] Patching PAM for sshd (idempotent)..."
  patch_pam_for_mfa_idempotent

  # OPTIONAL sanity check: ensure google-authenticator command exists
  if ! command -v google-authenticator >/dev/null 2>&1; then
    echo "[!] google-authenticator command not found in PATH after install."
    echo "    Package install may have failed or path differs on your system."
  fi

  echo
  echo "[*] MFA Enrollment Step (per-user):"
  echo "    You must enroll the target SSH user (recommended: secadmin) to generate the TOTP secret."
  echo "    Run this AFTER this script finishes and while keeping an existing SSH session open:"
  echo
  echo "      sudo -u secadmin -H google-authenticator"
  echo
  echo "    Then restart SSH:"
  echo
  echo "      sudo systemctl restart ssh"
  echo
  echo "    IMPORTANT: Keep your current SSH session open while testing MFA in a new terminal."
  echo
fi

echo "[*] Applying Fail2Ban sshd jail example..."
mkdir -p /etc/fail2ban/jail.d
cp "${PROJECT_ROOT}/configs/jail_sshd.conf.example" /etc/fail2ban/jail.d/sshd.conf

echo "[*] Enabling and starting ssh and fail2ban services..."
systemctl enable ssh
restart_sshd_or_rollback

systemctl enable fail2ban
systemctl restart fail2ban

echo "[*] Optional: review and apply UFW rules from configs/ufw_rules_example.txt"
echo "    You can run those commands manually to enable the firewall."

echo "[*] Marking helper scripts as executable..."
chmod +x "${PROJECT_ROOT}/scripts/"*.sh || true

echo
echo "[+] Deployment complete."
echo "    Next steps:"
echo "      - Verify SSH is reachable (test in a NEW terminal)."
echo "      - Check Fail2Ban status: sudo fail2ban-client status sshd"
echo "      - If you selected MFA profile: enroll secadmin and restart ssh (see instructions above)."
