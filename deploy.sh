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
#   - Supports a configurable admin SSH user (default: secadmin)
#   - If MFA profile selected:
#       * installs libpam-google-authenticator
#       * ensures an authorized public key exists for the admin user
#         (guided onboarding: ssh-copy-id instructions or paste public key)
#       * patches /etc/pam.d/sshd to require TOTP (idempotent)
#       * runs google-authenticator enrollment (prompted)
#       * restarts SSH automatically with rollback safety
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

DEFAULT_ADMIN_USER="secadmin"
ADMIN_USER=""
ADMIN_HOME=""
AUTH_KEYS=""
GA_FILE=""

SSH_RESTARTED_IN_MFA="false"

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
  grep -Eq '^\s*auth\s+required\s+pam_google_authenticator\.so\b' "$PAM_SSHD"
}

patch_pam_for_mfa_idempotent() {
  # Adds:
  #   auth required pam_google_authenticator.so
  #
  # NOTE: We do NOT use "nullok" here because the goal is MFA enforcement.
  local line='auth required pam_google_authenticator.so'

  [[ -f "$PAM_SSHD" ]] || die "Expected PAM file not found: $PAM_SSHD"

  if pam_has_google_authenticator_line; then
    echo "[*] PAM already configured for Google Authenticator in $PAM_SSHD (no changes)."
    return
  fi

  backup_file_if_exists "$PAM_SSHD" "$PAM_BACKUP"

  # Insert before "@include common-auth" if present; otherwise append at end.
  if grep -qE '^\s*@include\s+common-auth\b' "$PAM_SSHD"; then
    awk -v ins="$line" '
      BEGIN{done=0}
      {
        if(!done && $0 ~ /^\s*@include\s+common-auth\b/) {
          print ins
          done=1
        }
        print $0
      }
      END{ if(!done){ print ins } }
    ' "$PAM_SSHD" > "${PAM_SSHD}.tmp.${TS}"
    mv "${PAM_SSHD}.tmp.${TS}" "$PAM_SSHD"
  else
    echo "$line" >> "$PAM_SSHD"
  fi

  echo "[*] Patched $PAM_SSHD for MFA (Google Authenticator)."
}

prompt_admin_user() {
  echo
  read -rp "Target SSH admin user [default=${DEFAULT_ADMIN_USER}]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-$DEFAULT_ADMIN_USER}"

  [[ "$ADMIN_USER" == "root" ]] && die "Refusing: do not use root for SSH. Use a non-root admin user."

  if ! id "$ADMIN_USER" >/dev/null 2>&1; then
    echo "[!] User '$ADMIN_USER' does not exist."
    read -rp "Create user '$ADMIN_USER' now? [y/N]: " yn
    yn="${yn:-N}"
    if [[ "$yn" =~ ^[Yy]$ ]]; then
      useradd -m -s /bin/bash "$ADMIN_USER"
      echo "[*] Created user: $ADMIN_USER"
      echo "[*] If you want admin privileges: usermod -aG sudo $ADMIN_USER"
    else
      die "User '$ADMIN_USER' must exist. Aborting."
    fi
  fi

  ADMIN_HOME="$(eval echo "~${ADMIN_USER}")"
  AUTH_KEYS="${ADMIN_HOME}/.ssh/authorized_keys"
  GA_FILE="${ADMIN_HOME}/.google_authenticator"
}

ensure_ssh_dir_perms() {
  mkdir -p "${ADMIN_HOME}/.ssh"
  chown -R "${ADMIN_USER}:${ADMIN_USER}" "${ADMIN_HOME}/.ssh"
  chmod 700 "${ADMIN_HOME}/.ssh"
  touch "$AUTH_KEYS"
  chown "${ADMIN_USER}:${ADMIN_USER}" "$AUTH_KEYS"
  chmod 600 "$AUTH_KEYS"
}

authorized_keys_has_any_key() {
  [[ -s "$AUTH_KEYS" ]] && grep -Eq '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp)' "$AUTH_KEYS"
}

prompt_key_onboarding() {
  echo
  echo "[*] No authorized SSH keys detected for user: ${ADMIN_USER}"
  echo "    MFA profile requires: publickey + TOTP."
  echo
  echo "    Option A (recommended): run from your CLIENT machine"
  echo "      ssh-keygen -t ed25519 -a 64 -f ~/.ssh/ssh_lab_${ADMIN_USER}"
  echo "      # macOS: brew install ssh-copy-id (if you don't have it)"
  echo "      ssh-copy-id -i ~/.ssh/ssh_lab_${ADMIN_USER}.pub ${ADMIN_USER}@<SERVER_IP>"
  echo
  echo "    Option B (works everywhere): paste the public key now (server-side prompt)"
  echo

  read -rp "Choose key onboarding method [A/B, default=B]: " method
  method="${method:-B}"

  if [[ "$method" =~ ^[Aa]$ ]]; then
    echo
    echo "[!] You chose client-side ssh-copy-id."
    echo "    Run the commands above on your client, then return here."
    read -rp "Press ENTER once your key has been installed (or Ctrl+C to abort)... " _
  else
    echo
    echo "[*] Paste your client PUBLIC key now (single line starting with ssh-ed25519 or ssh-rsa)."
    echo "    Then press Ctrl+D to finish."
    sudo -u "$ADMIN_USER" -H bash -c "cat >> '$AUTH_KEYS'"
  fi

  if ! authorized_keys_has_any_key; then
    die "authorized_keys still appears empty/invalid. Cannot proceed with MFA enforcement."
  fi

  echo "[+] Authorized key installed for ${ADMIN_USER}."
}

run_google_auth_enroll() {
  echo
  echo "[*] Google Authenticator enrollment for user: ${ADMIN_USER}"
  echo "    You will see a QR code. Scan it in Google Authenticator/Authy."
  echo "    Save the emergency scratch codes securely."
  echo
  read -rp "Ready to run enrollment now? [Y/n]: " yn
  yn="${yn:-Y}"
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    sudo -u "$ADMIN_USER" -H google-authenticator
    echo "[+] Enrollment complete: ${GA_FILE}"
  else
    echo "[!] Skipping enrollment. You must run:"
    echo "      sudo -u ${ADMIN_USER} -H google-authenticator"
  fi
}

update_allowusers_if_present() {
  # If profile contains AllowUsers, rewrite it to the chosen admin user.
  if grep -qE '^\s*AllowUsers\b' "$SSHD_CONFIG"; then
    sed -i "s/^\s*AllowUsers.*/AllowUsers ${ADMIN_USER}/" "$SSHD_CONFIG"
    echo "[*] Updated AllowUsers to: ${ADMIN_USER}"
  fi
}

# ---------- main ----------

echo "[*] Updating package index..."
apt update -y

echo "[*] Installing required packages (openssh-server, fail2ban, ufw, python3)..."
apt install -y openssh-server fail2ban ufw python3

prompt_admin_user

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

# Make profile portable for different admin usernames (if profile uses AllowUsers)
update_allowusers_if_present

# Validate sshd_config syntax before attempting restart
echo "[*] Validating sshd_config (sshd -t)..."
validate_sshd_or_rollback

# MFA flow
if [[ "${PROFILE_CHOICE}" == "2" ]]; then
  echo
  echo "[*] MFA profile selected. Installing PAM Google Authenticator module..."
  apt install -y libpam-google-authenticator

  echo "[*] Patching PAM for sshd (idempotent)..."
  patch_pam_for_mfa_idempotent

  if ! command -v google-authenticator >/dev/null 2>&1; then
    echo "[!] google-authenticator command not found in PATH after install."
    echo "    Package install may have failed or path differs on your system."
  fi

  ensure_ssh_dir_perms

  if ! authorized_keys_has_any_key; then
    prompt_key_onboarding
  else
    echo "[*] Authorized key(s) already present for ${ADMIN_USER}."
  fi

  run_google_auth_enroll

  echo
  echo "[*] Restarting SSH to apply MFA requirements..."
  restart_sshd_or_rollback
  SSH_RESTARTED_IN_MFA="true"

  echo
  echo "[+] MFA setup complete."
  echo "    Test from a NEW terminal on your client:"
  echo "      ssh ${ADMIN_USER}@<SERVER_IP>"
  echo "    You should be prompted for a Verification code (TOTP)."
fi

echo "[*] Applying Fail2Ban sshd jail example..."
mkdir -p /etc/fail2ban/jail.d
cp "${PROJECT_ROOT}/configs/jail_sshd.conf.example" /etc/fail2ban/jail.d/sshd.conf

echo "[*] Enabling and starting ssh and fail2ban services..."
systemctl enable ssh

# If MFA block already restarted ssh, avoid redundant restart; otherwise restart safely now.
if [[ "$SSH_RESTARTED_IN_MFA" != "true" ]]; then
  restart_sshd_or_rollback
fi

systemctl enable fail2ban
systemctl restart fail2ban

echo "[*] Optional: review and apply UFW rules from configs/ufw_rules_example.txt"
echo "    You can run those commands manually to enable the firewall."

echo "[*] Marking helper scripts as executable..."
chmod +x "${PROJECT_ROOT}/scripts/"*.sh || true
chmod +x "${PROJECT_ROOT}/scripts/"*.py || true

echo
echo "[+] Deployment complete."
echo "    Admin SSH user: ${ADMIN_USER}"
echo "    Next steps:"
echo "      - Verify SSH is reachable (test in a NEW terminal)."
echo "      - Check Fail2Ban status: sudo fail2ban-client status sshd"
echo "      - If you selected MFA profile: ensure you can log in with key + TOTP."


# Notes:
# - Parser outputs default to: ./screenshots/ssh_reports/ (via scripts/run_ssh_parser.sh)
# - To re-run parser later: sudo ./scripts/run_ssh_parser.sh
# - To test brute-force: ./scripts/ssh_bruteforce_test.sh <TARGET_IP> <USERNAME> <WORDLIST> 