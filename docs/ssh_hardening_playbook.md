# SSH Hardening Lab – SSH Hardening Playbook

This playbook walks through the full lifecycle of the SSH Hardening Lab:

1. Environment setup
2. SSH hardening deployment
3. Attack simulation (Nmap + Hydra)
4. Log parsing and CSV export
5. Splunk (or SIEM) ingestion
6. Optional MFA setup
7. Screenshot guidance

---

## 1️⃣ Environment Setup

### Hardened Server (Debian)

- Debian or Ubuntu-based VM
- Internet access for updates and optional geo-IP/MFA packages
- Static or known IP reachable from the attacker machine

Initial commands:

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/<your-username>/SSH-Hardening-Lab.git
cd SSH-Hardening-Lab

sudo adduser secadmin
sudo usermod -aG sudo secadmin
```

### Attacker Machine

- Another Linux VM (or a separate host)
- Tools: `nmap`, `hydra`

Install tools:

```bash
sudo apt update
sudo apt install -y nmap hydra
```

---

## 2️⃣ Deploy SSH Hardening (deploy.sh)

On the hardened server, from the project root:

```bash
sudo ./deploy.sh
```

The script will:

- Install `openssh-server`, `fail2ban`, `ufw`, `python3`
- Prompt you to select an SSH profile
- Backup any existing `/etc/ssh/sshd_config`
- Copy the chosen profile into `/etc/ssh/sshd_config`
- Copy `jail_sshd.conf.example` into `/etc/fail2ban/jail.d/sshd.conf`
- Enable and restart `ssh` and `fail2ban`

Profiles:

1. **Lab secure defaults** – good overall tightening for classroom/demo use  
2. **MFA-enabled profile** – intended for use with PAM + Google Authenticator  
3. **Production-style hardened** – more restrictive, key-only, bastion-like

After deployment:

```bash
sudo systemctl status ssh
sudo systemctl status fail2ban
```

Optional: enable UFW following `configs/ufw_rules_example.txt`.

---

## 3️⃣ Attack Simulation (Nmap + Hydra)

All attack activity should originate from the attacker machine.

### 3.1 Nmap Reconnaissance

From the attacker VM:

```bash
cd /path/to/SSH-Hardening-Lab/scripts

./scan_ssh.sh <SERVER_IP>
```

Screenshot suggestions:

- Nmap version detection output on port 22
- Any additional ports discovered

### 3.2 Hydra Brute-Force (LAB ONLY)

From the attacker VM:

```bash
./ssh_bruteforce_test.sh <SERVER_IP> secadmin /usr/share/wordlists/rockyou.txt
```

- This generates realistic failed SSH login attempts.
- Fail2Ban should eventually ban the attacking IP.
- Logs are written to `/var/log/auth.log` on the server.

On the server, validate Fail2Ban:

```bash
sudo fail2ban-client status sshd
```

Screenshots:

- Hydra output showing attempts
- `fail2ban-client status sshd` showing banned IP(s)

---

## 4️⃣ Log Parsing & CSV Export

On the hardened server, as the `secadmin` user:

```bash
sudo -i -u secadmin
cd /path/to/SSH-Hardening-Lab

./scripts/run_ssh_parser.sh
```

What this does:

- Parses `/var/log/auth.log` via `parse_ssh_logs_geo.py`
- Enriches entries with geo-IP (if internet is available)
- Computes a simple `danger_score`
- Writes timestamped output into `~/ssh_reports/`
- Computes a SHA-256 hash of each CSV
- Updates `ssh_events_latest.csv` symlink

Check results:

```bash
ls -l ~/ssh_reports/
cat ~/ssh_reports/ssh_events_latest.csv | head
cat ~/ssh_reports/ssh_events_latest.csv.sha256
```

Screenshots:

- Directory listing of `~/ssh_reports/`
- First few lines of the CSV
- SHA-256 hash file

---

## 5️⃣ Import into Splunk (or Another SIEM)

In Splunk:

1. Go to **Add Data** → upload `ssh_events_latest.csv`.  
2. Set the source type to `csv` (or create a custom `ssh_events_csv` sourcetype).  
3. Assign to index `ssh_security` (or similar).  

Once indexed, run example SPL queries from the README:

- Top attacking IPs
- High `danger_score` events
- Invalid user enumeration
- Failed vs successful logins per IP

Screenshots:

- Search results for each SPL example
- Any dashboard panels you build



---

## 🔐 Optional Advanced Control: MFA / Google Authenticator SSH Protection

This section enables **time-based one-time password (TOTP) multi-factor authentication** for SSH using PAM and Google Authenticator.

> ⚠️ Only enable this after you have verified that SSH key-based login works and you have console access or alternate admin access. A misconfiguration can lock you out.

### 1️⃣ Install dependencies

On the hardened SSH server:

```bash
sudo apt update
sudo apt install libpam-google-authenticator
```

---

### 2️⃣ Enroll the SSH admin user

Log in as the user that will authenticate over SSH (e.g., `secadmin`) and run:

```bash
google-authenticator
```

Recommended answers:

| Prompt                                                    | Recommended |
|-----------------------------------------------------------|------------|
| Do you want authentication tokens to be time-based?       | **y**      |
| Do you want to disallow multiple uses?                    | **y**      |
| Do you want to increase the time window?                  | **n**      |
| Do you want rate-limiting protection against attackers?   | **y**      |

Actions:

- Scan the generated QR code into a TOTP app (Google Authenticator, Authy, 1Password, etc.).  
- Save the emergency scratch codes in a secure location.

---

### 3️⃣ Configure PAM to use Google Authenticator

Edit the SSH PAM configuration:

```bash
sudo nano /etc/pam.d/sshd
```

Add the following line near the top of the file (before any `@include common-auth` line, if present):

```text
auth required pam_google_authenticator.so nullok
```

Key points:

- `required` → this line must succeed for authentication to succeed.  
- `nullok` → allows accounts without a `.google_authenticator` file to log in without MFA (useful when gradually onboarding users). Remove `nullok` later if you want to enforce MFA for everyone.

---

### 4️⃣ Ensure sshd_config is MFA-aware

The **MFA profile** in this lab already includes the necessary directives:

```text
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

This enforces **public key + keyboard-interactive (TOTP)** for login when you deploy the profile:

- `configs/sshd_config.example.mfa_profile`

If you modify `sshd_config` manually, make sure these two options are present and not overridden later in the file.

---

### 5️⃣ Restart SSH safely

After updating PAM and sshd_config, restart the SSH daemon:

```bash
sudo systemctl restart ssh
sudo systemctl status ssh
```

Confirm that `Active:` shows `active (running)` and there are no syntax errors in the logs:

```bash
sudo journalctl -u ssh --since "5 minutes ago"
```

---

### 6️⃣ Test the MFA login flow

From a separate attacker/test machine:

```bash
ssh secadmin@<SERVER_IP>
```

Expected behavior:

1. SSH negotiates the connection and authenticates your **public key**.  
2. You receive a prompt similar to:  

   ```text
   Verification code:
   ```

3. Only after providing the correct 6-digit TOTP code from your authenticator app should the login succeed.

You can intentionally enter a wrong TOTP value once to:

- Generate **failed MFA attempts** in the logs  
- Confirm that Fail2Ban and/or your Splunk rules still behave correctly

---

### 7️⃣ Rollback / Break-glass procedure

If something goes wrong or you get locked out, you should have a simple rollback path documented.

**Option A – Temporarily disable Google Authenticator in PAM**

From console or another valid session:

```bash
sudo sed -i 's/^auth required pam_google_authenticator.so nullok/#auth disabled pam_google_authenticator.so nullok/' /etc/pam.d/sshd
sudo systemctl restart ssh
```

**Option B – Switch back to a non-MFA SSH profile**

Run the lab deploy script again and choose the **lab secure defaults** profile:

```bash
cd /path/to/SSH-Hardening-Lab
sudo ./deploy.sh
# Select: 1) Lab secure defaults
```

Then test SSH login normally (no TOTP prompt).

Documenting these break-glass steps shows operational maturity and safety awareness.

---

### 8️⃣ MFA Screenshot Checklist

Recommended screenshots for the report / submission:

1. Output of `google-authenticator` showing QR and configuration summary (safely redacted).  
2. Authenticator app UI (blurred secret, but visible TOTP code pattern).  
3. Edited `/etc/pam.d/sshd` file with the `pam_google_authenticator.so` line.  
4. Terminal view of an SSH login showing the `Verification code:` prompt.  
5. Splunk view of SSH events where successful logins & failed attempts are visible before/after MFA rollout.

This provides a full lifecycle story:
- design → hardening → MFA → validation → telemetry.

