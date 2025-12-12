# SSH Hardening Lab  
### Automated SSH Defense, Attack Simulation & Splunk-Ready Telemetry

![Status: Active](https://img.shields.io/badge/Status-Active-success)
![Security Engineering](https://img.shields.io/badge/Focus-Security%20Engineering-blue)
![Detection Engineering](https://img.shields.io/badge/Focus-Detection%20Engineering-orange)
![Linux](https://img.shields.io/badge/Platform-Linux-red)
![Splunk Ready](https://img.shields.io/badge/SIEM-Splunk-informational)

## 📌 Overview

This project demonstrates end-to-end **SSH security engineering** on a Debian Linux server.

The project was developed as a personal security engineering lab and portfolio artifact, while also fulfilling academic coursework requirements, with an emphasis on real-world defensive and detection workflows.

The design prioritizes observability, reproducibility, and detection signal quality over purely preventive controls.
It combines:
- 🔐 SSH service hardening (multiple profiles)
- 🚫 Automated blocking of brute-force attacks (Fail2Ban + UFW)
- 🔴 Red-team attack simulation (Nmap + Hydra)
- 🟦 Blue-team log parsing & geo-enrichment (Python)
- 🧮 Risk scoring of attacker behavior (`danger_score`)
- 📊 Splunk-ready CSV export + example SPL queries
- 🔑 Optional SSH MFA with Google Authenticator (TOTP)

It is designed so that:

- A **security reviewer** can clone → deploy → attack → validate → ingest logs  
- A **hiring manager** can evaluate practical skills, detection maturity, and automation capability  
- A **practitioner** can replicate and extend the scenario on their own VM  

---

## 🎯 Lab Objectives

1. Harden a Debian SSH service against brute-force attacks  
2. Implement logging & detection of SSH authentication activity  
3. Automatically block malicious IPs using Fail2Ban  
4. Parse SSH logs into enriched CSV datasets (including geo + risk scoring)  
5. Simulate attacks using Hydra + Nmap from an attacker machine  
6. Ingest data into Splunk (or another SIEM) and build detection logic  
7. Optionally enable MFA (TOTP) for higher assurance authentication  

---

## 🔥 Key Capabilities

### 🔐 Hardening Profiles

Located in `configs/` and applied via `deploy.sh`:

- `sshd_config.example.lab_secure`  
  Lab-friendly hardened SSH config (key + password, restricted, good crypto).
- `sshd_config.example.mfa_profile`  
  SSH config wired for MFA via PAM + `pam_google_authenticator`.
- `sshd_config.example.production_hardened`  
  More restrictive, bastion-style configuration (key-only, stricter limits).
- `sshd_config.example`  
  Baseline hardened config kept for convenience/backward compatibility.

All profiles:

- Disable root SSH login (`PermitRootLogin no`)
- Prefer strong key exchange and cipher suites
- Restrict allowed users (default: `AllowUsers secadmin`)
- Tighten brute-force related controls (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`)
- Disable legacy features (X11 forwarding, TCP forwarding, tunnels, etc.)
- Increase log verbosity for security telemetry (`LogLevel VERBOSE`)

---

### 🔍 Detection Engineering

Blue team scripts under `scripts/`:

- `parse_ssh_logs_geo.py`  
  Python script that:
  - Reads `/var/log/auth.log`
  - Extracts SSH events (failed logins, invalid users, successful logins)
  - Enriches with basic geo-IP (free `ip-api.com`)
  - Tracks per-IP/user fail counts
  - Computes a simple `danger_score` (0–100)
  - Writes a normalized CSV for SIEM/Splunk ingestion

- `run_ssh_parser.sh`  
  Wrapper that:
  - Creates `~/ssh_reports/`
  - Generates timestamped CSV: `ssh_events_YYYYMMDD_HHMMSS.csv`
  - Computes SHA-256 hash for integrity: `.sha256` file
  - Maintains `ssh_events_latest.csv` symlink for easy SIEM imports

Fields exported per row:

- `timestamp` (ISO8601)
- `src_ip`
- `src_port`
- `dst_port`
- `username`
- `event_status` (`success` / `fail`)
- `event_type` (`failed_login`, `invalid_user`, `successful_login`)
- `fail_count` (per src_ip + username)
- `total_attempts`
- `src_country`
- `src_city`
- `danger_score` (0–100)

---

### 🧪 Attack Simulation

Red team scripts:

- `scan_ssh.sh`  
  Runs common Nmap scans against the target:
  - Basic SSH version enumeration
  - Default script + version scan on port 22
  - Top ports connectivity scan

- `ssh_bruteforce_test.sh`  
  Hydra-based brute-force simulation for **lab use only**:
  - Takes target IP, username, and wordlist
  - Generates realistic failed SSH log entries
  - Intended to trigger Fail2Ban and produce data for the parser

- `nmap_scan_examples.txt`  
  Handy one-liner references for manual scanning.

> ⚠️ **Legal / Ethical Note:** Only use Hydra/Nmap against systems you own or are explicitly authorized to test. This lab is meant for self-contained, educational use.

---

### 📊 SIEM / Splunk Integration

The CSVs from `run_ssh_parser.sh` are designed to be imported directly into Splunk or another SIEM as a lookup table or an indexed dataset.

Recommended Splunk index: `ssh_security`

Example SPL queries:

**Top attacking IPs with geo:**

```spl
index=ssh_security
| stats count as attempts by src_ip src_country src_city
| sort -attempts
```

**High-risk attempts (danger_score >= 70):**

```spl
index=ssh_security danger_score>=70
| table timestamp src_ip username event_type fail_count danger_score src_country
```

**User enumeration behavior:**

```spl
index=ssh_security event_type=invalid_user
| stats count as invalid_attempts dc(username) as distinct_usernames by src_ip
| sort -invalid_attempts
```

**Failed vs successful logins per IP:**

```spl
index=ssh_security
| stats count(eval(event_status="fail")) as failed
        count(eval(event_status="success")) as success
        by src_ip
| where failed > 0
| sort -failed
```

---

## 📂 Repository Layout

```text
SSH-Hardening-Lab/
│
├── README.md
├── deploy.sh
├── .gitignore
│
├── configs/
│   ├── sshd_config.example
│   ├── sshd_config.example.lab_secure
│   ├── sshd_config.example.mfa_profile
│   ├── sshd_config.example.production_hardened
│   ├── jail_sshd.conf.example
│   └── ufw_rules_example.txt
│
├── docs/
│   ├── design_and_threat_model.md
│   └── ssh_hardening_playbook.md
│
├── screenshots/
│   └── (add redacted validation screenshots here)
│
└── scripts/
    ├── nmap_scan_examples.txt
    ├── parse_ssh_logs_geo.py
    ├── run_ssh_parser.sh
    ├── scan_ssh.sh
    └── ssh_bruteforce_test.sh
```

---

## 🔐 Scripts by Role

### 🟦 Blue Team (Defender)

| File                        | Purpose                                                |
|-----------------------------|--------------------------------------------------------|
| `deploy.sh`                 | Installs SSH, Fail2Ban, UFW, Python; applies profiles |
| `scripts/parse_ssh_logs_geo.py` | Parses SSH logs → enriches → CSV                   |
| `scripts/run_ssh_parser.sh` | Cron-friendly wrapper for parser + hashing             |

### 🔴 Red Team (Adversary Simulation)

| File                         | Purpose                              |
|------------------------------|--------------------------------------|
| `scripts/scan_ssh.sh`        | Nmap reconnaissance against SSH      |
| `scripts/ssh_bruteforce_test.sh` | Hydra brute-force simulation    |
| `scripts/nmap_scan_examples.txt` | Manual Nmap reference commands |

---

## 🚀 Quickstart

### 1️⃣ Hardened Server VM (Debian-based)

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/<your-username>/SSH-Hardening-Lab.git
cd SSH-Hardening-Lab
```

Create a non-root admin user:

```bash
sudo adduser secadmin
sudo usermod -aG sudo secadmin
```

Run the deployment script (as root or with sudo):

```bash
sudo ./deploy.sh
```

You will be prompted to choose a hardening profile:

- `1) Lab secure defaults`
- `2) MFA-enabled profile`
- `3) Production-style hardened`

After deployment:

```bash
sudo systemctl status ssh
sudo systemctl status fail2ban
```

Optionally, apply UFW rules from:

```text
configs/ufw_rules_example.txt
```

---

### 2️⃣ Attacker VM (separate machine)

On another Linux VM (or host) used as the attacker box:

```bash
sudo apt update
sudo apt install -y nmap hydra
```

Run Nmap scans:

```bash
./scripts/scan_ssh.sh <SERVER_IP>
```

Run Hydra brute-force (LAB ONLY):

```bash
./scripts/ssh_bruteforce_test.sh <SERVER_IP> secadmin /usr/share/wordlists/rockyou.txt
```

This generates failed SSH attempts in `/var/log/auth.log` on the target, which Fail2Ban should react to and which your parser will later ingest.

---

### 3️⃣ Log Parsing & CSV Generation

On the **hardened server**, as `secadmin`:

```bash
sudo -i -u secadmin
cd /path/to/SSH-Hardening-Lab

./scripts/run_ssh_parser.sh
```

This will:

- Read `/var/log/auth.log`
- Write CSV reports into `~/ssh_reports/`, e.g.:

```text
/home/secadmin/ssh_reports/ssh_events_YYYYMMDD_HHMMSS.csv
/home/secadmin/ssh_reports/ssh_events_YYYYMMDD_HHMMSS.csv.sha256
/home/secadmin/ssh_reports/ssh_events_latest.csv -> symlink
```

You can then copy `ssh_events_latest.csv` into a Splunk ingest location, or upload via the Splunk UI as a CSV source.

---

### 4️⃣ Optional: MFA / Google Authenticator

This lab includes an advanced optional step using:

- `configs/sshd_config.example.mfa_profile`
- `docs/ssh_hardening_playbook.md` (MFA section)

Follow the MFA section in the playbook to:

- Install `libpam-google-authenticator`
- Enroll `secadmin` with `google-authenticator`
- Configure `/etc/pam.d/sshd`
- Restart `ssh` and test the `Verification code:` prompt
- Validate events in Splunk before and after MFA

---

## 📸 Screenshot Checklist

For a complete lab report or portfolio writeup, recommended screenshots:

- `ssh -V` and hardened `sshd_config` profile
- `sudo fail2ban-client status sshd` showing banned IPs
- Nmap scan output against the hardened server
- Hydra brute-force attempts output
- Excerpts from `/var/log/auth.log` before/after attacks
- Terminal output from `./scripts/run_ssh_parser.sh`
- Directory listing of `~/ssh_reports/` (CSV + SHA256 files)
- Splunk dashboards / searches using the provided SPL
- MFA prompt and/or authenticator app (redacted where needed)

---

## 🔒 Security & Ethics Notice

- This lab is intended for **educational and portfolio** use.  
- Do **not** aim these tools at systems you do not own or explicitly control.  
- Hydra and Nmap must be used responsibly within legal and ethical boundaries.  

No private keys, passwords, or secrets are included in this repository.

---

## ✅ Skills Demonstrated

This project demonstrates practical experience in:

- Practical Linux SSH hardening skills
- Understanding of brute-force attack patterns
- Ability to simulate attacks safely in a lab environment
- Ability to parse and enrich security logs programmatically
- SIEM/Splunk ingestion and basic detection engineering
- Optional MFA hardening for SSH using PAM

---

## 👤 Author & Maintainer

**Tito Mazzetta** 
Security Engineering • Detection Engineering • Linux

- GitHub: https://github.com/titomazzetta  
- LinkedIn: https://www.linkedin.com/in/tito-carlo-piero-mazzetta-16a14264  

