# SSH Hardening Lab  
### Automated SSH Defense, Attack Simulation & SIEM-Ready Telemetry

![Status: Active](https://img.shields.io/badge/Status-Active-success)
![Security Engineering](https://img.shields.io/badge/Focus-Security%20Engineering-blue)
![Detection Engineering](https://img.shields.io/badge/Focus-Detection%20Engineering-orange)
![Linux](https://img.shields.io/badge/Platform-Linux-red)
![Splunk Ready](https://img.shields.io/badge/SIEM-Splunk-informational)

---

## 📌 Overview

This project demonstrates **end-to-end SSH security engineering** on a Debian Linux server, with an emphasis on **detection, response, and observability** (not just preventive hardening).

It is designed as both:

- A **portfolio-grade security engineering artifact** for employers
- An **academic lab** aligned with SSH hardening, logging, blocking, and SIEM ingestion requirements

The system is intentionally built so attack activity is **visible, measurable, and analyzable**, enabling clean pre/post comparisons when adding stronger controls (e.g., MFA).

### What’s included

- 🔐 SSH hardening (multiple deployable `sshd_config` profiles)
- 🚫 Automated brute-force blocking (Fail2Ban + optional UFW rules)
- 🔴 Red-team simulation (Nmap + Hydra, lab-only)
- 🟦 Blue-team parsing & enrichment (Python)
- 🧮 Stateful attacker scoring (`danger_score`, 0–100)
- 📊 SIEM-ready CSV telemetry + **SHA-256 integrity hashes**
- 🔑 Optional SSH MFA using TOTP (Google Authenticator)

---

## 🎯 Lab Objectives

1. Harden an SSH service against brute-force and user-enumeration behavior  
2. Generate high-fidelity authentication logging for analysis  
3. Automatically block malicious IPs using Fail2Ban  
4. Parse and normalize SSH logs into SIEM-ready datasets  
5. Simulate attacks from an external attacker machine (lab only)  
6. Ingest telemetry into Splunk (or another SIEM)  
7. Optionally measure the impact of MFA as an additional control  

---

## 🧱 Repository Structure

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
├── scripts/
│   ├── parse_ssh_logs_geo.py
│   ├── run_ssh_parser.sh
│   ├── scan_ssh.sh
│   ├── ssh_bruteforce_test.sh
│   └── nmap_scan_examples.txt
│
└── screenshots/
    └── ssh_reports/   (generated demo artifacts; gitignored)
```

---

## 🔥 Key Capabilities

### 🔐 SSH Hardening Profiles

Profiles live in `configs/` and are applied via `deploy.sh`:

- `sshd_config.example.lab_secure`  
  Hardened but lab-friendly (key + password allowed, strong crypto, verbose logging)

- `sshd_config.example.mfa_profile`  
  SSH configuration wired for PAM-based TOTP MFA

- `sshd_config.example.production_hardened`  
  Bastion-style posture (key-only, stricter limits)

All profiles enforce:

- `PermitRootLogin no`
- Restricted users (default: `AllowUsers secadmin`)
- Tightened brute-force controls (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`)
- Disabled legacy/high-risk features (X11 forwarding, TCP forwarding, tunnels)
- High-quality security telemetry (`LogLevel VERBOSE`)

---

## 🔍 Detection Engineering

Blue-team components live in `scripts/`.

### `parse_ssh_logs_geo.py`

- Reads the SSH auth log (typically `/var/log/auth.log`)
- Extracts SSH authentication events:
  - failed login attempts
  - invalid user attempts
  - successful logins
- Tracks per-IP and per-user state
- Computes `danger_score` (0–100)
- Outputs normalized CSV telemetry suitable for SIEM ingestion

### `run_ssh_parser.sh`

- Wrapper that **handles sudo internally** (to read auth logs)
- Generates timestamped CSV reports
- Computes SHA-256 hashes for integrity
- Maintains `ssh_events_latest.csv` symlinks for convenience
- Produces:
  - **Authoritative output** in `~/ssh_reports/`
  - **Demo/UX copies** in `./screenshots/ssh_reports/` (useful for Splunk upload and screenshots)

#### CSV fields exported

- `timestamp` (ISO-8601)
- `src_ip`
- `src_port`
- `dst_port`
- `username`
- `event_type` (`failed_login`, `invalid_user`, `successful_login`)
- `event_status` (`info`, `fail`, `success`)
- `fail_count`
- `total_attempts`
- `src_country`
- `src_city`
- `danger_score`

---

## 🧪 Attack Simulation (Red Team)

Scripts are for **authorized lab testing only**:

- `scripts/scan_ssh.sh`  
  Nmap-based SSH reconnaissance

- `scripts/ssh_bruteforce_test.sh`  
  Hydra-based brute-force simulation to:
  - generate realistic attack logs
  - trigger Fail2Ban
  - produce detection telemetry

These scripts are intentionally simple and repeatable to ensure consistent test conditions.

---

## 📊 SIEM / Splunk Integration

The CSV output from `run_ssh_parser.sh` is designed for **direct Splunk ingestion**.

Recommended Splunk index:

```text
ssh_security
```

Example SPL queries:

**Top attacking IPs**
```spl
index=ssh_security
| stats count as attempts by src_ip src_country src_city
| sort -attempts
```

**High-risk behavior**
```spl
index=ssh_security danger_score>=70
| table timestamp src_ip username event_type fail_count danger_score src_country
```

**Failed vs successful per IP**
```spl
index=ssh_security
| stats count(eval(event_status="fail")) as failed
        count(eval(event_status="success")) as success
        by src_ip
| where failed > 0
| sort -failed
```

---

## 🧠 Pre-MFA vs Post-MFA Experiment Design

This lab supports **controlled security experimentation**:

- **Pre-MFA dataset**: hardened SSH + Fail2Ban baseline
- **Post-MFA dataset**: SSH after introducing TOTP MFA

Each parser run generates a **new timestamped CSV** (no overwrites), enabling clear comparisons over time.

---

## 🚀 Quickstart

### 1) Hardened Server (Debian)

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/titomazzetta/SSH-Hardening-Lab.git
cd SSH-Hardening-Lab
sudo ./deploy.sh
```

### 2) Attacker Machine (separate host/VM)

```bash
sudo apt update && sudo apt install -y nmap hydra
./scripts/scan_ssh.sh <SERVER_IP>
./scripts/ssh_bruteforce_test.sh <SERVER_IP> secadmin <WORDLIST_PATH>
```

### 3) Parse logs and generate telemetry (on server)

```bash
./scripts/run_ssh_parser.sh
```

Outputs:

- Authoritative: `~/ssh_reports/`
- Demo/UX copies: `./screenshots/ssh_reports/`

---

## 🔑 SSH Client Configuration (Recommended)

For convenience and repeatability, define an SSH host alias on your client machine:

```text
~/.ssh/config
```

```ssh
Host ssh-lab
  HostName <SERVER_IP>
  User secadmin
  IdentityFile ~/.ssh/<your_key>
  IdentitiesOnly yes
```

Connect with:

```bash
ssh ssh-lab
```

---

## 📦 Artifact Export & Integrity Verification

`run_ssh_parser.sh` generates demo artifacts in:

- `./screenshots/ssh_reports/ssh_events_<timestamp>.csv`
- `./screenshots/ssh_reports/ssh_events_<timestamp>.csv.sha256`
- `./screenshots/ssh_reports/ssh_events_latest.csv` (symlink)
- `./screenshots/ssh_reports/ssh_events_latest.csv.sha256` (symlink)

### Verify integrity (recommended: on the Debian server)

```bash
cd ./screenshots/ssh_reports
sha256sum -c ssh_events_latest.csv.sha256
```

### Export off the server (from your Mac / attacker box)

```bash
scp -i ~/.ssh/<your_key> secadmin@<SERVER_IP>:~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv .
scp -i ~/.ssh/<your_key> secadmin@<SERVER_IP>:~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv.sha256 .
```

> Note: `scp`/SFTP requires an SFTP subsystem. The MFA profile includes `Subsystem sftp internal-sftp`.

---

## 🔒 Ethics & Usage

- This project is for **educational and portfolio** use  
- Only test systems you own or are explicitly authorized to assess  
- No secrets, credentials, or private keys should ever be committed  

---

## ✅ Skills Demonstrated

- Linux SSH hardening and secure configuration management  
- Brute-force detection and automated response (Fail2Ban)  
- Red-team simulation for generating detection telemetry (lab-safe)  
- Log parsing, enrichment, and normalization for SIEM ingestion  
- Integrity verification of exported telemetry (SHA-256)  
- Control evaluation methodology (pre/post MFA)  

---

## 📘 Additional Documentation

- Design & Threat Model: `docs/design_and_threat_model.md`  
- Step-by-step Playbook: `docs/ssh_hardening_playbook.md`  

---

## 👤 Author

**Tito Mazzetta**  
Security Engineering • Detection Engineering • Linux

- GitHub: https://github.com/titomazzetta  
- LinkedIn: https://www.linkedin.com/in/tito-carlo-piero-mazzetta-16a14264
