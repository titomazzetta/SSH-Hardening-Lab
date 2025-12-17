# SSH Hardening Lab  
### Automated SSH Defense, Attack Simulation & SIEM-Ready Telemetry

![Status: Active](https://img.shields.io/badge/Status-Active-success)
![Security Engineering](https://img.shields.io/badge/Focus-Security%20Engineering-blue)
![Detection Engineering](https://img.shields.io/badge/Focus-Detection%20Engineering-orange)
![Linux](https://img.shields.io/badge/Platform-Linux-red)
![Splunk Ready](https://img.shields.io/badge/SIEM-Splunk-informational)

---

## 📌 Overview

This project demonstrates **end-to-end SSH security engineering** on a Debian Linux server, with a focus on **real-world detection, response, and observability** rather than purely preventive controls.

The lab was developed as both:

- A **portfolio-grade security engineering artifact**
- An **academic project** aligned with SSH hardening, logging, IP blocking, and SIEM ingestion requirements

The system is intentionally designed so that attack activity is **visible, measurable, and analyzable**, enabling clear before/after comparisons when defensive controls (such as MFA) are introduced.

The project integrates:

- 🔐 SSH hardening (multiple deployable profiles)
- 🚫 Automated brute-force blocking (Fail2Ban + UFW)
- 🔴 Red-team attack simulation (Hydra + Nmap)
- 🟦 Blue-team log parsing & enrichment (Python)
- 🧮 Stateful attacker risk scoring (`danger_score`)
- 📊 SIEM-ready CSV telemetry (Splunk compatible)
- 🔑 Optional SSH MFA using TOTP (Google Authenticator)

The workflow supports:

- **Reproducible experiments**
- **Pre- and post-control analysis**
- **Straightforward SIEM ingestion**
- **Clear security conclusions**

---

## 🎯 Lab Objectives

1. Harden a Debian SSH service against brute-force attacks  
2. Enable detailed logging of SSH authentication activity  
3. Automatically block malicious IPs using Fail2Ban  
4. Parse SSH logs into structured CSV datasets  
5. Simulate attacks from an external attacker machine  
6. Ingest telemetry into Splunk (or another SIEM)  
7. Measure the impact of MFA as an added control (optional but recommended)

---

## 🔥 Key Capabilities

### 🔐 SSH Hardening Profiles

Located in `configs/` and applied via `deploy.sh`:

- `sshd_config.example.lab_secure`  
  Hardened but lab-friendly (password + key auth, strong crypto, verbose logging)

- `sshd_config.example.mfa_profile`  
  SSH configuration integrated with PAM-based TOTP MFA

- `sshd_config.example.production_hardened`  
  Bastion-style configuration (key-only auth, stricter rate limits)

All profiles enforce:

- `PermitRootLogin no`
- Restricted users (`AllowUsers secadmin`)
- Tightened brute-force controls (`MaxAuthTries`, `LoginGraceTime`, `MaxStartups`)
- Disabled legacy features (X11 forwarding, TCP forwarding, tunnels)
- High-quality security telemetry (`LogLevel VERBOSE`)

---

## 🔍 Detection Engineering

Blue-team scripts live in `scripts/`.

### `parse_ssh_logs_geo.py`

- Reads `/var/log/auth.log`
- Extracts SSH authentication events:
  - Failed public key attempts
  - PAM authentication failures
  - Failed passwords
  - Successful logins
- Tracks per-IP and per-user state
- Computes a `danger_score` (0–100) based on failure volume
- Outputs normalized CSV telemetry suitable for SIEM ingestion

### `run_ssh_parser.sh`

- Requires root privileges (to read `auth.log`)
- Generates timestamped CSV reports
- Computes SHA-256 hashes for integrity
- Maintains a `ssh_events_latest.csv` symlink for convenience

**CSV fields exported:**

- `timestamp` (ISO8601)
- `src_ip`
- `src_port`
- `dst_port`
- `username`
- `event_status` (`failed` / `success`)
- `event_type`
- `fail_count`
- `total_attempts`
- `src_country`
- `src_city`
- `danger_score`

---

## 🧪 Attack Simulation (Red Team)

Scripts used for **authorized lab testing only**:

- `scan_ssh.sh`  
  Nmap-based SSH reconnaissance

- `ssh_bruteforce_test.sh`  
  Hydra-based brute-force simulation to:
  - Generate realistic attack logs
  - Trigger Fail2Ban
  - Produce detection telemetry

These scripts are intentionally simple and repeatable to ensure consistent test conditions.

---

## 📊 SIEM / Splunk Integration

CSV output from `run_ssh_parser.sh` is designed for **direct Splunk ingestion**.

Recommended index:

```text
ssh_security
```

Example SPL queries:

```spl
index=ssh_security
| stats count by src_ip
| sort -count
```

```spl
index=ssh_security danger_score>=70
| table timestamp src_ip username event_type fail_count danger_score
```

```spl
index=ssh_security
| stats count(eval(event_status="failed")) as failed
        count(eval(event_status="success")) as success
        by src_ip
```

---

## 🧠 Pre-MFA vs Post-MFA Experiment Design

This lab is structured to support **controlled security experimentation**.

- **Pre-MFA dataset**: baseline SSH behavior with hardened config + Fail2Ban
- **Post-MFA dataset**: SSH behavior after introducing TOTP MFA

Each parser run generates a **new timestamped CSV**, enabling direct comparison without overwriting historical data.

---

## 🚀 Quickstart

### Hardened Server (Debian)

```bash
sudo apt update && sudo apt install -y git
git clone https://github.com/titomazzetta/SSH-Hardening-Lab.git
cd SSH-Hardening-Lab
sudo ./deploy.sh
```

---

### Attacker Machine

```bash
sudo apt install -y nmap hydra
./scripts/scan_ssh.sh <SERVER_IP>
./scripts/ssh_bruteforce_test.sh <SERVER_IP> secadmin <wordlist>
```

---

### Log Parsing

```bash
sudo ./scripts/run_ssh_parser.sh
```

CSV output appears in:

```text
/home/secadmin/ssh_reports/
```

---

## 🔑 SSH Client Configuration (Recommended)

For convenience and repeatability, this project recommends **SSH host aliasing** on the client machine. This ensures the correct SSH identity is always presented to the hardened server without requiring the `-i` flag on each connection.

Add the following entry to your local SSH client configuration file:

```text
~/.ssh/config
```

```ssh
Host ssh-lab
  HostName 192.168.50.245
  User secadmin
  IdentityFile ~/.ssh/ssh_lab_ed25519
  IdentitiesOnly yes
```

Connect using:

```bash
ssh ssh-lab
```

**Notes:**
- SSH host aliasing is client-side only and does not modify the server.
- Each client machine must define its own alias.
- Alternatively, the identity file may be specified explicitly using `ssh -i`.

---

## 🔒 Ethics & Usage

- This project is for **educational and portfolio use**
- Only test systems you own or are authorized to access
- No secrets or credentials are stored in this repository

---

## ✅ Skills Demonstrated

- Linux SSH hardening
- Attack simulation & detection engineering
- Fail2Ban and automated response
- Log parsing and enrichment
- SIEM-ready telemetry design
- Security control evaluation (pre/post MFA)

---

## 👤 Author

**Tito Mazzetta**  
Security Engineering • Detection Engineering • Linux

- GitHub: https://github.com/titomazzetta  
- LinkedIn: https://www.linkedin.com/in/tito-carlo-piero-mazzetta-16a14264

---

## 📦 Artifact Export (CSV + Hash)

`run_ssh_parser.sh` writes reports into the repo for clean demos:

- `./screenshots/ssh_reports/ssh_events_<timestamp>.csv`
- `./screenshots/ssh_reports/ssh_events_<timestamp>.csv.sha256`
- `./screenshots/ssh_reports/ssh_events_latest.csv`
- `./screenshots/ssh_reports/ssh_events_latest.csv.sha256`

### Verify integrity (Linux)

```bash
cd ./screenshots/ssh_reports
sha256sum -c ssh_events_latest.csv.sha256
```

### Verify integrity (macOS)

```bash
cd ./screenshots/ssh_reports
shasum -a 256 -c ssh_events_latest.csv.sha256
```

### Copy off the server (from your Mac / attacker box)

```bash
scp -i ~/.ssh/<your_key> secadmin@<SERVER_IP>:~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv .
scp -i ~/.ssh/<your_key> secadmin@<SERVER_IP>:~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv.sha256 .
```

Note: `scp` requires the SSH server to have an SFTP subsystem enabled.  
The MFA profile includes:
`Subsystem sftp internal-sftp`.
