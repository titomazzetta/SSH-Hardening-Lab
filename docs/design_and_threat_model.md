# SSH Hardening Lab – Design & Threat Model

## 1. High-Level Design

This lab models a **single hardened SSH server** exposed to an attacker machine on the same network (or host-only / NAT segment).

- **Hardened SSH Server (Debian):**
  - Runs OpenSSH, Fail2Ban, UFW
  - Uses one of several hardened `sshd_config` profiles
  - Produces authentication logs in `/var/log/auth.log`
  - Exports enriched telemetry via a Python parser to CSV

- **Attacker Machine:**
  - Runs Nmap for reconnaissance
  - Runs Hydra for brute-force attempts (lab only)
  - Connects to the SSH server over the network

- **Analyst / SIEM:**
  - Ingests CSV data (`ssh_events_*.csv`) into Splunk
  - Runs detection queries and visualizes high-risk behavior

This is a **red/blue team micro-lab** focused on SSH.

---

## 2. Threat Model

### Assets

- SSH service on the Debian server
- System integrity and availability
- Credentials for the `secadmin` user (and any other SSH-capable accounts)
- Telemetry integrity (logs + exported CSV)

### Adversary Capabilities

The attacker is assumed to:

- Discover the SSH service via **Nmap** scanning
- Attempt password guessing and credential stuffing via **Hydra**
- Enumerate users by trying common usernames
- Potentially bypass basic controls by spreading attempts over time

### Security Goals

1. **Confidentiality**  
   - Prevent unauthorized access over SSH.

2. **Integrity**  
   - Maintain integrity of logs and exported CSVs (hashing).

3. **Availability**  
   - Keep SSH available to legitimate users while rate-limiting attackers.

4. **Detectability**  
   - Log all relevant SSH auth events with enough context for analysis.
   - Generate enriched telemetry suitable for SIEM ingestion.

### Non-Goals (Out of Scope)

- Kernel exploitation or privilege escalation beyond SSH compromise
- Lateral movement inside a larger enterprise network
- Post-exploitation persistence mechanisms

---

## 3. Controls Implemented

### 3.1 SSH Hardening

- `PermitRootLogin no`
- Strong cryptographic algorithms (KEX, Ciphers, MACs)
- `AllowUsers secadmin` (principle of least privilege)
- Limited authentication attempts (`MaxAuthTries`, `LoginGraceTime`)
- Disabled forwarding/tunneling: `X11Forwarding no`, `AllowTcpForwarding no`

### 3.2 Network & Rate Limiting

- UFW firewall providing default-deny inbound policy (config example provided)
- Fail2Ban jail monitoring `/var/log/auth.log` for repeated failures
- Automatic banning of IPs with excessive failed attempts

### 3.3 Logging & Telemetry

- `LogLevel VERBOSE` in sshd_config for richer security logs
- Python log parser extracting:
  - timestamps
  - source IP / port
  - username
  - event type + status
  - per-IP/user fail counts
  - geo-IP country/city
  - computed `danger_score`

- SHA-256 hash files for CSV integrity (`*.sha256`)

### 3.4 Optional MFA

- MFA profile for sshd (`sshd_config.example.mfa_profile`)
- PAM integration via `pam_google_authenticator.so`
- 2-factor login: SSH key + TOTP

---

## 4. Example Attack Scenarios

1. **Brute-Force Against `secadmin`**
   - Attacker runs Hydra with a common wordlist.
   - Server logs failed attempts; Fail2Ban bans IP.
   - Parser converts logs to CSV; Splunk surfaces high `danger_score` for that IP.

2. **User Enumeration via Invalid Users**
   - Attacker tries `root`, `admin`, `test`, `user`, `guest`.
   - Logged as `invalid user` events.
   - Parser classifies event type as `invalid_user`; Splunk uses SPL to find enumeration patterns.

3. **Successful Login (with Legit or Compromised Key)**
   - Logged as `Accepted` events.
   - Parser marks `event_status=success`, `event_type=successful_login`.
   - SIEM can correlate successful logins from previously noisy IPs.

4. **MFA-Enabled Scenario**
   - SSH login requires both key and TOTP.
   - Incorrect TOTP attempts generate additional failures.
   - Detection rules can flag repeated MFA failures per user/IP.

---

## 5. Assumptions & Limitations

- Logs are local to the SSH server (no remote syslog forwarding in this lab).
- Geo-IP is performed using an external free API (ip-api.com); offline environments will not get geo data.
- Hydra attacks are performed only within a controlled lab network.
- This lab does not attempt to cover kernel hardening, full CIS benchmarks, or OS-wide hardening.

---

## 6. Future Enhancements

- Add remote syslog / log forwarding to a central collector.
- Add JSON log export in addition to CSV.
- Add more advanced risk scoring (time-based patterns, country allowlists, etc.).
- Export Splunk dashboards as XML/JSON for easier replication.
- Integrate with another SIEM (e.g., ELK / OpenSearch) as a second target.



## Operational Note: Artifact Export Over SCP/SFTP

In an MFA + key-only posture, exporting parser artifacts typically uses `scp`/SFTP. Ensure:

- The SSH server advertises an SFTP subsystem (`Subsystem sftp internal-sftp`), and
- The MFA profile does not disable SFTP unintentionally.

The project’s hash files are generated using a **relative filename** so integrity checks work on both Linux (`sha256sum -c`) and macOS (`shasum -a 256 -c`) after export.
