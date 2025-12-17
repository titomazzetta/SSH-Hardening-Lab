secadmin@ssh-lab:~$ wc -l ~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv
1 /home/secadmin/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv
secadmin@ssh-lab:~$ nano ~/SSH-Hardening-Lab/scripts/parse_ssh_logs_geo.py
secadmin@ssh-lab:~$ cd ~/SSH-Hardening-Lab
cp -v scripts/parse_ssh_logs_geo.py scripts/parse_ssh_logs_geo.py.bak
'scripts/parse_ssh_logs_geo.py' -> 'scripts/parse_ssh_logs_geo.py.bak'
secadmin@ssh-lab:~/SSH-Hardening-Lab$ nano scripts/parse_ssh_logs_geo.py
secadmin@ssh-lab:~/SSH-Hardening-Lab$ wc -l ~/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv
1 /home/secadmin/SSH-Hardening-Lab/screenshots/ssh_reports/ssh_events_latest.csv
secadmin@ssh-lab:~/SSH-Hardening-Lab$ nano scripts/parse_ssh_logs_geo.py
secadmin@ssh-lab:~/SSH-Hardening-Lab$ sudo python3 scripts/parse_ssh_logs_geo.py --log /var/log/auth.log --out /tmp/ssh_events_test.csv
wc -l /tmp/ssh_events_test.csv
tail -n 15 /tmp/ssh_events_test.csv
[sudo] password for secadmin: 
Sorry, try again.
[sudo] password for secadmin: 
[+] Parsed 421 events -> /tmp/ssh_events_test.csv
422 /tmp/ssh_events_test.csv
2025-12-17T16:09:37.701879-05:00,192.168.50.94,61544,,secadmin,info,publickey,44,210,,,53
2025-12-17T16:09:37.717669-05:00,192.168.50.94,61544,,secadmin,info,mfa,44,211,,,50
2025-12-17T16:09:42.031505-05:00,192.168.50.94,,,secadmin,fail,pam,45,212,,,80
2025-12-17T16:09:42.032381-05:00,192.168.50.94,61544,,secadmin,fail,mfa,46,213,,,70
2025-12-17T16:09:42.041595-05:00,192.168.50.94,61544,,secadmin,info,mfa,46,214,,,50
2025-12-17T16:09:45.285752-05:00,192.168.50.94,61544,,secadmin,info,mfa,46,215,,,50
2025-12-17T16:09:53.191909-05:00,192.168.50.94,61544,,secadmin,info,mfa,46,216,,,50
2025-12-17T16:09:53.193301-05:00,192.168.50.94,61544,,secadmin,success,mfa,46,217,,,50
2025-12-17T16:13:33.244897-05:00,192.168.50.94,61708,22,,info,connection,46,218,,,50
2025-12-17T16:13:33.329529-05:00,192.168.50.94,61708,,secadmin,info,publickey,46,219,,,53
2025-12-17T16:13:33.329564-05:00,192.168.50.94,61708,,secadmin,info,publickey,46,220,,,53
2025-12-17T16:13:33.344580-05:00,192.168.50.94,61708,,secadmin,info,mfa,46,221,,,50
2025-12-17T16:13:35.706077-05:00,192.168.50.94,61708,,secadmin,info,mfa,46,222,,,50
2025-12-17T16:13:43.752656-05:00,192.168.50.94,61708,,secadmin,info,mfa,46,223,,,50
2025-12-17T16:13:43.752854-05:00,192.168.50.94,61708,,secadmin,success,mfa,46,224,,,50
secadmin@ssh-lab:~/SSH-Hardening-Lab$ ./scripts/run_ssh_parser.sh
wc -l screenshots/ssh_reports/ssh_events_latest.csv
tail -n 15 screenshots/ssh_reports/ssh_events_latest.csv
[*] Running SSH log parser...
    Parser:      /home/secadmin/SSH-Hardening-Lab/scripts/parse_ssh_logs_geo.py
    Logfile:     /var/log/auth.log
    Authoritative output: /home/secadmin/ssh_reports/ssh_events_20251217_163729.csv
    UX copies:   /home/secadmin/SSH-Hardening-Lab/screenshots/ssh_reports
usage: parse_ssh_logs_geo.py [-h] [--log LOG] --out OUT [--geo-cache GEO_CACHE]
parse_ssh_logs_geo.py: error: the following arguments are required: --out
1 screenshots/ssh_reports/ssh_events_latest.csv
timestamp,src_ip,src_port,dst_port,username,event_status,event_type,fail_count,total_attempts,src_country,src_city,danger_score
secadmin@ssh-lab:~/SSH-Hardening-Lab$ nano scripts/run_ssh_parser.sh







secadmin@ssh-lab:~/SSH-Hardening-Lab$ nano scripts/run_ssh_parser.sh
secadmin@ssh-lab:~/SSH-Hardening-Lab$ nano scripts/run_ssh_parser.sh

  GNU nano 8.4                                                                         scripts/run_ssh_parser.sh *                                                                                 
OUT_CSV="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv"
OUT_HASH="${AUTHORITATIVE_DIR}/ssh_events_${TIMESTAMP}.csv.sha256"

# --- logfile detection / override ---
if [[ -n "${LOGFILE:-}" ]]; then
  DETECTED_LOGFILE="${LOGFILE}"
elif [[ -f /var/log/auth.log ]]; then
  DETECTED_LOGFILE="/var/log/auth.log"
elif [[ -f /var/log/secure ]]; then
  DETECTED_LOGFILE="/var/log/secure"
else
  echo "[!] Could not find auth log at /var/log/auth.log or /var/log/secure."
  echo "[!] Set manually, e.g.: LOGFILE=/path/to/log ./scripts/run_ssh_parser.sh"
  exit 1
fi

echo "[*] Running SSH log parser..."
echo "    Parser:      ${PARSER}"
echo "    Logfile:     ${DETECTED_LOGFILE}"
echo "    Authoritative output: ${OUT_CSV}"
echo "    UX copies:   ${UX_DIR}"

# Prefer non-interactive sudo if available
SUDO=(sudo -n)
if ! sudo -n true 2>/dev/null; then
  echo "[!] Non-interactive sudo not configured (NOPASSWD not set)."
  echo "[*] Falling back to interactive sudo (you may be prompted)..."
  SUDO=(sudo)
fi

# Run parser with sudo (needed to read auth logs), write output to user-owned path
GEO_CACHE="${SCRIPT_DIR}/geo_cache.json"
"${SUDO[@]}" python3 "${PARSER}" --log "${DETECTED_LOGFILE}" --out "${OUT_CSV}" --geo-cache "${GEO_CACHE}"

if [[ ! -f "${OUT_CSV}" ]]; then
  echo "[!] Expected CSV not found: ${OUT_CSV}"
  exit 1
fi

echo "[*] Computing SHA-256 hash (portable verification on Mac/Linux)..."
(
  cd "${AUTHORITATIVE_DIR}"
  # IMPORTANT: write hash with basename only so `shasum -a 256 -c` works after SCP
  sha256sum "$(basename "${OUT_CSV}")" > "$(basename "${OUT_HASH}")"
)

# Maintain "latest" symlinks in the authoritative directory
ln -sf "$(basename "${OUT_CSV}")"  "${AUTHORITATIVE_DIR}/ssh_events_latest.csv"
ln -sf "$(basename "${OUT_HASH}")" "${AUTHORITATIVE_DIR}/ssh_events_latest.csv.sha256"



# Copy newest artifacts into repo screenshots/ for UX / demos (real files, no symlinks)
