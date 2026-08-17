#!/usr/bin/env bash
# CyberOrion watchdog: keeps the backend alive, restarts on crash.
# Usage: nohup bash scripts/watchdog.sh > /dev/null 2>&1 &
export PATH=/home/groy/cai/cai_env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE=/home/groy/cai/cyberorion
LOG="$BASE/logs/watchdog.log"
while true; do
  if ! pgrep -f 'uvicorn server:app --host 0.0.0.0 --port 8000' > /dev/null 2>&1; then
    echo "[watchdog] $(date '+%F %T') backend down, starting..." >> "$LOG"
    nohup bash "$BASE/scripts/run_server.sh" >> "$LOG" 2>&1 &
    for i in $(seq 1 60); do
      if curl -sf -m 2 http://127.0.0.1:8000/api/status > /dev/null 2>&1; then break; fi
      sleep 1
    done
  fi
  sleep 5
done