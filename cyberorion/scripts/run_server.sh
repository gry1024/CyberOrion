#!/usr/bin/env bash
# CyberOrion backend launcher (run under watchdog).
set -u
export PATH=/home/groy/cai/cai_env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /home/groy/cai/cyberorion || exit 1
LOG=/home/groy/cai/cyberorion/logs/server.log
ERR=/home/groy/cai/cyberorion/logs/server.err.log
echo "[run_server] $(date '+%F %T') starting uvicorn on :8000" >> "$LOG"
exec /home/groy/cai/cai_env/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8000 >> "$LOG" 2>>"$ERR"