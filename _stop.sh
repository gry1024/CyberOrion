set -u
echo "=== stop session (generate report/metrics) ==="
curl -s -m 15 -X POST http://127.0.0.1:8000/api/session/stop | head -c 300
echo
sleep 5
echo "=== latest session dir files ==="
ls -la /home/groy/cai/cyberorion/logs/session_20260817_125054/