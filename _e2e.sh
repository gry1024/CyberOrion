set -u
echo "=== session start ==="
curl -s -m 15 -X POST http://127.0.0.1:8000/api/session/start | head -c 120
echo
sleep 6
echo "=== red start ==="
curl -s -m 10 -X POST http://127.0.0.1:8000/api/red/start | head -c 160
echo