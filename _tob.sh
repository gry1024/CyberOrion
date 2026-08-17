set -u
echo "=== stop red ==="
curl -s -m 10 -X POST http://127.0.0.1:8000/api/red/stop
echo
sleep 3
echo "=== start blue ==="
curl -s -m 10 -X POST http://127.0.0.1:8000/api/blue/start | head -c 180
echo