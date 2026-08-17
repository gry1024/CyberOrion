echo "=== status ==="
curl -s -m 5 http://127.0.0.1:8000/api/status
echo
echo "=== alerts ==="
curl -s -m 5 http://127.0.0.1:8000/api/alerts | head -c 700
echo
echo "=== blue running? ==="
curl -s -m 5 http://127.0.0.1:8000/api/status | grep -o '"blue_running":[a-z]*'