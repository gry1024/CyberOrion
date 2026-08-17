sleep 90
echo "=== blue still running? ==="
curl -s -m 5 http://127.0.0.1:8000/api/status | grep -o '"blue_running":[a-z]*'
echo "=== alerts count ==="
curl -s -m 5 http://127.0.0.1:8000/api/alerts | grep -c '"host":' 
echo "=== score ==="
curl -s -m 5 http://127.0.0.1:8000/api/score
echo