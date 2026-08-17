sleep 60
echo "=== blue status ==="
curl -s -m 5 http://127.0.0.1:8000/api/status
echo
echo "=== alerts (count + technique) ==="
curl -s -m 5 http://127.0.0.1:8000/api/alerts | grep -o '"technique":"T[0-9.]*"' | sort | uniq -c
echo "=== latest session dir ==="
ls -td /home/groy/cai/cyberorion/logs/session_* | head -1