set -u
export PATH=/home/groy/cai/cai_env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# stop current backend gracefully
pkill -f 'uvicorn server:app --host 0.0.0.0 --port 8000' 2>/dev/null
sleep 3
# start fresh via run_server.sh
nohup bash /home/groy/cai/cyberorion/scripts/run_server.sh >/dev/null 2>&1 &
sleep 6
# wait for health
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 http://127.0.0.1:8000/api/status 2>/dev/null)
  if [ "$code" = "200" ]; then echo "backend UP after restart"; break; fi
  sleep 1
done
curl -s -m 5 http://127.0.0.1:8000/api/status | head -c 200
echo
echo "=== pid ==="
pgrep -f 'uvicorn server:app' | head -1