echo "=== session dir contents ==="
ls -la /home/groy/cai/cyberorion/logs/session_20260817_124111/
echo "=== memory ==="
free -h
echo "=== backend uptime / restrarts ==="
ps -o pid,etime,cmd -p 61505 2>/dev/null
grep -c 'backend down' /home/groy/cai/cyberorion/logs/watchdog.log 2>/dev/null