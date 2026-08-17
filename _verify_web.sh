#!/usr/bin/env bash
cd /home/groy/cai/cyberorion
echo "=== INDEX HTML ==="
curl -s -m 5 http://127.0.0.1:8000/ | head -c 600
echo ""
echo "=== DIST DIR ==="
ls web/dist/ 2>/dev/null | head
echo "=== ASSET TEST ==="
ASSET=$(curl -s -m 5 http://127.0.0.1:8000/ | grep -oE 'src="[^"]+\.js"' | head -1 | sed 's/src="//;s/"//')
echo "ASSET=$ASSET"
curl -s -m 5 -o /dev/null -w 'asset_status=%{http_code}\n' "http://127.0.0.1:8000/$ASSET"
echo "=== API check ==="
curl -s -m 5 -o /dev/null -w 'api_status=%{http_code}\n' http://127.0.0.1:8000/api/status