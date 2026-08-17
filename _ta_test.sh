#!/usr/bin/env bash
cd /home/groy/cai/cyberorion
echo "=== TRAFFIC ANALYZE (SSE) ==="
curl -s -m 40 -N -X POST http://127.0.0.1:8000/api/traffic/analyze \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"session_20260817_030935"}' | head -c 1500
echo ""
echo "=== check files ==="
ls -la logs/session_20260817_030935/