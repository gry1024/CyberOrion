#!/usr/bin/env python3
import sqlite3, os
base = "/home/groy/cai/cyberorion/logs/session_20260817_030935"
con = sqlite3.connect(os.path.join(base, "telemetry.db"))
cur = con.cursor()
print("=== claim/verify related events ===")
for row in cur.execute("SELECT ts, source, technique, substr(evidence,1,120) FROM events WHERE source LIKE '%claim%' OR source LIKE '%referee%' OR evidence LIKE '%VERIFIED%' OR evidence LIKE '%claim%' LIMIT 20"):
    print(f"{row[0]:.1f} {row[1]:<14} {row[2]:<10} {row[3]}")
print("=== events by source ===")
for row in cur.execute("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY 2 DESC LIMIT 15"):
    print(row)
print("=== attacks: how many success=1 ===")
for row in cur.execute("SELECT success, COUNT(*) FROM attacks GROUP BY success"):
    print("success=", row[0], "count=", row[1])
con.close()
