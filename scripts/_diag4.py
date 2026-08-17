#!/usr/bin/env python3
import sqlite3, os
base = "/home/groy/cai/cyberorion/logs/session_20260817_030935"
con = sqlite3.connect(os.path.join(base, "telemetry.db"))
cur = con.cursor()
print("=== events schema ===")
for row in cur.execute("SELECT sql FROM sqlite_master WHERE name='events'"):
    print(row[0])
print("=== claim/verified mentions ===")
for row in cur.execute("SELECT ts, host, source, technique, substr(data,1,100) FROM events WHERE source IN ('tool_output','tool_call','attack','detection') AND (data LIKE '%claim%' OR data LIKE '%VERIFIED%' OR data LIKE '%referee%') LIMIT 25"):
    print(f"{row[0]:.1f} {row[1]:<12} {row[2]:<12} {row[3]:<10} {row[4]}")
con.close()
