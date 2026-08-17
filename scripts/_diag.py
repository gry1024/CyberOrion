#!/usr/bin/env python3
import sqlite3, os, glob
base = "/home/groy/cai/cyberorion/logs/session_20260817_030935"
db = os.path.join(base, "telemetry.db")
con = sqlite3.connect(db)
cur = con.cursor()
print("=== ATTACKS BY TARGET ===")
for row in cur.execute("SELECT target, technique, action, COUNT(*) FROM attacks GROUP BY target, technique, action ORDER BY 4 DESC LIMIT 40"):
    print(row)
print("=== ALERTS BY HOST ===")
for row in cur.execute("SELECT host, technique, verdict, COUNT(*) FROM alerts GROUP BY host, technique, verdict"):
    print(row)
print("=== SCHEMA attacks ===")
for row in cur.execute("SELECT sql FROM sqlite_master WHERE name='attacks'"):
    print(row[0])
print("=== SCHEMA alerts ===")
for row in cur.execute("SELECT sql FROM sqlite_master WHERE name='alerts'"):
    print(row[0])
con.close()
