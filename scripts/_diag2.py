#!/usr/bin/env python3
import sqlite3, os, subprocess, json
base = "/home/groy/cai/cyberorion/logs/session_20260817_030935"
con = sqlite3.connect(os.path.join(base, "telemetry.db"))
cur = con.cursor()
print("=== ATTACKS ts/target/tech/action ===")
for row in cur.execute("SELECT ts, target, technique, action, success FROM attacks ORDER BY ts"):
    print(f"{row[0]:.1f}  {row[1]:<14} {row[2]:<10} {row[3]} success={row[4]}")
print("=== ALERTS ts/host/tech/verdict ===")
for row in cur.execute("SELECT ts, host, technique, verdict, confidence FROM alerts ORDER BY ts"):
    print(f"{row[0]:.1f}  {row[1]:<12} {row[2]:<10} {row[3]} conf={row[4]}")
con.close()
print("=== CONTAINER IPs ===")
for c in ["cyberorion_dvwa","cyberorion_weak_ssh","cyberorion_log4j","cyberorion_webgoat","cyberorion_vampi"]:
    r = subprocess.run(["docker","inspect","-f","{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",c], capture_output=True, text=True)
    print(c, "->", r.stdout.strip())
print("=== SCENARIO CONFIG ===")
import sys
sys.path.insert(0, "/home/groy/cai/cyberorion")
try:
    from cyberorion.scenarios import load_scenario
    sc = load_scenario()
    for name, t in (sc.targets or {}).items():
        svcs = {}
        for sname, s in (t.services or {}).items():
            svcs[sname] = {"proto": getattr(s,"proto",""), "port": getattr(s,"port",""), "host_port": getattr(s,"host_port","")}
        print(name, "| ip=", getattr(t,"ip",""), "| container=", getattr(t,"container",""), "| services=", json.dumps(svcs, ensure_ascii=False))
except Exception as e:
    print("SCENARIO ERROR:", e)
