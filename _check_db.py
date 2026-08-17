import sqlite3, glob, os
dirs = sorted(glob.glob("/home/groy/cai/cyberorion/logs/session_*"), key=os.path.getmtime, reverse=True)
cur = dirs[0]
print("session dir:", cur)
db = os.path.join(cur, "telemetry.db")
if os.path.exists(db):
    c = sqlite3.connect(db); c.row_factory = sqlite3.Row
    n = c.execute("select count(*) c from attacks").fetchone()["c"]
    print("attacks in current session telemetry:", n)
    for r in c.execute("select target,technique,action,success from attacks order by id"):
        print("  ", dict(r))
    na = c.execute("select count(*) c from alerts").fetchone()["c"]
    print("alerts:", na)
    c.close()
else:
    print("no telemetry.db yet")