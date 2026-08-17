import sqlite3, glob, os, time
dirs = sorted(glob.glob("/home/groy/cai/cyberorion/logs/session_*"), key=os.path.getmtime, reverse=True)
cur = dirs[0]
db = os.path.join(cur, "telemetry.db")
c = sqlite3.connect(db); c.row_factory = sqlite3.Row
n1 = c.execute("select count(*) c from attacks").fetchone()["c"]
c.close()
time.sleep(20)
c = sqlite3.connect(db); c.row_factory = sqlite3.Row
n2 = c.execute("select count(*) c, max(ts) mt from attacks").fetchone()
c.close()
print("attacks at t0:", n1)
print("attacks after 20s:", n2["c"], "max_ts", n2["mt"])