import sqlite3
db = "/home/groy/cai/cyberorion/logs/session_20260817_124111/telemetry.db"
c = sqlite3.connect(db)
c.row_factory = sqlite3.Row
print("=== TABLES ===")
print([r[0] for r in c.execute("select name from sqlite_master where type='table'")])
try:
    rows = c.execute("select * from attacks order by ts").fetchall()
    print("attacks:", len(rows))
    if rows:
        print("cols:", rows[0].keys())
        for r in rows[:15]:
            print("  ", dict(r))
except Exception as e:
    print("attacks err", e)
try:
    rows = c.execute("select * from alerts order by ts").fetchall()
    print("alerts:", len(rows))
    if rows:
        for r in rows:
            d=dict(r); print("  ", {k:d[k] for k in d})
except Exception as e:
    print("alerts err", e)