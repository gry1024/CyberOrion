import json, urllib.request, time, sqlite3, glob, os
def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=5))
    except Exception as ex:
        return {"err": str(ex)}
# wait blue to finish
waited = 0
while waited < 240:
    st = get("http://127.0.0.1:8000/api/status")
    if st.get("err"):
        print("backend down?", st); break
    if not st.get("blue_running"):
        print(f"blue finished at t+{waited}s; blue_history_count={st.get('blue_history_count')}")
        break
    if waited % 30 == 0:
        print(f"t+{waited}s blue running")
    time.sleep(15)
    waited += 15
else:
    print("timeout waiting for blue")
# dump alerts in current session
dirs = sorted(glob.glob("/home/groy/cai/cyberorion/logs/session_*"), key=os.path.getmtime, reverse=True)
cur = dirs[0]
print("session:", cur)
db = os.path.join(cur, "telemetry.db")
c = sqlite3.connect(db); c.row_factory = sqlite3.Row
for r in c.execute("select id,host,technique,verdict,confidence,status from alerts order by id"):
    print("  alert", dict(r))
na=c.execute("select count(*) c from attacks").fetchone()["c"]
print("total attacks:", na)
c.close()