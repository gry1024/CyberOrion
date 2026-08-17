import json, urllib.request, time
def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=5))
    except Exception as ex:
        return {"err": str(ex)}
waited = 0
while waited < 300:
    st = get("http://127.0.0.1:8000/api/status")
    if st.get("err"):
        print("backend down?", st); break
    if not st.get("red_running"):
        print(f"red finished at t+{waited}s; red_history_count={st.get('red_history_count')}")
        break
    if waited % 30 == 0:
        print(f"t+{waited}s red still running")
    time.sleep(15)
    waited += 15
else:
    print("timeout waiting for red")