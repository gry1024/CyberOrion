import json, urllib.request
def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=5))
    except Exception as ex:
        return {"err": str(ex)}
st = get("http://127.0.0.1:8000/api/status")
print("red_running:", st.get("red_running"), "blue_running:", st.get("blue_running"))
evs = get("http://127.0.0.1:8000/api/events?limit=100")
if isinstance(evs, list):
    from collections import Counter
    c = Counter(e.get("type") for e in evs)
    print("event types:", dict(c))
    for e in evs[:8]:
        print("  ", e.get("type"), e.get("host"), str(e.get("action") or e.get("technique"))[:40])
else:
    print("events err", evs)