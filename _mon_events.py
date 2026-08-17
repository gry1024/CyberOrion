import json, urllib.request, time, sys
# sample /api/events from telemetry to confirm red attacking
for i in range(6):
    try:
        d = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/events?limit=30", timeout=5))
        print("poll", i, "events:", len(d) if isinstance(d, list) else d)
        if isinstance(d, list):
            for e in d[:6]:
                print("   ", e.get("type"), e.get("host"), str(e.get("action") or e.get("src") or "")[:60])
        if isinstance(d, list) and len(d) > 0:
            break
    except Exception as ex:
        print("poll", i, "err", ex)
    time.sleep(15)