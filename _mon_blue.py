import json, urllib.request, time
alerts = 0
for i in range(8):
    try:
        d = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/events?limit=150", timeout=5))
        if isinstance(d, list):
            definitions = [e for e in d if e.get("type") in ("detection","alert","finding","alerts")]
            alerts = len([e for e in d if e.get("type")=="detection" or e.get("severity")])
        print("poll", i, "events", len(d) if isinstance(d,list) else d, "detection-ish", alerts)
        # check for error events
        errs = [e for e in (d if isinstance(d,list) else []) if str(e.get("type"))=="error"]
        if errs:
            print("   ERRORS:", errs[:3])
    except Exception as ex:
        print("poll", i, "err", ex)
    time.sleep(20)