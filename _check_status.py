import json, urllib.request, time
time.sleep(6)
d = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/status", timeout=5))
print("session_active", d.get("session_active"), "scenario", d.get("scenario"), "round", d.get("round"))