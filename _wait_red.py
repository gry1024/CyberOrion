import json, urllib.request, time

def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=5))
    except Exception:
        return None

# wait for red attacks to accumulate (next session events)
sess = get("http://127.0.0.1:8000/api/status")
print("red_running start:", sess.get("red_running"))

# poll current telemetry via /api/events limit high
attacks_seen = 0
waited = 0
while waited < 180:
    evs = get("http://127.0.0.1:8000/api/events?limit=200")
    if isinstance(evs, list):
        atks = [e for e in evs if e.get("type") == "attack"]
        attacks_seen = len(atks)
        print(f"t+{waited}s attacks={attacks_seen}")
        if attacks_seen >= 5:
            break
    time.sleep(15)
    waited += 15

print("attacks seen:", attacks_seen)