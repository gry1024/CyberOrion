import json, urllib.request, time
hosts = {}
for i in range(10):
    try:
        d = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/events?limit=100", timeout=5))
        if isinstance(d, list):
            for e in d:
                h = e.get("host") or "?"
                hosts.setdefault(h, 0)
                hosts[h] += 1
        print("poll", i, "total_events", sum(hosts.values()), "hosts", dict(list(hosts.items())[-5:]))
        if sum(hosts.values()) >= 20:
            break
    except Exception as ex:
        print("poll", i, "err", ex)
    time.sleep(20)