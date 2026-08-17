import json, urllib.request, time
def get(url):
    try:
        return json.load(urllib.request.urlopen(url, timeout=8))
    except Exception as ex:
        return {"err": str(ex)}
time.sleep(5)
st = get("http://127.0.0.1:8000/api/status")
print("status:", st if st else None)