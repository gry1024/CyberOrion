import json, urllib.request
# check sessions API lists this session and whether report/metrics exist
sessions = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/sessions", timeout=5))
print("num sessions:", len(sessions) if isinstance(sessions,list) else sessions)
if isinstance(sessions, list) and sessions:
    s0 = sessions[0]
    print("most recent:", s0.get("session_id"), "has_report:", s0.get("has_report"), "has_metrics:", s0.get("has_metrics"))
    import glob, os
    d = s0.get("session_id")
    print("files:", [os.path.basename(f) for f in glob.glob(f"/home/groy/cai/cyberorion/logs/{d}/*")])