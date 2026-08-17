import json, urllib.request, glob, os
sessions = json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/sessions", timeout=5))
for s in sessions[:4]:
    print({k: s.get(k) for k in list(s.keys())[:12]})
# list all session dirs with files
for d in sorted(glob.glob("/home/groy/cai/cyberorion/logs/session_*"))[-4:]:
    fs = [os.path.basename(f) for f in glob.glob(os.path.join(d,"*")) if os.path.isfile(f)]
    print("DIR", os.path.basename(d), fs)