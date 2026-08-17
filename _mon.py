import sys, json, urllib.request
def get(url):
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            return json.load(r)
    except Exception as e:
        return {'error': str(e)}
d = get('http://127.0.0.1:8000/api/status')
if 'error' in d:
    print('STATUS_ERROR', d['error']); sys.exit(0)
print('red_running=%s blue_running=%s red_hist=%s blue_hist=%s active=%s' % (
    d['red_running'], d['blue_running'], d['red_history_count'], d['blue_history_count'], d['session_active']))
s = d.get('summary') or {}
print('summary_keys=%s' % list(s.keys()))