import sqlite3, glob, os
dirs = sorted(glob.glob('/home/groy/cai/cyberorion/logs/session_*'), reverse=True)
d = dirs[0] if dirs else ''
print('latest_session=', d)
if not d: raise SystemExit
db = sqlite3.connect(os.path.join(d, 'telemetry.db'))
for tbl in ('events', 'attacks', 'alerts', 'snapshots'):
    try:
        n = db.execute('select count(*) from %s' % tbl).fetchone()[0]
        print('%s=%s' % (tbl, n))
    except Exception as e:
        print('%s ERR %s' % (tbl, e))
print('--- recent attacks ---')
try:
    for r in db.execute('select target, technique, success from attacks order by rowid desc limit 8'):
        print(r)
except Exception as e:
    print('attacks ERR', e)
print('--- recent events types ---')
try:
    for r in db.execute('select type, count(*) from events group by type'):
        print(r)
except Exception as e:
    print('events ERR', e)