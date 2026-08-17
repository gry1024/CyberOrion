import sqlite3
db = sqlite3.connect('/home/groy/cai/cyberorion/logs/session_20260817_030935/telemetry.db')
print('=== attacks schema ===')
for r in db.execute('PRAGMA table_info(attacks)'):
    print(r[1], r[2])
print('=== attacks summary ===')
try:
    for r in db.execute('select target, technique, success, count(*) from attacks group by target, technique, success'):
        print(r)
except Exception as e:
    print('ERR', e)
print('=== sample attack rows ===')
for r in db.execute('select * from attacks order by rowid desc limit 10'):
    print(r)