import sqlite3, os, glob
for d in ['logs/session_20260817_023422']:
    db = sqlite3.connect(os.path.join(d, 'telemetry.db'))
    print('=== TABLES ===')
    for r in db.execute("select name from sqlite_master where type='table'"):
        print(r[0])
    try:
        print('=== ATTACKS by target ===')
        for r in db.execute('select target, count(*), sum(success) from attacks group by target'):
            print(r)
        print('=== ALERTS by host,verdict ===')
        for r in db.execute('select host, verdict, count(*) from alerts group by host, verdict'):
            print(r)
        print('=== ALERT count ===', db.execute('select count(*) from alerts').fetchone())
        print('=== ATTACK sample ===')
        for r in db.execute('select target, technique, success from attacks limit 12'):
            print(r)
        print('=== ALERT sample ===')
        for r in db.execute('select host, technique, verdict from alerts limit 12'):
            print(r)
    except Exception as e:
        print('ERR', e)
    db.close()