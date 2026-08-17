import os, sys
sys.path.insert(0, '/home/groy/cai/cyberorion')
from cyberorion.scenarios import load_scenario

s = load_scenario()
print('scenario =', os.environ.get('CO_SCENARIO'))
for t in s.targets.values():
    print('target', getattr(t, 'name', '?'),
          '|ip=' + str(getattr(t, 'ip', '')),
          '|container=' + str(getattr(t, 'container', '')),
          '|host_port=' + str(getattr(t, 'host_port', '')))
    svcs = getattr(t, 'services', {}) or {}
    if isinstance(svcs, dict):
        for proto, svc in svcs.items():
            print('    svc', proto, '->', str(getattr(svc, 'proto', '')))
