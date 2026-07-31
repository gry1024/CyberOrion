#!/usr/bin/env bash
# 手动重置靶场目标到易受攻击基线（weak_ssh 弱密码可登录 / DVWA security=low /
# log4j 重启）。等价于控制器 start_session 时的自动重置。
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-/home/groy/cai/cai_env/bin/python}"
exec "$PY" -m cyberorion.arena_reset "$@"
