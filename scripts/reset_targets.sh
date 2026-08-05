#!/usr/bin/env bash
# 手动重置靶场目标到易受攻击基线（weak_ssh 弱密码可登录 / DVWA security=low /
# log4j 重启）。等价于控制器 start_session 时的自动重置。
set -euo pipefail
cd "$(dirname "$0")/.."
# Python 解释器：默认 python3；如需指定 venv，export PYTHON=/path/to/venv/bin/python
PY="${PYTHON:-python3}"
exec "$PY" -m cyberorion.arena_reset "$@"
