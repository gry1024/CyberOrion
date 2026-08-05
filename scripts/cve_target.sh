#!/usr/bin/env bash
# cve_target.sh — CyberOrion CVE 场景靶机生命周期助手。
#
# 包装 CVE-Bench 仓库的 ./run 脚本（绝对路径），并提供一个 status 命令
# 同时展示容器状态与评分器健康度。
#
# 用法:
#   scripts/cve_target.sh up     CVE-2024-4323   # 拉取(缺失时)并启动靶栈
#   scripts/cve_target.sh down   CVE-2024-4323   # 停止并删除 volumes
#   scripts/cve_target.sh status CVE-2024-4323   # 容器 + 评分器状态
#
# 环境变量:
#   CVEBENCH_REPO  CVE-Bench 仓库路径（默认见下）
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
_CAI_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"
CVEBENCH_REPO="${CVEBENCH_REPO:-$_CAI_ROOT/benchmarks/cvebench/CVE-Bench}"
GRADER_BASE="http://localhost:9091"
APP_BASE="http://localhost:9090"

die() { echo "cve_target: error: $*" >&2; exit 2; }

[ $# -ge 2 ] || die "usage: $0 {up|down|status} <CVE-ID>"
CMD="$1"
CVE="$2"
PROJECT="$(echo "$CVE" | tr 'A-Z' 'a-z')"

[ -x "$CVEBENCH_REPO/run" ] || die "CVE-Bench repo not found at $CVEBENCH_REPO (set CVEBENCH_REPO)"

case "$CMD" in
  up)
    (cd "$CVEBENCH_REPO" && ./run pull "$CVE" && ./run up "$CVE" --no-build)
    echo "cve_target: $CVE is up — app $APP_BASE grader $GRADER_BASE/done"
    ;;
  down)
    (cd "$CVEBENCH_REPO" && ./run down "$CVE")
    echo "cve_target: $CVE is down"
    ;;
  status)
    echo "== containers ($PROJECT-*) =="
    docker ps -a --filter "name=${PROJECT}-" \
      --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
    echo
    echo "== app $APP_BASE =="
    curl -s -o /dev/null -w 'HTTP %{http_code}\n' --max-time 5 "$APP_BASE/" \
      || echo "unreachable"
    echo "== grader $GRADER_BASE =="
    curl -s --max-time 5 "$GRADER_BASE/health" || echo "health: unreachable"
    echo
    curl -s --max-time 5 "$GRADER_BASE/done" || echo "done: unreachable"
    echo
    ;;
  *)
    die "unknown command $CMD (expected up|down|status)"
    ;;
esac
