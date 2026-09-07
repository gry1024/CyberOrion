#!/usr/bin/env bash
# CyberOrion 一键安装脚本
#
# 用法（任何一种都可以）：
#   curl -sSL https://raw.githubusercontent.com/gry1024/CyberOrion/main/cyberorion/install.sh | bash
#   bash install.sh                 # 在已 git clone 的仓库里
#
# 做了什么：
#   1) 创建 venv: ~/.cyberorion/venv  （环境变量 CAI_VENV 可覆盖）
#   2) pip install -e ./cyberorion/cai-latest  （CAI framework 1.1.5+）
#   3) 安装 cyberorion 启动器到 ~/.local/bin/cyberorion
#   4) 首次启动时交互式询问 OPENAI_API_KEY / 模型 / base，写入 ~/.cyberorion/.env
#
# 不修改系统 Python、不需要 sudo。
set -euo pipefail

CYAN=$'\033[0;36m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; RED=$'\033[0;31m'; RST=$'\033[0m'
info() { echo "${YLW}ⓘ${RST} $*"; }
ok()   { echo "${GRN}✓${RST} $*"; }
err()  { echo "${RED}✗${RST} $*" >&2; }

# ---------- 0. 找到仓库根（cyberorion/）----------
# 兼容 curl | bash 的场景：脚本会被下载到 /tmp，仓库根要根据 URL/git clone 推导
CO_ROOT_DEFAULT="${HOME}/CyberOrion"
if [[ -f "./cyberorion/bin/cyberorion" ]]; then
  REPO_ROOT="$(pwd)"
elif [[ -f "./bin/cyberorion" ]]; then
  REPO_ROOT="$(cd .. && pwd)"
elif [[ -d "${CO_ROOT_DEFAULT}/cyberorion/bin" ]]; then
  REPO_ROOT="${CO_ROOT_DEFAULT}"
else
  # curl | bash 场景：尝试 clone
  info "未检测到 CyberOrion 仓库，正在 clone 到 ${CO_ROOT_DEFAULT} ..."
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 https://github.com/gry1024/CyberOrion.git "${CO_ROOT_DEFAULT}"
    REPO_ROOT="${CO_ROOT_DEFAULT}"
  else
    err "未找到 git，也无法定位 CyberOrion 仓库。请先安装 git，然后:"
    err "  git clone https://github.com/gry1024/CyberOrion.git"
    err "  cd CyberOrion && bash cyberorion/install.sh"
    exit 1
  fi
fi

CO_DIR="${REPO_ROOT}/cyberorion"
if [[ ! -f "${CO_DIR}/bin/cyberorion" ]]; then
  err "在 ${REPO_ROOT} 下找不到 ${CO_DIR}/bin/cyberorion，请确认仓库完整。"
  exit 1
fi
ok "仓库根：${REPO_ROOT}"

# ---------- 1. 准备 venv ----------
VENV_DIR="${CAI_VENV:-${HOME}/.cyberorion/venv}"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  info "创建 venv：${VENV_DIR}"
  mkdir -p "$(dirname "${VENV_DIR}")"
  if ! command -v python3.10 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.11 || command -v python3.12 || command -v python3 || true)"
    if [[ -z "${PYTHON_BIN}" ]]; then
      err "找不到 python3，请先安装 Python 3.10+"
      exit 1
    fi
    info "未找到 python3.10，使用 ${PYTHON_BIN}（建议 3.10+）"
  else
    PYTHON_BIN="python3.10"
  fi
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  ok "venv 已创建"
else
  ok "复用已有 venv：${VENV_DIR}"
fi

# ---------- 2. 安装 cai-framework ----------
CAI_LATEST_DIR="${REPO_ROOT}/cai-latest"
if [[ ! -d "${CAI_LATEST_DIR}" ]]; then
  err "仓库缺少 ${CAI_LATEST_DIR}，请确认仓库完整（包含 cai-latest 子模块或目录）。"
  exit 1
fi
info "安装 CAI framework（首次约 1-2 分钟）..."
"${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
"${VENV_DIR}/bin/pip" install -e "${CAI_LATEST_DIR}" 2>&1 | tail -n 5
ok "CAI framework 已安装"

# ---------- 3. 安装 cyberorion 启动器到 PATH ----------
BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"
install -m 0755 "${CO_DIR}/bin/cyberorion" "${BIN_DIR}/cyberorion"
ok "已安装启动器：${BIN_DIR}/cyberorion"

# 检查 PATH
if ! command -v cyberorion >/dev/null 2>&1; then
  info "${BIN_DIR} 不在当前 PATH。"
  case ":${PATH}:" in
    *":${BIN_DIR}:"*) ;;
    *)
      SHELL_RC=""
      if [[ -n "${ZSH_VERSION:-}" ]] && [[ -f "${HOME}/.zshrc" ]]; then
        SHELL_RC="${HOME}/.zshrc"
      elif [[ -f "${HOME}/.bashrc" ]]; then
        SHELL_RC="${HOME}/.bashrc"
      fi
      if [[ -n "${SHELL_RC}" ]] && ! grep -q "${BIN_DIR}" "${SHELL_RC}" 2>/dev/null; then
        echo "" >> "${SHELL_RC}"
        echo "# CyberOrion CLI" >> "${SHELL_RC}"
        echo "export PATH=\"${BIN_DIR}:\${PATH}\"" >> "${SHELL_RC}"
        info "已把 ${BIN_DIR} 加入 PATH（写入 ${SHELL_RC}），请执行：source ${SHELL_RC}"
      else
        info "请把 ${BIN_DIR} 加入 PATH：export PATH=\"${BIN_DIR}:\${PATH}\""
      fi
      ;;
  esac
fi

echo
echo "${CYAN}─────────────────────────────────────────────────────────${RST}"
echo "${GRN}  ✓ 安装完成${RST}"
echo "${CYAN}─────────────────────────────────────────────────────────${RST}"
echo
info "下一步：直接运行 ${GRN}cyberorion${RST} 即可。首次运行会交互式询问 API key / 模型。"
echo
echo "  ${GRN}cyberorion${RST}               # 默认进入对话终端"
echo "  ${GRN}cyberorion --help${RST}        # 查看所有子命令"
echo "  ${GRN}cyberorion ctf <name>${RST}    # 跑 CTF（需 docker 靶场）"
echo
