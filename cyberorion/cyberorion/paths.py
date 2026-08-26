"""集中管理所有外部路径，杜绝硬编码 ``/home/user/...``。

设计原则
========
1. **仓库内路径**用 ``Path(__file__)`` 相对推导，永远不写死绝对路径；
2. **仓库外路径**（venv / .env）通过环境变量覆盖，默认值基于仓库根的父目录推导；
   **benchmark 题库与结果默认在仓库内**，确保 GitHub clone 后文档与代码一致；
3. 所有路径都是 ``Path`` 对象，调用方按需 ``str()``。

环境变量
========
- ``CAI_VENV``         : Python 虚拟环境路径（默认 ``<cai-repo>/cai_env``）
- ``CAI_ENV_FILE``     : .env 文件路径（默认 ``<cai-repo>/.env``）
- ``CAI_BENCHMARKS``   : 基准数据集根目录（默认 ``<repo>/benchmarks``）
- ``CICIDS_DIR``       : CICIDS2017 CSV 目录（默认 ``<repo>/cyberorion/traffic/data/cicids2017``）
- ``PURPLE_LLAMA_DIR`` : PurpleLlama 数据根（默认 ``<repo>/benchmarks/cybersoceval/PurpleLlama``）
- ``CVEBENCH_REPO``    : CVE-Bench 仓库路径（默认 ``<repo>/benchmarks/cvebench/CVE-Bench``）

其中 ``<repo>`` = cyberorion 仓库根（本文件所在目录上两级），
``<cai-repo>`` = ``<repo>.parent``（含 ``.env`` / ``cai_env``）。
"""

from __future__ import annotations

import os
from pathlib import Path

# paths.py 位于 <repo>/cyberorion/paths.py，上两级即 cyberorion 仓库根。
REPO_ROOT: Path = Path(__file__).resolve().parents[1]
# CAI 仓库根（cyberorion 的父目录）：含 .env、cai_env、benchmarks。
CAI_ROOT: Path = REPO_ROOT.parent


def _env_path(name: str, default: Path) -> Path:
    """读环境变量 name，未设或为空则返回 default。"""
    v = os.environ.get(name, "").strip()
    return Path(v).expanduser() if v else default


# Python 虚拟环境。合作者可 export CAI_VENV=/path/to/venv 覆盖。
CAI_VENV: Path = _env_path("CAI_VENV", CAI_ROOT / "cai_env")
# venv 内的 python 解释器（脚本调用常用）。
CAI_VENV_PYTHON: Path = CAI_VENV / "bin" / "python"

# .env 配置文件（server.py / run.py 启动时自动加载）。
ENV_FILE: Path = _env_path("CAI_ENV_FILE", CAI_ROOT / ".env")

# 基准题库/数据根目录。默认放在仓库内，保证 GitHub 文档引用的题库随代码上传；
# 若本地有完整第三方数据镜像，可用 CAI_BENCHMARKS 覆盖。
BENCHMARKS_DIR: Path = _env_path("CAI_BENCHMARKS", REPO_ROOT / "benchmarks")

# CICIDS2017 流量数据集 CSV 目录（流量分析模块用）。
CICIDS_DIR: Path = _env_path("CICIDS_DIR", REPO_ROOT / "cyberorion" / "traffic" / "data" / "cicids2017")

# PurpleLlama 仓库根（CyberSOCEval / threat_intel 基准用）。
PURPLE_LLAMA_DIR: Path = _env_path("PURPLE_LLAMA_DIR", BENCHMARKS_DIR / "cybersoceval" / "PurpleLlama")

# CVE-Bench 仓库路径（CVE 场景生成与靶栈控制用）。
CVEBENCH_REPO: Path = _env_path("CVEBENCH_REPO", BENCHMARKS_DIR / "cvebench" / "CVE-Bench")


__all__ = [
    "REPO_ROOT", "CAI_ROOT", "CAI_VENV", "CAI_VENV_PYTHON", "ENV_FILE",
    "BENCHMARKS_DIR", "CICIDS_DIR", "PURPLE_LLAMA_DIR", "CVEBENCH_REPO",
]
