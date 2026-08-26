"""外部 benchmark 资产清单与离线可用性检查。

服务端绝不自动下载数据。管理员通过环境变量或 ``benchmarks/external``
放置上游资产；缺失时向 API 返回结构化、可操作的错误，而不是生成零分。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = Path(os.getenv(
    "CYBERORION_BENCHMARK_ROOT", _REPO / "benchmarks" / "external"))


@dataclass(frozen=True)
class AssetSpec:
    suite: str
    title: str
    upstream_url: str
    version: str
    license: str
    expected: tuple[str, ...]
    env_var: str
    recognition: str


ASSETS: dict[str, AssetSpec] = {
    "secalertbench": AssetSpec(
        "secalertbench", "SecAlertBench",
        "https://github.com/Dxsssu/SecAlertBench", "upstream-pinned",
        "see upstream repository", ("*.json", "*.jsonl"),
        "CYBERORION_SECALERTBENCH_DIR", "external_real_soc_artifact"),
    "excytin": AssetSpec(
        "excytin", "ExCyTIn via ACESEvals",
        "https://github.com/microsoft/ACESEvals", "legacy_test_set-589",
        "MIT (runner); dataset terms follow upstream",
        ("*.yaml", "*.yml", "*.json", "*.jsonl", "*.db", "*.sqlite", "*.sqlite3"),
        "CYBERORION_EXCYTIN_DIR", "peer_reviewed_official_protocol"),
    "cage2": AssetSpec(
        "cage2", "CybORG CAGE Challenge 2",
        "https://github.com/cage-challenge/cage-challenge-2", "challenge-2",
        "see upstream repository", ("Scenario2.yaml", "evaluation.py"),
        "CYBERORION_CAGE2_DIR", "official_challenge"),
}


class BenchmarkAssetMissing(RuntimeError):
    """所需公开数据/环境尚未配置。"""

    def __init__(self, suite: str, detail: str = "") -> None:
        spec = ASSETS[suite]
        self.suite = suite
        self.code = "benchmark_asset_missing"
        self.asset = asset_status(suite)
        message = (
            f"{spec.title} 资产未配置；设置 {spec.env_var} 或放入 "
            f"{DEFAULT_ROOT / suite}。来源：{spec.upstream_url}"
        )
        super().__init__(f"{message}{'; ' + detail if detail else ''}")


def asset_root(suite: str) -> Path:
    spec = ASSETS[suite]
    configured = os.getenv(spec.env_var)
    return Path(configured).expanduser() if configured else DEFAULT_ROOT / suite


def _matches(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    found: list[Path] = []
    if not root.exists():
        return found
    for pattern in patterns:
        found.extend(root.rglob(pattern))
    return sorted({p.resolve() for p in found if p.exists()})


def _has_sqlite_header(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def asset_status(suite: str) -> dict:
    spec = ASSETS[suite]
    root = asset_root(suite)
    matches = _matches(root, spec.expected)
    names = {p.name for p in matches}
    files = [p for p in matches if p.is_file()]
    if suite == "cage2":
        ready = "Scenario2.yaml" in names and "evaluation.py" in names
        validation = "Scenario2.yaml+official evaluation.py"
    elif suite == "excytin":
        has_tasks = any(p.suffix.lower() in {".yaml", ".yml", ".json", ".jsonl"}
                        for p in files)
        has_sqlite = any(p.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
                         and p.is_file() and _has_sqlite_header(p) for p in files)
        ready = has_tasks and has_sqlite
        validation = "task schema + verified SQLite header (official backend is MySQL/Inspect Docker)"
    else:
        ready = False
        for path in files:
            if path.stat().st_size > 8 * 1024 * 1024:
                # 不为状态探测扫描大文件；官方规范文件名足以判定。
                ready = ready or path.name == "secalertbench.json"
                continue
            try:
                with path.open("r", encoding="utf-8") as stream:
                    prefix = stream.read(65536)
            except (OSError, UnicodeError):
                continue
            if any(token in prefix for token in ('"Label"', '"label"')):
                ready = True
                break
        validation = "binary Label/label schema"
    return {
        "suite": suite, "title": spec.title, "available": bool(ready),
        "root": str(root), "version": spec.version, "license": spec.license,
        "upstream_url": spec.upstream_url, "recognition": spec.recognition,
        "expected": list(spec.expected), "matched_files": len(matches),
        "validation": validation,
    }


def require_asset(suite: str) -> tuple[Path, list[Path]]:
    root = asset_root(suite)
    matches = _matches(root, ASSETS[suite].expected)
    if not matches or not asset_status(suite)["available"]:
        raise BenchmarkAssetMissing(suite)
    return root, matches


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_asset_status() -> list[dict]:
    return [cybersoceval_asset_status(), *(asset_status(name) for name in ASSETS)]


def cybersoceval_asset_status() -> dict:
    """只读校验已存在的官方 CyberSOCEval questions.json。"""
    from .cybersoceval import DEFAULT_QUESTIONS, load_questions
    path = Path(DEFAULT_QUESTIONS)
    if not path.is_file():
        return {"suite": "malware_analysis", "available": False,
                "root": str(path.parent), "validation": "questions.json missing"}
    try:
        usable = len(load_questions(path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"suite": "malware_analysis", "available": False,
                "root": str(path.parent), "validation": f"schema error: {exc}"}
    return {
        "suite": "malware_analysis", "title": "CyberSOCEval malware_analysis",
        "available": usable > 0, "root": str(path.parent),
        "dataset_file": str(path), "upstream_n": 609, "usable_n": usable,
        "excluded_n": 609 - usable, "sha256": sha256_file(path),
        "validation": "official question/options/correct_options schema",
    }
