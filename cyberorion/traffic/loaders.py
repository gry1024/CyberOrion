"""CICIDS2017 数据集加载器。

职责（高内聚）：读取CSV、清洗脏数据（前导空格/NaN/Inf/numpy类型）、
Label→ATT&CK映射、按配额优先保留攻击样本，返回 list[dict]。
低耦合：仅依赖 pandas/numpy/标准库，不导入项目其他模块。
"""
from __future__ import annotations

import math
from typing import Any, Optional

import numpy as np
import pandas as pd

# ATT&CK 映射表：规范化标签 -> (ATT&CK 技术, 攻击类型描述)
_LABEL_TECH_MAP: dict[str, tuple[Optional[str], str]] = {
    "BENIGN": (None, "正常"),
    "DoS": ("T1498", "网络DoS"),            # Hulk/GoldenEye/slowloris/Slowhttptest
    "DDoS": ("T1498.001", "直接网络DoS"),
    "PortScan": ("T1046", "网络服务扫描"),
    "FTP-Patator": ("T1110", "暴力破解"),
    "SSH-Patator": ("T1110", "暴力破解"),
    "Web Attack - Brute Force": ("T1110.001", "密码猜测"),
    "Web Attack - XSS": ("T1059.007", "跨站脚本"),
    "Web Attack - Sql Injection": ("T1190", "利用公开应用"),
    "Infiltration": ("T1190", "利用公开应用"),
    "Bot": ("T1071", "应用层协议"),
    "Heartbleed": ("T1190", "利用公开应用"),
}
def _classify_label(raw_label: Any) -> tuple[str, Optional[str], str]:
    """分类原始 Label -> (规范化标签, ATT&CK技术, 攻击类型描述)。用子串匹配，兼容拼写错误。"""
    low = str(raw_label).strip().lower()
    if low == "benign":
        norm = "BENIGN"
    elif "ddos" in low:                                   # 顺序敏感：先匹配 DDoS
        norm = "DDoS"
    elif ("slowloris" in low or "slowhttptest" in low or "goldeneye" in low
          or "hulk" in low or low.startswith("dos")):
        norm = "DoS"
    elif "portscan" in low:
        norm = "PortScan"
    elif "ftp" in low and "patator" in low:
        norm = "FTP-Patator"
    elif "ssh" in low and "patator" in low:
        norm = "SSH-Patator"
    elif "brute force" in low:
        norm = "Web Attack - Brute Force"
    elif "xss" in low:
        norm = "Web Attack - XSS"
    elif "sql" in low:
        norm = "Web Attack - Sql Injection"
    elif "infiltration" in low or "infilteration" in low:
        norm = "Infiltration"
    elif "bot" in low:
        norm = "Bot"
    elif "heartbleed" in low:
        norm = "Heartbleed"
    else:
        return low, None, "未知"
    technique, attack_type = _LABEL_TECH_MAP[norm]
    return norm, technique, attack_type
def _to_native(v: Any) -> Any:
    """numpy 标量转原生类型；NaN/Inf 转 0，便于序列化与检测。"""
    if v is None:
        return None
    if isinstance(v, np.integer):
        return int(v)
    if isinstance(v, np.floating):
        f = float(v)
        return 0.0 if (math.isnan(f) or math.isinf(f)) else f
    if isinstance(v, np.bool_):
        return bool(v)
    if isinstance(v, float):
        return 0.0 if (math.isnan(v) or math.isinf(v)) else v
    return v


# 需强制数值化并清洗 NaN/Inf 的已知脏列
_DIRTY_NUMERIC_COLS = ("Flow Bytes/s", "Flow Packets/s")


def load_cicids(csv_path: str, max_rows: int = 50000, attack_only: bool = False) -> list[dict]:
    """加载 CICIDS2017 CSV，返回规范化行列表。

    返回每个 dict 含原始特征（已清洗）+ label/technique/attack_type 三个映射字段。
    采样：分块读取，优先保留攻击行（小 max_rows 也能看到攻击），再用 BENIGN 补齐。
    """
    target_attacks = max_rows if attack_only else max_rows // 2
    attack_rows: list[dict] = []
    benign_rows: list[dict] = []
    # 分块读取：收集够配额即提前终止，避免读取整个大文件
    for chunk in pd.read_csv(csv_path, chunksize=100_000, low_memory=False):
        chunk.columns = [str(c).strip() for c in chunk.columns]       # 去列名前导空格
        for col in _DIRTY_NUMERIC_COLS:                                # 脏列强制数值化+清洗
            if col in chunk.columns:
                chunk[col] = pd.to_numeric(chunk[col], errors="coerce")
                chunk[col] = chunk[col].replace([np.inf, -np.inf], np.nan).fillna(0.0)
        for r in chunk.to_dict(orient="records"):
            norm_label, technique, attack_type = _classify_label(r.get("Label", "BENIGN"))
            is_attack = norm_label != "BENIGN"
            if attack_only and not is_attack:
                continue
            cleaned = {k: _to_native(v) for k, v in r.items()}         # 清理 numpy 类型
            cleaned["label"] = norm_label
            cleaned["technique"] = technique
            cleaned["attack_type"] = attack_type
            if is_attack:
                if len(attack_rows) < target_attacks:
                    attack_rows.append(cleaned)
            elif len(benign_rows) < (max_rows - len(attack_rows)):
                benign_rows.append(cleaned)
        if attack_only:
            if len(attack_rows) >= target_attacks:
                break
        else:
            if len(attack_rows) >= target_attacks and len(benign_rows) >= (max_rows - target_attacks):
                break
            if attack_rows == [] and len(benign_rows) >= max_rows:     # 此文件无攻击
                break
    rows = attack_rows + benign_rows                                   # 攻击行在前
    return rows[:max_rows]
