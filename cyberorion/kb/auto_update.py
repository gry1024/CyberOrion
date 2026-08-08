"""auto_update: 知识库自动更新模块。

定时从公开数据源拉取最新威胁情报，增量合并到知识库：
  1. NVD CVE API — 拉取近期高危漏洞（CVSS >= 7.0）
  2. CNVD/国家信息安全漏洞库 — 国内监管政策与漏洞通告（预设数据源）

更新策略：
  - 每 6 小时执行一次（可在环境变量 AUTO_UPDATE_INTERVAL_HOURS 调整）
  - 增量合并：按 doc id 去重，新条目追加到 attack_kb.jsonl
  - 更新后调用 reset_kb() 让进程内单例重新加载
  - 网络失败时静默跳过，不中断服务

用法（手动触发）：
    python -m cyberorion.kb.auto_update           # 立即执行一次
    python -m cyberorion.kb.auto_update --daemon   # 守护进程模式
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger("cyberorion.kb.auto_update")

_HERE = Path(__file__).resolve().parent
KB_PATH = _HERE / "data" / "attack_kb.jsonl"
UPDATE_INTERVAL = int(os.getenv("AUTO_UPDATE_INTERVAL_HOURS", "6")) * 3600

# NVD API v2（无需 key，但有限速 5 req/30s；带 key 可提高到 50 req/30s）
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # 可选：申请后填入提高速率

# CNVD RSS / 公告页（预留接口，实际数据源需按需配置）
CNVD_SOURCES = [
    # 国家信息安全漏洞库 — 最新漏洞
    "https://www.cnvd.org.cn/flaw/list.htm",
]

_TEXT_CLIP = 1200  # 与 build_kb.py 保持一致


def _http_get(url: str, headers: dict[str, str] | None = None,
              timeout: int = 30) -> bytes:
    """简单 HTTP GET，返回原始 bytes。"""
    req = Request(url, headers=headers or {})
    return urlopen(req, timeout=timeout).read()


def _clean(text: str) -> str:
    import re
    return re.sub(r"\\s+", " ", str(text or "")).strip()


def _clip(text: str, limit: int = _TEXT_CLIP) -> str:
    text = _clean(text)
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "…"


# --------------------------------------------------------------------------- #
# NVD CVE 拉取
# --------------------------------------------------------------------------- #
def fetch_recent_cves(days: int = 7, min_cvss: float = 7.0) -> list[dict[str, Any]]:
    """从 NVD API 拉取近期 CVE（按 CVSS 过滤），返回 KB 文档格式列表。

    每条文档结构与 build_kb.py 中 CVE 文档一致：
      id / name / type=cve / cvss / published / description /
      affected_products / attack_vector / cwe / text
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    pub_start = start.strftime("%Y-%m-%dT00:00:00.000")
    pub_end = now.strftime("%Y-%m-%dT23:59:59.999")

    params = f"?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=200"
    url = NVD_API + params

    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        raw = _http_get(url, headers, timeout=60)
        data = json.loads(raw)
    except (URLError, HTTPError, json.JSONDecodeError, TimeoutError) as e:
        logger.warning("NVD API 请求失败: %s", e)
        return []

    cve_items = data.get("vulnerabilities", [])
    docs: list[dict[str, Any]] = []

    for item in cve_items:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # 提取描述
        descriptions = cve.get("descriptions", [])
        desc_en = ""
        desc_cn = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
            elif d.get("lang") == "zh":
                desc_cn = d.get("value", "")
        description = desc_cn or desc_en

        # 提取 CVSS 评分（优先 CVSS v3.1，其次 v3.0，最后 v2）
        metrics = cve.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                cvss_score = m.get("baseScore", 0.0)
                cvss_vector = m.get("vectorString", "")
                break

        # 按 CVSS 过滤
        if cvss_score < min_cvss:
            continue

        # 提取受影响产品
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        # cpe:2.3:a:vendor:product:version:...
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            affected.append(f"{parts[3]}/{parts[4]}")
        affected_products = sorted(set(affected))[:10]  # 最多 10 个

        # 提取 CWE
        cwe_ids = []
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])
        cwe = sorted(set(cwe_ids))[:3]

        # 提取攻击向量
        attack_vector = ""
        if "AV:" in cvss_vector:
            av_map = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
            av_code = cvss_vector.split("AV:")[1][0] if len(cvss_vector.split("AV:")) > 1 else ""
            attack_vector = av_map.get(av_code, "")

        published = cve.get("published", "")

        # 构造检索用 text 字段
        text_parts = [cve_id, description]
        if attack_vector:
            text_parts.append(f"攻击向量: {attack_vector}")
        if cwe:
            text_parts.append(f"CWE: {', '.join(cwe)}")
        if affected_products:
            text_parts.append(f"受影响产品: {', '.join(affected_products[:5])}")
        text = _clip(" ".join(text_parts))

        docs.append({
            "id": cve_id,
            "type": "cve",
            "name": f"{cve_id} (CVSS {cvss_score:.1f})",
            "cvss": cvss_score,
            "published": published,
            "description": _clip(description, 700),
            "affected_products": affected_products,
            "attack_vector": attack_vector,
            "cwe": cwe,
            "text": text,
            "_source": "nvd_auto",
            "_updated": now.isoformat(),
        })

    logger.info("NVD 拉取完成: %d 条 CVE (CVSS >= %.1f, 近 %d 天)", len(docs), min_cvss, days)
    return docs


# --------------------------------------------------------------------------- #
# 监管政策拉取（框架，数据源可配置）
# --------------------------------------------------------------------------- #
def _fetch_anquanke_rss(now) -> list[dict]:
    """从安全客(anquanke) RSS 拉取国内安全资讯（含监管动态）。"""
    url = "https://api.anquanke.com/data/v1/rss"
    headers = {"User-Agent": "CyberOrion/1.0", "Accept": "application/json"}
    try:
        raw = _http_get(url, headers, timeout=20)
        data = json.loads(raw)
    except Exception:
        return []
    items = data.get("data", []) if isinstance(data, dict) else []
    docs = []
    for item in items[:20]:
        title = item.get("title", "")
        desc = _clean(item.get("desc", ""))
        link = item.get("link", "")
        date = item.get("date", "")
        cat = item.get("category", "")
        if not title:
            continue
        doc_id = "AQ-" + re.sub(r"[^a-zA-Z0-9]", "", title[:30]).upper()
        text = _clip(title + " | " + cat + " | " + desc)
        docs.append({
            "id": doc_id, "type": "regulation", "name": title,
            "category": cat or "安全资讯", "published": date,
            "description": _clip(desc, 500), "url": link, "text": text,
            "_source": "anquanke_rss", "_updated": now.isoformat(),
        })
    return docs


def _fetch_cnnvd_advisories(now) -> list[dict]:
    """从 CNNVD 拉取最新漏洞通告（HTML 解析，容错）。"""
    url = "https://www.cnnvd.org.cn/web/xxk/jsjd.do"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "text/html"}
    try:
        raw = _http_get(url, headers, timeout=20)
        html = raw.decode("utf-8", errors="ignore")
    except Exception:
        return []
    docs = []
    titles = re.findall(r'title="([^"]{10,80})"', html)
    seen = set()
    for i, title in enumerate(titles[:15]):
        doc_id = "CNNVD-" + now.strftime("%Y%m%d") + "-" + str(i).zfill(3)
        if doc_id in seen:
            continue
        seen.add(doc_id)
        docs.append({
            "id": doc_id, "type": "regulation", "name": title,
            "category": "CNNVD漏洞通告", "published": now.strftime("%Y-%m-%d"),
            "description": title, "text": _clip(title),
            "_source": "cnnvd_advisory", "_updated": now.isoformat(),
        })
    return docs


def fetch_regulations() -> list[dict[str, Any]]:
    """拉取国内最新监管政策、安全通报与漏洞通告。

    数据源（按优先级，任一失败不影响其他）：
      1. regulations.json 种子数据 - 核心法律法规（网安法/数安法/个保法/关基条例），
         确保基线始终在库（build_kb 已加载，此处做去重兜底）
      2. 安全客(anquanke) RSS - 国内安全资讯，含监管动态与政策解读
      3. CNNVD 通报 - 国家信息安全漏洞库最新漏洞通告

    所有网络请求失败时仅返回种子数据，绝不阻塞主流程。
    """
    now = datetime.now(timezone.utc)
    docs: list[dict[str, Any]] = []

    # ---- 1. 种子数据兜底 ----
    reg_seed = _HERE / "data" / "regulations.json"
    if reg_seed.is_file():
        try:
            seed = json.loads(reg_seed.read_text(encoding="utf-8"))
            for r in seed:
                r.setdefault("type", "regulation")
                r.setdefault("_source", "seed_regulation")
                docs.append(r)
        except Exception as e:
            logger.warning("regulations.json 加载失败: %s", e)

    # ---- 2. 安全客 RSS（国内安全资讯，含监管动态）----
    try:
        docs.extend(_fetch_anquanke_rss(now))
    except Exception as e:
        logger.warning("安全客 RSS 拉取失败（跳过）: %s", e)

    # ---- 3. CNNVD 最新漏洞通告 ----
    try:
        docs.extend(_fetch_cnnvd_advisories(now))
    except Exception as e:
        logger.warning("CNNVD 通告拉取失败（跳过）: %s", e)

    seed_n = len([d for d in docs if d.get("_source") == "seed_regulation"])
    online_n = len(docs) - seed_n
    logger.info("监管政策拉取完成: 种子%d + 在线%d = %d 条", seed_n, online_n, len(docs))
    return docs

# --------------------------------------------------------------------------- #
# 增量合并到知识库
# --------------------------------------------------------------------------- #
def _load_existing_ids(kb_path: Path = KB_PATH) -> set[str]:
    """读取现有知识库的所有 doc id，用于去重。"""
    ids = set()
    if not kb_path.is_file():
        return ids
    with open(kb_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
                ids.add(doc.get("id", "").upper())
            except json.JSONDecodeError:
                continue
    return ids


def incremental_update(new_docs: list[dict[str, Any]],
                       kb_path: Path = KB_PATH) -> int:
    """将新文档增量合并到知识库 JSONL 文件。

    按 doc id 去重（大小写不敏感），新条目追加到文件末尾。
    返回实际新增的文档数。
    """
    if not new_docs:
        return 0

    existing_ids = _load_existing_ids(kb_path)
    added = 0

    with open(kb_path, "a", encoding="utf-8") as f:
        for doc in new_docs:
            doc_id = doc.get("id", "").upper()
            if doc_id and doc_id not in existing_ids:

                line = json.dumps(doc, ensure_ascii=False)
                # 写入前验证 JSON 可正确反序列化，防止损坏 KB
                try:
                    json.loads(line)
                except Exception:
                    logger.warning("跳过无效文档 %s", doc_id)
                    continue
                f.write(line + "\n")
                f.flush()
                existing_ids.add(doc_id)
                added += 1

    logger.info("增量更新完成: 新增 %d 条（去重后），总计 %d 条", added, len(existing_ids))
    return added


# --------------------------------------------------------------------------- #
# 完整更新流程
# --------------------------------------------------------------------------- #
def run_auto_update() -> dict[str, Any]:
    """执行一次完整的知识库自动更新。

    1. 拉取 NVD 近期高危 CVE
    2. 拉取监管政策（框架）
    3. 增量合并到 attack_kb.jsonl
    4. 重置进程内 KB 单例（让下次检索加载新数据）

    返回更新摘要。
    """
    start_ts = time.time()
    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "cve_fetched": 0,
        "regulation_fetched": 0,
        "added": 0,
        "elapsed_sec": 0.0,
        "errors": [],
    }

    try:
        cve_docs = fetch_recent_cves(days=7, min_cvss=7.0)
        result["cve_fetched"] = len(cve_docs)
    except Exception as e:
        logger.exception("CVE 拉取异常")
        result["errors"].append(f"cve: {e}")
        cve_docs = []

    try:
        reg_docs = fetch_regulations()
        result["regulation_fetched"] = len(reg_docs)
    except Exception as e:
        logger.exception("监管政策拉取异常")
        result["errors"].append(f"regulation: {e}")
        reg_docs = []

    all_new = cve_docs + reg_docs
    try:
        added = incremental_update(all_new)
        result["added"] = added

        # 重置 KB 单例，让下次 get_kb() 重新加载
        if added > 0:
            try:
                from cyberorion.kb.rag import reset_kb
                reset_kb()
                logger.info("KB 单例已重置，下次检索将加载新数据")
            except Exception:
                pass
    except Exception as e:
        logger.exception("增量合并失败")
        result["errors"].append(f"merge: {e}")

    result["elapsed_sec"] = round(time.time() - start_ts, 2)
    logger.info("自动更新完成: %s", result)
    return result


async def auto_update_loop(stop_event=None):
    """守护进程模式：每 AUTO_INTERVAL 秒执行一次自动更新。

    在 server.py lifespan 中作为后台任务启动。
    stop_event: asyncio.Event，设置后停止循环（用于优雅关闭）。
    """
    import asyncio
    logger.info("知识库自动更新守护进程已启动，间隔 %d 秒", UPDATE_INTERVAL)

    # 启动后立即执行一次，然后按间隔循环
    while True:
        try:
            run_auto_update()
        except Exception:
            logger.exception("自动更新周期执行异常")

        if stop_event is not None:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=UPDATE_INTERVAL)
                break  # stop_event 被设置，退出循环
            except asyncio.TimeoutError:
                continue  # 超时，执行下一轮
        else:
            await asyncio.sleep(UPDATE_INTERVAL)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

    if "--daemon" in sys.argv:
        import asyncio
        asyncio.run(auto_update_loop())
    else:
        result = run_auto_update()
        print(json.dumps(result, indent=2, ensure_ascii=False))
