import re
p = "/home/groy/cai/cyberorion/cyberorion/eval/metrics.py"
src = open(p, encoding="utf-8").read()

old = """    verified = [a for a in attacks
                if a.get(\"success\") and not a.get(\"recon\")]"""
new = """    # 检测匹配用\"可检测攻击\"：所有非 recon 的攻击行为（含未成功得手的
    # 爆破/注入尝试）。只要蓝方在时间窗口内用对应技术检测到该行为，即算有效
    # 检测（TP）——攻击行为真实发生了且被侦测到，不能因其未得手就判误报。
    eligible = [a for a in attacks if not a.get(\"recon\")]
    # 红方得分仅统计已验证成功且非 recon 的攻击（体现实际战果）。
    verified = [a for a in eligible if a.get(\"success\")]"""
assert old in src, "match1 failed"
src = src.replace(old, new)

# detection loop over eligible
old2 = """    for atk in verified:
        equiv = _host_equiv(atk.get(\"target\") or \"\", scenario)"""
new2 = """    for atk in eligible:
        equiv = _host_equiv(atk.get(\"target\") or \"\", scenario)"""
assert old2 in src, "match2 failed"
src = src.replace(old2, new2)

# FP loop over eligible
old3 = """        for atk in verified:
            equiv = _host_equiv(atk.get(\"target\") or \"\", scenario)
            ok, _weak = _matches(atk, alert, equiv, window)"""
new3 = """        for atk in eligible:
            equiv = _host_equiv(atk.get(\"target\") or \"\", scenario)
            ok, _weak = _matches(atk, alert, equiv, window)"""
assert old3 in src, "match3 failed"
src = src.replace(old3, new3)

# response statistic loop: detections built from eligible, atk lookup uses verified -> change to eligible
old4 = """    for det in detections:
        atk = next(a for a in verified if a[\"id\"] == det[\"attack_id\"])"""
new4 = """    for det in detections:
        atk = next(a for a in eligible if a[\"id\"] == det[\"attack_id\"])"""
assert old4 in src, "match4 failed"
src = src.replace(old4, new4)

open(p, "w", encoding="utf-8").write(src)
print("patched OK")