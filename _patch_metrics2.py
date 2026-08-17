import re
p = "/home/groy/cai/cyberorion/cyberorion/eval/metrics.py"
src = open(p, encoding="utf-8").read()

# add n_eligible after n_verified
old = """    n_verified = len(verified)
    n_malicious = len(malicious_alerts)"""
new = """    n_verified = len(verified)
    n_eligible = len(eligible)
    n_malicious = len(malicious_alerts)"""
assert old in src, "m1"
src = src.replace(old, new, 1)

# detection_rate denominator -> n_eligible (all detectable non-recon attacks)
old2 = """    detection_rate = tp / n_verified if n_verified else 0.0"""
new2 = """    detection_rate = tp / n_eligible if n_eligible else 0.0"""
assert old2 in src, "m2"
src = src.replace(old2, new2, 1)

open(p, "w", encoding="utf-8").write(src)
print("patched detection_rate OK")