import sys
sys.path.insert(0, "/home/groy/cai/cyberorion")
sys.path.insert(0, "/home/groy/cai")
from cyberorion.telemetry import TelemetryStore
from cyberorion.eval.metrics import compute_metrics

s = TelemetryStore("/home/groy/cai/cyberorion/logs/session_20260817_124111/telemetry.db")
m = compute_metrics(s)
print("totals:", m["totals"])
print("tp:", m["tp"], "fn:", m["fn"], "fp:", m["fp"])
print("detection_rate:", m["detection_rate"], "fp_rate:", m["fp_rate"], "response_rate:", m["response"]["response_rate"])
print("blue_score:", m["blue_score"], "red_score:", m["red_score"])
print("detections:", [(d["attack_id"], d["target"], d["technique"]) for d in m["detections"]])
print("false_positives:", [(f["host"], f["technique"]) for f in m["false_positives"]])
print("missed:", [(x["target"], x["technique"]) for x in m["missed"]])
s.close()