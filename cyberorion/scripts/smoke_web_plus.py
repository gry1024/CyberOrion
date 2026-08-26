"""P5 smoke: TelemetryCollector against the web_plus scenario (live docker)."""
import asyncio
import sys
import tempfile
import urllib.request
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from cyberorion.scenarios import load_scenario
from cyberorion.telemetry.collectors import TelemetryCollector
from cyberorion.telemetry.store import TelemetryStore


async def main():
    scenario = load_scenario("web_plus")
    print("resolved targets:")
    for name, t in sorted(scenario.targets.items()):
        logs = ", ".join(f"{k}={v}" for k, v in t.logs.items())
        print(f"  {name:9s} {t.container:22s} {t.ip:13s} logs: {logs}")

    db = Path(tempfile.mkdtemp()) / "smoke.db"
    store = TelemetryStore(db, session_id="smoke_p5")
    collector = TelemetryCollector(scenario, store, "smoke_p5")
    collector.start()
    print(f"collector tasks: {len(collector._tasks)}")
    await asyncio.sleep(8)  # let tails + first snapshots settle

    # Generate traffic: one 404 + one SQLi-looking request against VAmPI.
    for url in ("http://localhost:25000/nosuchendpoint",
                "http://localhost:25000/users/v1?name=%27+UNION+SELECT+password--"):
        try:
            urllib.request.urlopen(url, timeout=5)
        except Exception as exc:
            print(f"request {url} -> {exc}")

    await asyncio.sleep(12)  # wait for docker logs to stream the lines
    await collector.stop()

    events = store.query_events()
    print(f"events stored: {len(events)}")
    for e in events:
        if e["host"] == "vampi":
            print(f"  [vampi] {e['severity']:6s} {e['technique']:9s} {e['summary'][:90]}")
    print("counts:", store.counts())
    snap_hosts = sorted(
        n for n, t in scenario.targets.items()
        if store.snapshot_count(n, "process") > 0
    )
    print("hosts with process snapshots:", snap_hosts)
    store.close()


asyncio.run(main())
