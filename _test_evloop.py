import sys
sys.path.insert(0, "/home/groy/cai/cyberorion")
sys.path.insert(0, "/home/groy/cai")
from cai.sdk.agents import Agent
from cyberorion.core.agent_runner import run_agent_once_sync

def build_agent():
    from cyberorion.agents.blue import _model
    return Agent(name="t", instructions="Say hi", tools=[], model=_model())

try:
    out = run_agent_once_sync(build_agent(), "Hello, reply briefly", max_turns=1, timeout=90)
    print("run_agent_once_sync OK ->", repr(out[:300]))
except Exception as e:
    print("run_agent_once_sync FAIL ->", type(e).__name__, str(e)[:300])