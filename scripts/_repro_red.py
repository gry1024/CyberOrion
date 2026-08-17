import sys, asyncio, traceback
sys.path.insert(0, "/home/groy/cai")
sys.path.insert(0, "/home/groy/cai/cyberorion")
from dotenv import load_dotenv
load_dotenv("/home/groy/cai/.env")

from cyberorion.core.event_bus import EventBus
from cyberorion.core.session_state import SessionState
from cyberorion.core.controller import Controller

async def main():
    eb = EventBus()
    ss = SessionState()
    c = Controller(eb, ss)
    await c.start_session()
    print("session started; red agent built")
    red_agent = c._red_agent
    print("red agent type:", type(red_agent))
    from cyberorion.core.agent_runner import AgentRunner
    runner = AgentRunner(eb, "red")
    try:
        result = await runner.run(red_agent, "ping", max_turns=1, timeout=120)
        print("OUTPUT:", str(result.get("output", ""))[:600])
    except Exception:
        traceback.print_exc()

asyncio.run(main())