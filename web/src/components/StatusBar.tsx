// Bottom status bar: WS connection, round, event/step counts.
// (历史回放 was promoted to a top-level 「历史」 tab.)

import { useArena } from '../arena'

export function StatusBar() {
  const { connected, status, timeline, alerts, redSteps, blueSteps } = useArena()

  return (
    <footer className="flex-none">
      <div className="flex h-7 items-center gap-4 border-t border-hairline bg-ink px-4 font-mono text-[9px] text-neutral-600">
        <span className="flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              connected ? 'bg-success' : 'bg-attacker'
            }`}
          />
          {connected ? 'WS 已连接' : 'WS 断开 · 重连中'}
        </span>
        <span>
          回合 <span className="text-neutral-400">R{status.round}</span>
        </span>
        <span>
          事件 <span className="text-neutral-400">{timeline.length}</span>
        </span>
        <span>
          告警 <span className="text-neutral-400">{alerts.length}</span>
        </span>
        <span>
          红 <span className="text-attacker/70">{redSteps.length}</span> 步 · 蓝{' '}
          <span className="text-defender/70">{blueSteps.length}</span> 步
        </span>
      </div>
    </footer>
  )
}
