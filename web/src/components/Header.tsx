import type { ControllerStatus } from '../types'
import { api } from '../api'

interface HeaderProps {
  connected: boolean
  status: ControllerStatus
}

export function Header({ connected, status }: HeaderProps) {
  return (
    <header className="app-header">
      <div className="app-header-row">
        <div>
          <h1 className="app-title">CyberOrion Arena</h1>
          <div className="app-subtitle">红蓝实时博弈 · 中枢控制 · 思考流可视化</div>
        </div>
        <div className={'conn-pill' + (connected ? ' connected' : '')}>
          <span className="conn-dot"></span>
          <span>{connected ? '实时连接' : '未连接'}</span>
        </div>
      </div>

      <div className="session-bar">
        <button className="btn btn-primary" onClick={() => api.sessionStart()}>
          启动会话
        </button>
        <button className="btn btn-danger" onClick={() => api.sessionStop()}>
          结束会话
        </button>
        <div className="session-meta">
          <span>轮次 <strong>{status.round}</strong></span>
          <span>红方记录 <strong>{status.red_history_count}</strong></span>
          <span>蓝方记录 <strong>{status.blue_history_count}</strong></span>
        </div>
      </div>
    </header>
  )
}
