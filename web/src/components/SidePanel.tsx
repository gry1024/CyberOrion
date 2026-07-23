import type { ControllerStatus, ThoughtStep } from '../types'
import { api } from '../api'
import { ThoughtStream } from './ThoughtStream'

interface SidePanelProps {
  side: 'red' | 'blue'
  status: ControllerStatus
  steps: ThoughtStep[]
}

export function SidePanel({ side, status, steps }: SidePanelProps) {
  const isRed = side === 'red'
  const running = isRed ? status.red_running : status.blue_running
  const paused = isRed ? status.red_paused : status.blue_paused

  const statusClass = running && !paused ? 'running' : paused ? 'paused' : 'idle'
  const statusLabel = running && !paused ? '运行中' : paused ? '已暂停' : '待命'

  return (
    <section className="side">
      <div className="side-head">
        <div className="side-head-left">
          <div className={'side-badge ' + side}>{isRed ? 'R' : 'B'}</div>
          <div>
            <div className="side-title">{isRed ? '红方攻击' : '蓝方防御'}</div>
            <div className="side-subtitle">
              {isRed ? 'Red Team · 主动攻击手' : 'CyberOrion SOC · 独立防御'}
            </div>
          </div>
        </div>
        <span className={'status-chip ' + statusClass}>
          <span className="dot"></span>
          {statusLabel}
        </span>
      </div>

      <div className="side-controls">
        <button
          className={'btn btn-sm ' + (isRed ? 'btn-red' : 'btn-blue')}
          disabled={running}
          onClick={() => (isRed ? api.redStart() : api.blueStart())}
        >
          启动{isRed ? '攻击' : '巡逻'}
        </button>
        <button
          className="btn btn-sm btn-ghost"
          disabled={!running || paused}
          onClick={() => (isRed ? api.redPause() : api.bluePause())}
        >
          暂停
        </button>
        <button
          className="btn btn-sm btn-ghost"
          disabled={!paused}
          onClick={() => (isRed ? api.redResume() : api.blueResume())}
        >
          继续
        </button>
        <button
          className="btn btn-sm btn-danger"
          disabled={!running}
          onClick={() => (isRed ? api.redStop() : api.blueStop())}
        >
          停止
        </button>
        {!isRed && (
          <>
            <button className="btn btn-sm btn-ghost" onClick={() => api.bluePatrolStart()}>
              自动巡逻
            </button>
            <button className="btn btn-sm btn-ghost" onClick={() => api.bluePatrolStop()}>
              停止巡逻
            </button>
          </>
        )}
      </div>

      <div className="side-stream">
        <ThoughtStream
          steps={steps}
          emptyHint={isRed ? '等待启动攻击…' : '等待启动防御…'}
        />
      </div>
    </section>
  )
}
