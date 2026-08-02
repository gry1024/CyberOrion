// OpsConsole — 作战台底部控制条（Kimi 输入框式白色大圆角卡）
// 会话生命周期 + 红蓝启停 + 巡逻 + 场景选择 + 实时状态。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'
import { ScenarioInfoModal } from './ScenarioInfoModal'

async function call(fn: () => Promise<unknown>, label: string) {
  try {
    await fn()
  } catch (e) {
    pushToast(`${label}失败：${e instanceof Error ? e.message : String(e)}`, {
      title: '作战台',
    })
  }
}

export function OpsConsole() {
  const { status, connected, refreshStatus, refreshScenario, scenario } = useArena()
  const [busy, setBusy] = useState(false)
  const [patrol, setPatrol] = useState(false)
  const [sceneList, setSceneList] = useState<string[]>([])
  const [infoOpen, setInfoOpen] = useState(false)
  const active = status.session_active
  const redRun = status.red_running
  const blueRun = status.blue_running
  const redPaused = status.red_paused
  const bluePaused = status.blue_paused

  const wrap = (fn: () => Promise<unknown>, label: string) => {
    setBusy(true)
    void call(fn, label).finally(() => setBusy(false))
  }

  // 一键开始：会话 → 红方 → 蓝方 依次启动；任一步失败即报错停下。
  const startAll = () => {
    setBusy(true)
    void call(async () => {
      if (!status.session_active) {
        await api.sessionStart()
      }
      await api.redStart()
      await api.blueStart()
    }, '一键开始').finally(() => setBusy(false))
  }

  const togglePatrol = () => {
    const next = !patrol
    setPatrol(next)
    void call(next ? api.bluePatrolStart : api.bluePatrolStop, next ? '开启巡逻' : '关闭巡逻')
  }

  // 场景清单（一次性拉取，供切换下拉）。
  useState(() => {
    void api.getScenarios().then((r) => setSceneList(r.scenarios)).catch(() => {})
  })

  const btn = (label: string, props: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
    <button key={label} className="btn" {...props}>
      {label}
    </button>
  )

  return (
    <div className="kimi-input flex flex-none flex-col gap-2.5 px-4 py-3">
      {/* 行 1：状态 + 场景 */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-[12.5px]" style={{ color: 'var(--color-fg-3)' }}>
          <span className="dot" style={{ background: connected ? 'var(--color-green)' : 'var(--color-red)' }} />
          {connected ? '已连接' : '断开'}
        </span>
        <span className="h-3.5 w-px" style={{ background: 'var(--color-line)' }} />
        <span className="flex items-center gap-1.5 text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
          场景
          <select
            className="max-w-[200px] cursor-pointer rounded-lg border px-2 py-1 text-[12px] outline-none transition-colors hover:bg-[var(--color-panel-2)]"
            style={{ background: 'var(--color-panel)', borderColor: 'var(--color-line-2)', color: 'var(--color-fg)' }}
            value={scenario?.name ?? status.scenario ?? ''}
            onChange={(e) => {
              const name = e.target.value
              if (!name) return
              void call(async () => {
                await api.selectScenario(name)
                await refreshScenario()
                await refreshStatus()
              }, '切换场景')
            }}
            title="切换场景"
          >
            <option value="">默认靶场</option>
            {sceneList.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </span>
        <button
          className="btn h-[26px] px-2.5 text-[11.5px]"
          onClick={() => setInfoOpen(true)}
          title="查看当前靶场情报（靶机 / 红蓝期望）"
        >
          ⓘ 靶场情报
        </button>
        <span className="h-3.5 w-px" style={{ background: 'var(--color-line)' }} />
        <span className="flex items-center gap-2 text-[12.5px]" style={{ color: 'var(--color-fg-3)' }}>
          <span className="flex items-center gap-1.5">
            <span className="dot" style={{ background: redRun ? 'var(--color-red)' : 'var(--color-fg-4)' }} />
            红方 {redRun ? (redPaused ? '已暂停' : '运行中') : '空闲'}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="dot" style={{ background: blueRun ? 'var(--color-blue)' : 'var(--color-fg-4)' }} />
            蓝方 {blueRun ? (bluePaused ? '已暂停' : '运行中') : '空闲'}
          </span>
          <span className="font-mono text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
            回合 #{status.round ?? 0}
          </span>
        </span>
      </div>

      {/* 行 2：控制按钮 */}
      <div className="flex flex-wrap items-center gap-2">
        {!active ? (
          <button
            className="btn btn-primary h-9 px-5 text-[13.5px]"
            disabled={busy || redRun || blueRun}
            onClick={startAll}
            title="一键开始：自动完成 启动会话 → 红方 → 蓝方"
          >
            ⚡ 一键开始
          </button>
        ) : (
          <button
            className="btn btn-danger h-9 px-5 text-[13.5px]"
            disabled={busy}
            onClick={() => wrap(api.sessionStop, '停止会话')}
            title="结束当前会话（红蓝全部停止）"
          >
            ■ 停止会话
          </button>
        )}
        {active && (
          <>
            {btn('红方 ▶', { disabled: busy || redRun, onClick: () => wrap(api.redStart, '红方'), title: '启动红方攻击' })}
            {btn(redRun && !redPaused ? '红方 ⏸' : '红方 ▶', { disabled: busy || !redRun, onClick: () => wrap(redPaused ? api.redResume : api.redPause, redPaused ? '恢复红方' : '暂停红方'), title: redPaused ? '恢复红方' : '暂停红方' })}
            {btn('蓝方 ▶', { disabled: busy || blueRun, onClick: () => wrap(api.blueStart, '蓝方'), title: '启动蓝方防御' })}
            {btn(blueRun && !bluePaused ? '蓝方 ⏸' : '蓝方 ▶', { disabled: busy || !blueRun, onClick: () => wrap(bluePaused ? api.blueResume : api.bluePause, bluePaused ? '恢复蓝方' : '暂停蓝方'), title: bluePaused ? '恢复蓝方' : '暂停蓝方' })}
          </>
        )}
        <button
          className={`btn ${patrol ? '' : 'btn-ghost'}`}
          style={patrol ? { color: 'var(--color-blue)', borderColor: 'color-mix(in srgb, var(--color-blue) 40%, transparent)', background: 'var(--color-blue-soft)' } : undefined}
          disabled={busy}
          onClick={togglePatrol}
          title="蓝方自动巡逻（周期性遥测巡检）"
        >
          {patrol ? '◉ 巡逻中' : '○ 巡逻'}
        </button>
        <span className="ml-auto flex items-center gap-3 font-mono text-[11px] tabular-nums" style={{ color: 'var(--color-fg-4)' }}>
          <span>红 {String(status.red_history_count ?? 0).padStart(2, '0')}</span>
          <span>蓝 {String(status.blue_history_count ?? 0).padStart(2, '0')}</span>
        </span>
      </div>

      {infoOpen && <ScenarioInfoModal onClose={() => setInfoOpen(false)} />}
    </div>
  )
}
