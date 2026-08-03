// OpsConsole — 作战台控制条（Cursor 式：平铺一行按钮，无圆角卡）
// 会话生命周期 + 红蓝启停 + 巡逻 + 场景选择 + 靶机信息入口。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'
import { ScenarioInfoModal } from './ScenarioInfoModal'

async function call(fn: () => Promise<unknown>, label: string) {
  try {
    await fn()
  } catch (e) {
    pushToast(`${label}失败：${e instanceof Error ? e.message : String(e)}`, { title: '作战台' })
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

  const wrap = (fn: () => Promise<unknown>, label: string) => {
    setBusy(true)
    void call(fn, label).finally(() => setBusy(false))
  }

  const startAll = () => {
    setBusy(true)
    void call(async () => {
      if (!status.session_active) await api.sessionStart()
      await api.redStart()
      await api.blueStart()
    }, '一键开始').finally(() => setBusy(false))
  }

  const togglePatrol = () => {
    const next = !patrol
    setPatrol(next)
    void call(next ? api.bluePatrolStart : api.bluePatrolStop, next ? '开启巡逻' : '关闭巡逻')
  }

  useState(() => {
    void api.getScenarios().then((r) => setSceneList(r.scenarios)).catch(() => {})
  })

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {!active ? (
        <button className="btn btn-primary" disabled={busy} onClick={startAll}>一键开始</button>
      ) : (
        <button className="btn btn-danger" disabled={busy} onClick={() => wrap(api.sessionStop, '停止会话')}>停止</button>
      )}
      {active && (
        <>
          <button className="btn" disabled={busy || redRun} onClick={() => wrap(api.redStart, '红方')}>红方 ▶</button>
          <button className="btn" disabled={busy || !redRun} onClick={() => wrap(api.redStop, '红方')}>红方 ■</button>
          <button className="btn" disabled={busy || blueRun} onClick={() => wrap(api.blueStart, '蓝方')}>蓝方 ▶</button>
          <button className="btn" disabled={busy || !blueRun} onClick={() => wrap(api.blueStop, '蓝方')}>蓝方 ■</button>
        </>
      )}
      <button className={`btn ${patrol ? '' : 'btn-ghost'}`} disabled={busy} onClick={togglePatrol}>
        {patrol ? '巡逻中' : '巡逻'}
      </button>
      <select
        className="h-[24px] cursor-pointer rounded border bg-[var(--color-panel-2)] px-1.5 text-[11.5px] outline-none"
        style={{ borderColor: 'var(--color-line)', color: 'var(--color-fg)' }}
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
        <option value="">{status.scenario || '默认靶场'}</option>
        {sceneList.map((s) => (<option key={s} value={s}>{s}</option>))}
      </select>
      <button className="btn btn-ghost" onClick={() => setInfoOpen(true)} title="靶机信息（靶机 / 红蓝期望）">靶机信息</button>
      <span className="ml-auto flex items-center gap-2 font-mono text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
        <span className="dot" style={{ background: connected ? 'var(--color-green)' : 'var(--color-red)' }} />
        {connected ? '在线' : '离线'}
        {active && <span>回合 #{status.round ?? 0}</span>}
      </span>
      {infoOpen && <ScenarioInfoModal onClose={() => setInfoOpen(false)} />}
    </div>
  )
}
