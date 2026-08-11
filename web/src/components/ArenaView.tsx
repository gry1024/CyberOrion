// ArenaView — 作战舱（Cursor 式：平铺双栏，无卡片）
// 顶部标题栏含 v1/v2 模式切换；中部红/蓝双栏；底部控制板。
// v2 模式：多角色架构（红 7 worker + orch / 蓝 4 worker + orch），独立 v2 控制按钮。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'
import { ChatStream } from './ChatStream'
import { DispatchGraph } from './DispatchGraph'
import { OpsConsole } from './OpsConsole'

/** v2 作战控制条：会话/红蓝编排器启停。 */
function V2Console() {
  const { status, refreshStatus } = useArena()
  const [busy, setBusy] = useState(false)
  const active = status.session_active
  const redRun = status.red_running
  const blueRun = status.blue_running

  const call = async (fn: () => Promise<unknown>, label: string) => {
    setBusy(true)
    try {
      await fn()
    } catch (e) {
      pushToast(`${label}失败：${e instanceof Error ? e.message : String(e)}`, { title: 'v2 作战台' })
    } finally {
      setBusy(false)
      void refreshStatus()
    }
  }

  const startAll = () => void call(async () => {
    if (!active) await api.startV2Session()
    await api.startV2Red()
    await api.startV2Blue()
  }, 'v2 一键开始')

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {!active ? (
        <button className="btn btn-primary" disabled={busy} onClick={startAll}>v2 一键开始</button>
      ) : (
        <button className="btn btn-danger" disabled={busy} onClick={() => void call(api.stopV2Session, '停止 v2 会话')}>停止</button>
      )}
      {active && (
        <>
          <button className="btn" disabled={busy || redRun} onClick={() => void call(api.startV2Red, 'v2 红方')}>红方 ▶</button>
          <button className="btn" disabled={busy || !redRun} onClick={() => void call(api.stopV2Red, 'v2 红方')}>红方 ■</button>
          <button className="btn" disabled={busy || blueRun} onClick={() => void call(api.startV2Blue, 'v2 蓝方')}>蓝方 ▶</button>
          <button className="btn" disabled={busy || !blueRun} onClick={() => void call(api.stopV2Blue, 'v2 蓝方')}>蓝方 ■</button>
        </>
      )}
      <span className="ml-auto text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>v2 多角色架构</span>
    </div>
  )
}

export function ArenaView() {
  const { status, scenario, redSteps, blueSteps } = useArena()
  const [v2, setV2] = useState(false)
  const sceneName = scenario?.name || status.scenario || '默认场景'

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* 场景标题 + v1/v2 模式切换 */}
      <div className="flex flex-none items-center gap-2 border-b px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>作战舱</span>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>{sceneName}</span>
        {/* v1/v2 模式切换器 */}
        <div className="ml-2 flex items-center gap-px rounded" style={{ background: 'var(--color-panel-2)' }}>
          <button
            className="rounded px-2 py-0.5 text-[10.5px] transition-colors"
            style={{ background: !v2 ? 'var(--color-overlay)' : 'transparent', color: !v2 ? 'var(--color-fg)' : 'var(--color-fg-3)' }}
            onClick={() => setV2(false)}
          >v1</button>
          <button
            className="rounded px-2 py-0.5 text-[10.5px] transition-colors"
            style={{ background: v2 ? 'var(--color-overlay)' : 'transparent', color: v2 ? 'var(--color-fg)' : 'var(--color-fg-3)' }}
            onClick={() => setV2(true)}
          >v2 多角色</button>
        </div>
        <span className="ml-auto text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
          红 {status.red_running ? '●' : '○'} · 蓝 {status.blue_running ? '●' : '○'}
        </span>
      </div>

      {/* 红蓝双栏：左 40%、右 60%，中间 1px 分隔线 */}
      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 40%', minHeight: 0 }}>
          <ChatStream
            side="red"
            steps={redSteps}
            running={Boolean(status.red_running)}
            accent="red"
            emptyTitle="红方未启动"
            emptyDesc={v2 ? 'v2 红队 7 worker：recon→credential_access→cracker→acl→privesc→lateral→coercion，由 orchestrator 编排。' : '点击下方开始，红队将自动完成侦察/枚举/漏洞利用与权限提升。'}
          />
        </div>
        <div className="w-px flex-none" style={{ background: 'var(--color-hairline)' }} />
        <div className="flex min-w-0 flex-1 flex-col" style={{ minHeight: 0 }}>
          <DispatchGraph v2={v2} />
          <ChatStream
            side="blue"
            steps={blueSteps}
            running={Boolean(status.blue_running)}
            accent="blue"
            emptyTitle="蓝方监控面板"
            emptyDesc={v2 ? 'v2 蓝队 4 worker：triage/threat_hunter/lateral_analyst/escalation_triage + SOC orchestrator。' : '哨兵 watcher 持续轮询检测，分析师 analyst 解析日志，处置 responder 执行封禁。'}
          />
        </div>
      </div>

      {/* 控制板：v1 用 OpsConsole，v2 用 V2Console */}
      <div className="flex-none border-t px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        {v2 ? <V2Console /> : <OpsConsole />}
      </div>
    </div>
  )
}
