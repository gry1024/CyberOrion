// ArenaView — 作战舱（正文优先：靶机透明、红蓝双流、底部控制）。
import { useEffect, useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { useDemoReplay } from '../demoReplay'
import { pushToast } from '../toasts'
import { ChatStream } from './ChatStream'
import { DispatchGraph } from './DispatchGraph'
import { Modal } from './Modal'
import { RangeCards } from './RangeCards'
import type { HostStatus, ScenarioDetail, TargetInfo } from '../types'

function BattleConsole({ onDemo, demoPlaying, demoSession }: {
  onDemo: () => void
  demoPlaying: boolean
  demoSession: string
}) {
  const { status, refreshStatus, clearSteps } = useArena()
  const [busy, setBusy] = useState(false)
  const active = status.session_active
  const redRun = status.red_running
  const blueRun = status.blue_running
  const pending = new Set(status.pending_agent_starts ?? [])

  const call = async (fn: () => Promise<unknown>, label: string) => {
    setBusy(true)
    try {
      await fn()
    } catch (e) {
        pushToast(`${label}失败：${e instanceof Error ? e.message : String(e)}`, { title: '作战台' })
    } finally {
      setBusy(false)
      void refreshStatus()
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button className="btn" disabled={busy || active || demoPlaying} onClick={onDemo}>
        {demoPlaying ? '演示中' : '演示'}
      </button>
      {active && (
        <>
          <button className="btn" disabled={busy || redRun || pending.has('red')} onClick={() => void call(async () => { clearSteps('red'); await api.redStart() }, '红方')}>
            {pending.has('red') ? '红方待启动' : '红方 ▶'}
          </button>
          <button className="btn" disabled={busy || !redRun} onClick={() => void call(api.redStop, '红方')}>红方 ■</button>
          <button className="btn" disabled={busy || blueRun || pending.has('blue')} onClick={() => void call(async () => { clearSteps('blue'); await api.blueStart() }, '蓝方')}>
            {pending.has('blue') ? '蓝方待启动' : '蓝方 ▶'}
          </button>
          <button className="btn" disabled={busy || !blueRun} onClick={() => void call(api.blueStop, '蓝方')}>蓝方 ■</button>
        </>
      )}
      <span className="ml-auto text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
        {status.session_boot_error ? `启动失败：${status.session_boot_error}` : demoSession ? `演示日志 ${demoSession}` : active ? '会话运行中' : '未启动'}
      </span>
    </div>
  )
}

function TargetCard({
  target,
  hostState,
}: {
  target: TargetInfo
  hostState: HostStatus | undefined
}) {
  // 状态映射：边框色 + 徽章文案 + 圆点。HostState = 'normal'|'alert'|'compromised'|'hardened'
  const palette = {
    compromised: { ring: 'border-attacker', dot: 'bg-attacker', badge: '🔥 已失陷' },
    hardened: { ring: 'border-blue', dot: 'bg-blue', badge: '🛡 已加固' },
    alert: { ring: 'border-warning', dot: 'bg-warning', badge: '⚠ 告警' },
  } as const
  const p = hostState && hostState.state !== 'normal' ? palette[hostState.state] : null
  const ringColor = p?.ring ?? 'border-hairline'
  const dotColor = p?.dot ?? 'bg-fg-4/40'
  const tsText = hostState
    ? new Date(hostState.ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })
    : ''
  return (
    <div
      className={`min-w-[190px] border px-2 py-1.5 ${ringColor}`}
      style={{ background: 'var(--color-bg-2)' }}
    >
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 flex-none rounded-full ${dotColor}`} />
        <span className="font-mono text-[11px]" style={{ color: 'var(--color-fg)' }}>{target.name}</span>
        <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>{target.ip || 'localhost'}</span>
      </div>
      <div className="mt-0.5 truncate font-mono text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
        {target.services.map((svc) => `${svc.proto}:${svc.host_port}->${svc.container_port}`).join(' · ')}
      </div>
      <div className="mt-1 flex items-center justify-between font-mono text-[9.5px]" style={{ color: 'var(--color-fg-2)' }}>
        <span>{p?.badge ?? '○ 静默'}</span>
        {tsText && <span style={{ color: 'var(--color-fg-4)' }}>{tsText}</span>}
      </div>
    </div>
  )
}

export function ArenaView() {
  const { status, scenario, redSteps, blueSteps, hosts } = useArena()
  const demo = useDemoReplay('red_adversary')
  const [scenarioOpen, setScenarioOpen] = useState(false)
  const [scenarioDetail, setScenarioDetail] = useState<ScenarioDetail | null>(null)
  const sceneName = scenario?.name || status.scenario || '默认场景'
  useEffect(() => {
    let stale = false
    api.getScenarioInfo().then((value) => {
      if (!stale) setScenarioDetail(value)
    }).catch(() => {})
    return () => { stale = true }
  }, [sceneName])
  const playDemo = () => void demo.play().catch((error) => {
    pushToast(`演示启动失败：${error instanceof Error ? error.message : String(error)}`, { title: '作战台' })
  })
  const shownRedSteps = demo.redSteps.length || demo.playing ? demo.redSteps : redSteps
  const shownBlueSteps = demo.blueSteps.length || demo.playing ? demo.blueSteps : blueSteps
  const targets = scenarioDetail?.targets ?? scenario?.targets ?? []

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Single production architecture: no legacy version selector. */}
      <div className="flex flex-none items-center gap-2 border-b px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>作战舱</span>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-3)' }}>当前靶场：{sceneName}</span>
        <span className="ml-2 font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>CTF LIVE RANGE</span>
        <button className="btn ml-2" onClick={() => setScenarioOpen(true)} style={{ height: 22, fontSize: 11 }}>
          靶机信息
        </button>
        <span className="ml-auto text-[10.5px]" style={{ color: 'var(--color-fg-4)' }}>
          红 {status.red_running ? '●' : '○'} · 蓝 {status.blue_running ? '●' : '○'}
        </span>
      </div>

      <RangeCards />

      <div className="flex flex-none gap-2 overflow-x-auto border-b px-3 py-2" style={{ borderColor: 'var(--color-hairline)' }}>
        {targets.map((target) => (
          <button
            key={target.name}
            type="button"
            className="text-left"
            onClick={() => setScenarioOpen(true)}
          >
            <TargetCard target={target} hostState={hosts[target.name]} />
          </button>
        ))}
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="flex min-w-0 flex-col" style={{ flex: '0 0 48%', minHeight: 0 }}>
          <ChatStream
            side="red"
            steps={shownRedSteps}
            running={Boolean(status.red_running) || demo.playing}
            accent="red"
            emptyTitle="红方未启动"
            emptyDesc="红队由 orchestrator 编排侦察、凭据访问、提权与横向移动 Agent。"
          />
        </div>
        <div className="w-px flex-none" style={{ background: 'var(--color-hairline)' }} />
        <div className="flex min-w-0 flex-1 flex-col" style={{ minHeight: 0 }}>
          <DispatchGraph v2 />
          <ChatStream
            side="blue"
            steps={shownBlueSteps}
            running={Boolean(status.blue_running) || demo.playing}
            accent="blue"
            emptyTitle="蓝方监控面板"
            emptyDesc="SOC 指挥官派遣分诊、威胁狩猎、横向分析与升级处置 Agent。"
          />
        </div>
      </div>

      <div className="flex-none border-t px-3 py-1.5" style={{ borderColor: 'var(--color-hairline)' }}>
        <BattleConsole
          onDemo={playDemo}
          demoPlaying={demo.playing}
          demoSession={demo.sessionId}
        />
      </div>
      {scenarioOpen && scenarioDetail && (
        <Modal title={`靶场信息 · ${scenarioDetail.name}`} onClose={() => setScenarioOpen(false)} width="w-[920px]">
          <div className="space-y-4 text-[12px]" style={{ color: 'var(--color-fg-2)' }}>
            <p>{scenarioDetail.description || 'CTF 风格授权靶场：只允许攻击本页列出的本地容器、IP 与宿主映射端口。'}</p>
            <div className="grid gap-3 md:grid-cols-2">
              {scenarioDetail.targets.map((target) => (
                <section key={target.name} className="border p-3" style={{ borderColor: 'var(--color-hairline)', background: 'var(--color-bg)' }}>
                  <h3 className="font-mono text-[13px]" style={{ color: 'var(--color-fg)' }}>{target.name}</h3>
                  <div className="mt-1 grid grid-cols-[90px_1fr] gap-y-1 font-mono text-[11px]">
                    <span style={{ color: 'var(--color-fg-4)' }}>容器</span><span>{target.container}</span>
                    <span style={{ color: 'var(--color-fg-4)' }}>内网 IP</span><span>{target.ip || '-'}</span>
                    <span style={{ color: 'var(--color-fg-4)' }}>服务</span>
                    <span>{target.services.map((svc) => `${svc.name}/${svc.proto} 宿主:${svc.host_port} → 容器:${svc.container_port}`).join('；')}</span>
                    <span style={{ color: 'var(--color-fg-4)' }}>日志源</span>
                    <span>{Object.entries(target.logs).map(([k, v]) => `${k}: ${v}`).join('；') || '-'}</span>
                  </div>
                </section>
              ))}
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <section>
                <h3 className="mb-1 text-[12px] font-semibold" style={{ color: 'var(--color-fg)' }}>红方任务</h3>
                <ul className="list-disc space-y-1 pl-5">{scenarioDetail.red_objectives.map((item) => <li key={item}>{item}</li>)}</ul>
              </section>
              <section>
                <h3 className="mb-1 text-[12px] font-semibold" style={{ color: 'var(--color-fg)' }}>蓝方任务</h3>
                <ul className="list-disc space-y-1 pl-5">{scenarioDetail.blue_objectives.map((item) => <li key={item}>{item}</li>)}</ul>
              </section>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
