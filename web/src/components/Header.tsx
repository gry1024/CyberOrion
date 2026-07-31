// Header bar: logo + wordmark, view switch (作战台 | Benchmark | 历史 |
// 知识图谱), scenario selector, session controls, LIVE indicator.
// CodeNest dark-green style: glass bar, pill buttons, green segmented tabs.
// 关键操作（会话/红蓝 开始停止、场景切换）失败一律 toast，绝不静默。

import { useEffect, useState } from 'react'
import { api } from '../api'
import { useArena } from '../arena'
import { pushToast } from '../toasts'
import type { ViewKey } from '../types'

/** 统一的关键操作错误出口：HTTP 非 2xx / 后端 ok:false / 网络失败。 */
function reportFailure(action: string, e: unknown): void {
  const msg = e instanceof Error ? e.message : String(e)
  pushToast(`${action}失败：${msg}`, { side: 'system', title: '操作失败' })
}

function CtrlButton({
  label,
  action,
  onClick,
  variant = 'ghost',
  disabled = false,
}: {
  label: string
  /** 中文操作名，用于失败 toast（如 "红方开始"）。 */
  action: string
  onClick: () => Promise<unknown>
  variant?: 'primary' | 'danger' | 'ghost' | 'accent'
  disabled?: boolean
}) {
  const [busy, setBusy] = useState(false)
  const cls = {
    primary: 'btn-primary',
    danger: 'btn-danger',
    ghost: 'btn-ghost',
    accent: 'btn-accent-ghost',
  }[variant]
  return (
    <button
      disabled={disabled || busy}
      onClick={() => {
        setBusy(true)
        onClick()
          .then((r) => {
            // 后端 200 但 ok:false（如 409 冲突经 JSONResponse 返回）
            const body = r as { ok?: boolean; error?: string } | null
            if (body && body.ok === false) {
              pushToast(`${action}失败：${body.error ?? '未知错误'}`, {
                side: 'system',
                title: '操作失败',
              })
            }
          })
          .catch((e) => reportFailure(action, e))
          .finally(() => setBusy(false))
      }}
      className={`btn-pill ${cls}`}
    >
      {label}
    </button>
  )
}

function ViewSwitch({
  view,
  onChange,
}: {
  view: ViewKey
  onChange: (v: ViewKey) => void
}) {
  const items: Array<{ key: ViewKey; label: string }> = [
    { key: 'arena', label: '作战台' },
    { key: 'bench', label: 'Benchmark' },
    { key: 'history', label: '历史' },
    { key: 'kb', label: '知识图谱' },
  ]
  return (
    <div className="flex items-center rounded-full border border-hairline bg-white/[0.03] p-0.5">
      {items.map((it) => (
        <button
          key={it.key}
          onClick={() => onChange(it.key)}
          className={`rounded-full px-3.5 py-1 font-display text-[11px] font-bold tracking-wide transition-colors ${
            view === it.key
              ? 'bg-white/5 text-accent'
              : 'text-neutral-400 hover:text-neutral-200'
          }`}
        >
          {it.label}
        </button>
      ))}
    </div>
  )
}

export function Header({
  view,
  onViewChange,
}: {
  view: ViewKey
  onViewChange: (v: ViewKey) => void
}) {
  const { connected, status, scenario, refreshScenario, refreshStatus } =
    useArena()
  const [scenarioNames, setScenarioNames] = useState<string[]>([])

  useEffect(() => {
    api
      .getScenarios()
      .then((r) => setScenarioNames(r.scenarios))
      .catch(() => {
        /* backend not ready */
      })
  }, [])

  const activeName = scenario?.name ?? status.scenario ?? ''
  const names = scenarioNames.includes(activeName)
    ? scenarioNames
    : [activeName, ...scenarioNames].filter(Boolean)

  const onSelect = (name: string) => {
    if (!name || name === activeName) return
    void api
      .selectScenario(name)
      .then((r) => {
        if (!r.ok) {
          pushToast(`场景切换失败：${r.error ?? '未知错误'}`, {
            side: 'system',
            title: '操作失败',
          })
          return
        }
        void refreshScenario()
        void refreshStatus()
      })
      .catch((e) => reportFailure('场景切换', e))
  }

  return (
    <header className="glass relative z-20 flex h-14 flex-none items-center gap-4 border-b border-hairline px-5">
      {/* wordmark */}
      <div className="flex items-center gap-2.5">
        <img src="/logo.svg" alt="CyberOrion" className="h-[22px] w-[22px]" />
        <div className="leading-tight">
          <div className="text-[14px] font-extrabold tracking-wide text-text-1">
            CyberOrion<span className="text-accent">.</span>{' '}
            <span className="font-serif italic text-accent/80">2.0</span>
          </div>
          <div className="font-display text-[8px] font-bold uppercase tracking-[0.28em] text-text-3">
            Red · Blue LLM Arena
          </div>
        </div>
      </div>

      {/* top-level view switch */}
      <ViewSwitch view={view} onChange={onViewChange} />

      {/* scenario selector (disabled while a session is active) */}
      <div className="flex items-center gap-1 rounded-full border border-hairline bg-white/[0.03] px-3 py-1 text-[10px] text-neutral-400">
        场景
        <select
          value={activeName}
          disabled={status.session_active}
          onChange={(e) => onSelect(e.target.value)}
          className="ml-1 max-w-[180px] truncate rounded-full border border-hairline bg-ink px-1.5 py-0.5 font-medium text-neutral-200
            outline-none transition-colors hover:border-accent/40 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {names.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <span className="ml-1 font-mono text-text-3">R{status.round}</span>
      </div>

      {/* controls */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          <span className="eyebrow mr-0.5 !text-text-2">会话</span>
          <CtrlButton label="开始" action="会话开始" variant="primary" onClick={() => api.sessionStart()} />
          <CtrlButton label="停止" action="会话停止" variant="danger" onClick={() => api.sessionStop()} />
        </div>
        <div className="flex items-center gap-1.5 border-l border-hairline pl-3">
          <span className="eyebrow mr-0.5 !text-attacker/70">红方</span>
          <CtrlButton label="开始" action="红方开始" variant="danger" onClick={() => api.redStart()} />
          {status.red_paused ? (
            <CtrlButton label="恢复" action="红方恢复" variant="danger" onClick={() => api.redResume()} />
          ) : (
            <CtrlButton label="暂停" action="红方暂停" variant="ghost" onClick={() => api.redPause()} />
          )}
          <CtrlButton label="停止" action="红方停止" variant="ghost" onClick={() => api.redStop()} />
        </div>
        <div className="flex items-center gap-1.5 border-l border-hairline pl-3">
          <span className="eyebrow mr-0.5">蓝方</span>
          <CtrlButton label="开始" action="蓝方开始" variant="accent" onClick={() => api.blueStart()} />
          {status.blue_paused ? (
            <CtrlButton label="恢复" action="蓝方恢复" variant="accent" onClick={() => api.blueResume()} />
          ) : (
            <CtrlButton label="暂停" action="蓝方暂停" variant="ghost" onClick={() => api.bluePause()} />
          )}
          <CtrlButton label="停止" action="蓝方停止" variant="ghost" onClick={() => api.blueStop()} />
          <CtrlButton label="巡逻" action="巡逻开始" variant="accent" onClick={() => api.bluePatrolStart()} />
          <CtrlButton label="停巡" action="巡逻停止" variant="ghost" onClick={() => api.bluePatrolStop()} />
        </div>
      </div>

      <div className="ml-auto flex items-center gap-4">
        {/* LIVE */}
        <div className="flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              connected ? 'bg-accent live-pulse' : 'bg-attacker'
            }`}
          />
          <span
            className={`font-display text-[9px] font-bold uppercase tracking-[0.2em] ${
              connected ? 'text-accent' : 'text-attacker'
            }`}
          >
            {connected ? 'Live' : '离线'}
          </span>
        </div>
      </div>
    </header>
  )
}
