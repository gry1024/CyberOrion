// Sidebar — Cursor/VSCode 式左侧边栏（208px，平铺列表导航）
// 顶部：品牌；「新建会话」= 列表首项；分组导航；底部极简状态。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'
import { Logo } from './Logo'
import { isDark } from '../theme'
import type { ViewKey } from '../types'

const NAV: { key: ViewKey; label: string }[] = [
  { key: 'arena', label: '作战台' },
  { key: 'traffic', label: '流量分析' },
  { key: 'bench', label: '基准测试' },
  { key: 'history', label: '历史复盘' },
  { key: 'kb', label: '知识库' },
  { key: 'docs', label: '框架文档' },
]

export function Sidebar({
  view,
  onView,
}: {
  view: ViewKey
  onView: (v: ViewKey) => void
}) {
  const { connected, status } = useArena()
  const [busy, setBusy] = useState(false)
  const [dark, setDark] = useState(() => isDark())
  const active = status.session_active

  const toggleTheme = () => {
    const next = !dark
    setDark(next)
    document.documentElement.classList.toggle('light', !next)
    document.documentElement.classList.toggle('dark', next)
  }

  const newSession = () => {
    if (busy) return
    setBusy(true)
    void (async () => {
      try {
        if (!status.session_active) await api.sessionStart()
        await api.redStart()
        await api.blueStart()
        onView('arena')
      } catch (e) {
        pushToast(`一键开始失败：${e instanceof Error ? e.message : String(e)}`, {
          title: '作战台',
        })
      } finally {
        setBusy(false)
      }
    })()
  }

  return (
    <aside className="sidebar">
      {/* 品牌 */}
      <div className="flex flex-none items-center gap-2 px-3 pb-1.5 pt-3">
        <Logo size={20} />
        <span className="text-[12px] font-semibold tracking-tight" style={{ color: 'var(--color-fg)' }}>
          CyberOrion
        </span>
      </div>

      {/* 导航 */}
      <nav className="flex flex-1 flex-col gap-px overflow-y-auto px-1 py-1">
        <button
          className="sidebar-item"
          onClick={newSession}
          disabled={busy}
          title={active ? '重新开始对局' : '一键开始：会话 → 红方 → 蓝方'}
        >
          <span style={{ fontSize: 13, lineHeight: 1, color: 'var(--color-accent)' }}>＋</span>
          {active ? '重新开始对局' : '新建会话'}
        </button>
        <div className="sidebar-section-title">工作台</div>
        {NAV.map((n) => (
          <button
            key={n.key}
            className={`sidebar-item relative ${view === n.key ? 'sidebar-item-active' : ''}`}
            onClick={() => onView(n.key)}
          >
            {n.label}
          </button>
        ))}
      </nav>

      {/* 底部：一行状态 */}
      <div className="flex flex-none items-center gap-2 border-t px-3 py-1.5 text-[11px]" style={{ borderColor: 'var(--color-hairline)', color: 'var(--color-fg-3)' }}>
        <span className="dot" style={{ background: connected ? 'var(--color-green)' : 'var(--color-red)' }} />
        <span className="truncate">{connected ? '后端在线' : '后端离线'}</span>
        <button
          onClick={toggleTheme}
          className="ml-auto rounded px-1.5 py-0.5 text-[10.5px] transition-colors hover:bg-[var(--color-overlay)]"
          style={{ color: 'var(--color-fg-4)' }}
          title="切换明暗"
        >
          {dark ? '浅色' : '深色'}
        </button>
      </div>
    </aside>
  )
}
