// Sidebar — CAI-first navigation.
import { useState } from 'react'
import { useArena } from '../arena'
import { Logo } from './Logo'
import { isDark } from '../theme'
import type { ViewKey } from '../types'

const NAV: { key: ViewKey; label: string }[] = [
  { key: 'cai', label: 'CAI 终端' },
  { key: 'kb', label: '安全知识库' },
  { key: 'history', label: 'CAI 历史' },
  { key: 'docs', label: '框架文档' },
]

export function Sidebar({
  view,
  onView,
}: {
  view: ViewKey
  onView: (v: ViewKey) => void
}) {
  const { connected } = useArena()
  const [dark, setDark] = useState(() => isDark())

  const toggleTheme = () => {
    const next = !dark
    setDark(next)
    document.documentElement.classList.toggle('light', !next)
    document.documentElement.classList.toggle('dark', next)
  }

  const newSession = () => onView('cai')

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
          title="进入 CyberOrion 终端"
        >
          <span style={{ fontSize: 13, lineHeight: 1, color: 'var(--color-accent)' }}>＋</span>
          CAI 终端
        </button>
        <div className="sidebar-section-title">工作台</div>
        {NAV.map((n) => (
          <button
            key={n.key}
            className={`sidebar-item ${view === n.key ? 'sidebar-item-active' : ''}`}
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
