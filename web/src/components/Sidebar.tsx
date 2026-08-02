// Sidebar — Kimi 式左侧边栏（240px）
// 顶部：品牌 logo + 新建会话（一键开始）；分组导航：作战台 / 基准测试 /
// 历史复盘 / 知识库 / 文档；底部：连接状态 + 场景 + 明暗切换。
import { useState } from 'react'
import { useArena } from '../arena'
import { api } from '../api'
import { pushToast } from '../toasts'
import { Logo } from './Logo'
import { isDark } from '../theme'
import type { ViewKey } from '../types'

const NAV: { key: ViewKey; label: string; icon: string }[] = [
  { key: 'arena', label: '作战台', icon: '◉' },
  { key: 'bench', label: '基准测试', icon: '▤' },
  { key: 'history', label: '历史复盘', icon: '◷' },
  { key: 'kb', label: '知识库', icon: '◈' },
  { key: 'docs', label: '框架文档', icon: '▤' },
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
      <div className="flex flex-none items-center gap-2.5 px-4 pb-2.5 pt-3.5">
        <Logo size={26} />
        <div className="min-w-0">
          <div className="text-[13.5px] font-semibold leading-tight tracking-tight" style={{ color: 'var(--color-fg)' }}>
            CyberOrion
          </div>
          <div className="text-[10px] leading-tight" style={{ color: 'var(--color-fg-4)' }}>
            自主红蓝对抗平台
          </div>
        </div>
      </div>

      {/* 新建会话 */}
      <div className="px-3 pb-2">
        <button
          onClick={newSession}
          disabled={busy}
          className="flex h-[36px] w-full items-center justify-center gap-2 rounded-[10px] border text-[12.5px] font-medium transition-colors"
          style={{
            background: 'var(--color-panel-2)',
            borderColor: 'var(--color-line-2)',
            color: 'var(--color-fg)',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--color-panel-3)')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--color-panel-2)')}
        >
          <span style={{ fontSize: 14, lineHeight: 1 }}>✚</span>
          {active ? '重新开始对局' : '新建会话'}
        </button>
      </div>

      {/* 导航分组 */}
      <div className="sidebar-section-title">工作台</div>
      <nav className="flex flex-col gap-0.5 px-2">
        {NAV.map((n) => (
          <button
            key={n.key}
            className={view === n.key ? 'sidebar-item sidebar-item-active' : 'sidebar-item'}
            onClick={() => onView(n.key)}
          >
            <span className="w-4 text-center text-[13px]" style={{ color: view === n.key ? 'var(--color-fg)' : 'var(--color-fg-3)' }}>
              {n.icon}
            </span>
            {n.label}
          </button>
        ))}
      </nav>

      {/* 底部状态 */}
      <div className="mt-auto flex flex-none flex-col gap-2 border-t px-4 py-3" style={{ borderColor: 'var(--color-hairline)' }}>
        <div className="flex items-center gap-2 text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
          <span className="dot" style={{ background: connected ? 'var(--color-green)' : 'var(--color-red)' }} />
          {connected ? '后端已连接' : '后端离线'}
          <button
            onClick={toggleTheme}
            className="ml-auto flex items-center gap-1 rounded-lg border px-2 py-0.5 text-[11px] transition-colors hover:bg-[var(--color-panel-2)]"
            style={{ borderColor: 'var(--color-line)', color: 'var(--color-fg-3)' }}
            title="切换明暗主题（Kimi 式）"
          >
            {dark ? '☀ 浅色' : '🌙 深色'}
          </button>
        </div>
        <div className="flex items-center gap-2 text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
          <span>场景</span>
          <span className="truncate" style={{ color: 'var(--color-fg-2)' }}>
            {status.scenario || '默认靶场'}
          </span>
        </div>
        <div className="flex items-center gap-2 text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
          <span>回合</span>
          <span className="font-mono" style={{ color: 'var(--color-fg-2)' }}>
            #{status.round ?? 0}
          </span>
          <span className="ml-auto flex items-center gap-3">
            <span className="flex items-center gap-1.5">
              <span className="dot" style={{ background: status.red_running ? 'var(--color-red)' : 'var(--color-fg-4)', boxShadow: status.red_running ? '0 0 5px var(--color-red)' : 'none' }} />
              红
            </span>
            <span className="flex items-center gap-1.5">
              <span className="dot" style={{ background: status.blue_running ? 'var(--color-blue)' : 'var(--color-fg-4)', boxShadow: status.blue_running ? '0 0 5px var(--color-blue)' : 'none' }} />
              蓝
            </span>
          </span>
        </div>
      </div>
    </aside>
  )
}
