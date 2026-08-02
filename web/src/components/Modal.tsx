// Modal — 通用弹窗外壳（场景信息 / 套件说明 / Agent 详情）。
// Kimi 式：白卡片 + 细边框 + 柔和阴影；portal 挂 body 避开 transform 劫持。

import { createPortal } from 'react-dom'
import type { ReactNode } from 'react'

export function Modal({
  title,
  onClose,
  children,
  width = 'w-[640px]',
}: {
  title: string
  onClose: () => void
  children: ReactNode
  width?: string
}) {
  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/25 p-6"
      onClick={onClose}
    >
      <div
        className={`scroll-thin flex max-h-[82vh] ${width} max-w-full flex-col overflow-hidden rounded-2xl`}
        style={{
          background: 'var(--color-panel)',
          border: '1px solid var(--color-line-2)',
          boxShadow: '0 20px 60px rgba(0, 0, 0, 0.16)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex flex-none items-center gap-2.5 border-b px-5 py-3.5" style={{ borderColor: 'var(--color-hairline)' }}>
          <span className="text-[14px] font-semibold" style={{ color: 'var(--color-fg)' }}>{title}</span>
          <button
            onClick={onClose}
            className="ml-auto rounded-full border px-3 py-1 text-[11px] transition-colors hover:bg-[var(--color-panel-2)]"
            style={{ borderColor: 'var(--color-line)', color: 'var(--color-fg-3)' }}
          >
            关闭 ✕
          </button>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {children}
        </div>
      </div>
    </div>,
    document.body,
  )
}
