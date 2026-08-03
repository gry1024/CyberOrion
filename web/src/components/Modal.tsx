// Modal — 通用弹窗外壳（Cursor 式：小圆角、轻描边、无重阴影）。

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
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-6"
      onClick={onClose}
    >
      <div
        className={`scroll-thin flex max-h-[82vh] ${width} max-w-full flex-col overflow-hidden rounded-lg`}
        style={{
          background: 'var(--color-bg-2)',
          border: '1px solid var(--color-line-2)',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex flex-none items-center gap-2.5 border-b px-4 py-2" style={{ borderColor: 'var(--color-hairline)' }}>
          <span className="text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>{title}</span>
          <button
            onClick={onClose}
            className="ml-auto rounded px-2 py-0.5 text-[11px] transition-colors hover:bg-[var(--color-overlay)]"
            style={{ color: 'var(--color-fg-3)' }}
          >
            关闭 ✕
          </button>
        </header>
        <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-4 py-3">
          {children}
        </div>
      </div>
    </div>,
    document.body,
  )
}
