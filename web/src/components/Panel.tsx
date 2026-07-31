// Shared panel chrome for the SOC grid.

import type { ReactNode } from 'react'

export function Panel({
  title,
  accent = 'text-text-2',
  right,
  children,
  className = '',
}: {
  title: string
  accent?: string
  right?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel flex min-h-0 flex-col overflow-hidden ${className}`}>
      <header className="panel-title">
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${accent.replace('text-', 'bg-')}`} />
        <span className={accent}>{title}</span>
        <div className="ml-auto flex items-center gap-2">{right}</div>
      </header>
      {children}
    </section>
  )
}
