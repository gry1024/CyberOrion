// CyberOrion — fixed-viewport shell with a top-level view switch:
// 作战台: header · [left rail: 拓扑+告警 | center: 红(2/5) terminal / 蓝(3/5)
// per-agent panels | right rail: 事件时间线] · status bar.
// Benchmark / 历史 / 知识图谱: full-page views.
//
// Layout invariant (overlap fix): every flex track that holds stream content
// carries min-w-0 and panels carry overflow-hidden, so no cell can exceed its
// share and push into a neighbor at any viewport width.

import { useState } from 'react'
import { ArenaProvider } from './arena'
import type { ViewKey } from './types'
import { AlertsPanel } from './components/AlertsPanel'
import { BenchmarkView } from './components/BenchmarkView'
import { BluePanel } from './components/BluePanel'
import { Header } from './components/Header'
import { HistoryView } from './components/HistoryView'
import { KnowledgeView } from './components/KnowledgeView'
import { StatusBar } from './components/StatusBar'
import { TerminalPanel } from './components/TerminalPanel'
import { Timeline } from './components/Timeline'
import { Toaster } from './components/Toaster'
import { Topology } from './components/Topology'

/** 作战台专属环境氛围：三条细分竖线 + 顶部一团径向绿光（纯 CSS，不挡交互）。 */
function ArenaAmbient() {
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 z-0 overflow-hidden">
      <div className="absolute inset-y-0 left-1/4 w-px bg-white/[0.04]" />
      <div className="absolute inset-y-0 left-2/4 w-px bg-white/[0.04]" />
      <div className="absolute inset-y-0 left-3/4 w-px bg-white/[0.04]" />
      <div
        className="absolute left-1/2 top-[-220px] h-[460px] w-[min(1100px,90%)] -translate-x-1/2 rounded-[50%] opacity-[0.07] blur-[80px]"
        style={{ background: 'radial-gradient(ellipse at center, #5ed29c 0%, transparent 70%)' }}
      />
    </div>
  )
}

export default function App() {
  const [view, setView] = useState<ViewKey>('arena')
  const [railOpen, setRailOpen] = useState(true)

  return (
    <ArenaProvider>
      <div className="flex h-screen w-screen min-w-[1280px] flex-col overflow-hidden bg-ink font-sans text-neutral-300">
        <Header view={view} onViewChange={setView} />
        {view === 'arena' && (
          <main className="relative flex min-h-0 flex-1 gap-3 overflow-hidden p-3">
            <ArenaAmbient />
            {/* left rail: 拓扑 over 告警 (collapsible) */}
            {railOpen ? (
              <aside className="relative z-10 flex w-[250px] flex-none flex-col gap-3 overflow-hidden">
                <Topology />
                <AlertsPanel />
              </aside>
            ) : null}
            <button
              onClick={() => setRailOpen((v) => !v)}
              title={railOpen ? '收起侧栏' : '展开侧栏'}
              className="relative z-10 w-3 flex-none self-stretch rounded-lg border border-hairline bg-white/[0.03] text-[9px] text-text-3 transition-colors hover:border-accent/30 hover:text-neutral-300"
            >
              {railOpen ? '◂' : '▸'}
            </button>

            {/* center stage: red 2/5 terminal | blue 3/5 per-agent panels */}
            <section className="relative z-10 flex min-w-0 flex-1 gap-3 overflow-hidden">
              <TerminalPanel side="red" className="flex-[2]" />
              <BluePanel className="flex-[3]" />
            </section>

            {/* right rail: 事件时间线 (full height — score panel removed) */}
            <aside className="relative z-10 flex w-[300px] flex-none flex-col gap-3 overflow-hidden">
              <Timeline />
            </aside>
          </main>
        )}
        {view === 'bench' && <BenchmarkView />}
        {view === 'history' && <HistoryView />}
        {view === 'kb' && <KnowledgeView />}
        <StatusBar />
        <Toaster />
      </div>
    </ArenaProvider>
  )
}
