// App — Kimi 式布局：左侧 240px 侧边栏 + 主内容区
// 视图切换由侧边栏驱动；作战台 = 双栏红蓝流式输出（Kimi chat 风格）。
import { useState } from 'react'
import { ArenaProvider } from './arena'
import type { ViewKey } from './types'
import { Sidebar } from './components/Sidebar'
import { ArenaView } from './components/ArenaView'
import { TrafficView } from './components/TrafficView'
import { BenchmarkView } from './components/BenchmarkView'
import { HistoryView } from './components/HistoryView'
import { KnowledgeView } from './components/KnowledgeView'
import { SkillsView } from './components/SkillsView'
import { AboutView } from './components/AboutView'
import { Toaster } from './components/Toaster'

export default function App() {
  const [view, setView] = useState<ViewKey>('arena')
  return (
    <ArenaProvider>
      <div className="flex h-full overflow-hidden">
        <Sidebar view={view} onView={setView} />
        <main className="flex min-w-0 flex-1 flex-col bg-[var(--color-bg)]">
          {view === 'arena' && <ArenaView />}
          {view === 'traffic' && <TrafficView />}
          {view === 'bench' && (
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              <BenchmarkView />
            </div>
          )}
          {view === 'history' && (
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              <HistoryView />
            </div>
          )}
          {view === 'skills' && <SkillsView />}
          {view === 'kb' && (
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              <KnowledgeView />
            </div>
          )}
          {view === 'docs' && (
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              <AboutView />
            </div>
          )}
        </main>
      </div>
      <Toaster />
    </ArenaProvider>
  )
}
