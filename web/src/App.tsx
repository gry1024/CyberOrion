import { useArena } from './useArena'
import { Header } from './components/Header'
import { SidePanel } from './components/SidePanel'
import { LedgerTable } from './components/LedgerTable'

export default function App() {
  const arena = useArena()

  return (
    <div className="app">
      <Header connected={arena.connected} status={arena.status} />
      <main className="app-main">
        <div className="arena-grid">
          <SidePanel side="red" status={arena.status} steps={arena.redSteps} />
          <SidePanel side="blue" status={arena.status} steps={arena.blueSteps} />
        </div>
        <LedgerTable ledger={arena.ledger} />
      </main>
      <footer className="app-footer">
        CyberOrion Arena · 事件驱动的实时红蓝对抗
      </footer>
    </div>
  )
}
