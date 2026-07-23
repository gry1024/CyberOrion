import type { LedgerEntry } from '../types'

interface LedgerTableProps {
  ledger: Record<string, LedgerEntry>
}

function statusClass(status: string): string {
  const s = status.toLowerCase()
  if (s === 'open' || s === 'failed') return 'open'
  if (s === 'investigating') return 'investigating'
  if (s === 'mitigated' || s === 'hardened') return 'mitigated'
  if (s === 'verified_fixed') return 'verified_fixed'
  return ''
}

export function LedgerTable({ ledger }: LedgerTableProps) {
  const entries = Object.values(ledger).sort((a, b) => {
    const sa = (a.scope || 'session') + a.vuln_id
    const sb = (b.scope || 'session') + b.vuln_id
    return sa.localeCompare(sb)
  })

  return (
    <section className="ledger-section">
      <h2 className="ledger-title">漏洞账本</h2>
      <div className="ledger-subtitle">
        全局状态（靶机配置）与会话状态（检测基线）分别追踪
      </div>
      {entries.length === 0 ? (
        <div className="ledger-empty">尚无记录</div>
      ) : (
        <table className="ledger-table">
          <thead>
            <tr>
              <th style={{ width: '80px' }}>范围</th>
              <th style={{ width: '220px' }}>漏洞 ID</th>
              <th style={{ width: '130px' }}>状态</th>
              <th>证据 / 描述</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.vuln_id}>
                <td>
                  <span className={'scope-tag ' + (e.scope || 'session')}>
                    {e.scope === 'global' ? '全局' : '会话'}
                  </span>
                </td>
                <td className="vuln-id">{e.vuln_id}</td>
                <td>
                  <span className={'status-tag ' + statusClass(e.status)}>{e.status}</span>
                </td>
                <td>{e.evidence || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
