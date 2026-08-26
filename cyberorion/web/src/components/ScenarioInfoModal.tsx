// ScenarioInfoModal — 作战台「ⓘ 场景信息」弹窗：
// /api/scenario/info → 组装成普通 markdown（描述/模式/靶机清单/红方目标/
// 蓝方期望），经 MarkdownView 渲染。端点不含 ground truth，可放心展示。

import { useEffect, useState } from 'react'
import { api } from '../api'
import type { ScenarioDetail } from '../types'
import { MarkdownView } from './MarkdownView'
import { Modal } from './Modal'

function buildMarkdown(info: ScenarioDetail): string {
  const lines: string[] = []
  lines.push(`## ${info.name}`)
  if (info.description) lines.push(info.description)
  lines.push('')
  lines.push(
    `**模式**：\`${info.mode}\`${info.network.subnet ? ` · **网段**：\`${info.network.subnet}\`` : ''}`,
  )
  if (info.briefing) {
    lines.push('', '### 任务简报', '', `> ${info.briefing}`)
  }
  lines.push('', '### 靶机清单', '')
  lines.push('| 靶机 | IP | 容器 | 服务（主机→容器端口） | 日志源 |')
  lines.push('| --- | --- | --- | --- | --- |')
  for (const t of info.targets) {
    const svcs = t.services
      .map((s) => `\`${s.name}\` ${s.host_port}→${s.container_port}/${s.proto}`)
      .join('<br>')
    const logs = Object.entries(t.logs)
      .map(([k, v]) => `\`${k}\`` + (v === 'docker_logs' || v.startsWith('docker_logs:') ? '（docker logs）' : ''))
      .join('<br>') || '—'
    lines.push(
      `| **${t.name}** | \`${t.ip || 'host'}\` | \`${t.container}\` | ${svcs || '—'} | ${logs} |`,
    )
  }
  lines.push('', '### 红方目标', '')
  info.red_objectives.forEach((o, i) => lines.push(`${i + 1}. ${o}`))
  lines.push('', '### 蓝方期望', '')
  info.blue_objectives.forEach((o, i) => lines.push(`${i + 1}. ${o}`))
  return lines.join('\n')
}

export function ScenarioInfoModal({ onClose }: { onClose: () => void }) {
  const [info, setInfo] = useState<ScenarioDetail | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .getScenarioInfo()
      .then(setInfo)
      .catch(() => setError('场景信息读取失败 — 后端可能未就绪'))
  }, [])

  return (
    <Modal title="场景信息" onClose={onClose} width="w-[720px]">
      {error && <div className="text-[11px] text-attacker">{error}</div>}
      {!error && !info && (
        <div className="text-[11px] text-text-2">加载中…</div>
      )}
      {info && (
        <MarkdownView markdown={buildMarkdown(info)} className="md-doc" />
      )}
    </Modal>
  )
}
