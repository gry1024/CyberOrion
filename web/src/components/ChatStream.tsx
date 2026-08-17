// ChatStream — REFACTOR_M4 重构版
// 路由 11 种 kind（thinking/tool_call/tool_output/rag_retrieval/rag_no_match/
//   rag_unavailable/subagent_dispatch/subagent_result/sop_phase/report/error）
// 各 kind 用专属颜色卡片区分；中文标注由后端预生成（label_zh/summary_zh）。
//
// 旧事件向后兼容：缺失 kind 时按 legacy type 映射。

import { useEffect, useRef, useState } from 'react'
import { blueRoleOf } from '../types'
import { MarkdownView } from './MarkdownView'
import type { ThoughtStep, Side } from '../types'

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('zh-CN', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
  })
}

interface AgentMeta {
  label: string
  color: string
}

function metaOf(agent: string | undefined, side: Side): AgentMeta {
  if (side === 'red') return { label: '红方', color: 'var(--color-red)' }
  const r = blueRoleOf(agent ?? 'orchestrator')
  if (r) return { label: r.name, color: r.colorVar }
  return { label: '调度指挥', color: 'var(--color-blue)' }
}

/** 人像头像：角色色圆底 + 白色人像剪影 */
function AgentAvatar({ color, size = 20 }: { color: string; size?: number }) {
  return (
    <span
      className="flex flex-none select-none items-center justify-center rounded-full"
      style={{ width: size, height: size, background: color }}
    >
      <svg viewBox="0 0 24 24" width={size * 0.62} height={size * 0.62} fill="none" aria-hidden>
        <circle cx="12" cy="8.6" r="3.6" fill="#fff" />
        <path d="M4.5 21c0-4.2 3.4-6.6 7.5-6.6s7.5 2.4 7.5 6.6z" fill="#fff" />
      </svg>
    </span>
  )
}

// =============== 11 种 kind 各有专属组件 ===============

/** 工具调用：蓝框 + label_zh + 参数 */
function ToolCallCard({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  const labelZh = step.label_zh || step.tool || ''
  return (
    <div
      className="fade-in my-2 rounded-lg p-3 shadow-sm"
      style={{
        borderLeft: '4px solid #2E86AB',
        background: '#EBF5FB',
      }}
    >
      <div className="flex items-center gap-2 text-xs text-gray-500">
        <span>🔧 工具调用</span>
        <span
          className="rounded bg-blue-100 px-2 py-0.5 font-mono text-[10px] text-blue-800"
        >
          {step.tool}
        </span>
      </div>
      <div className="mt-1 font-semibold text-gray-900">{labelZh}</div>
      {step.args && (
        <>
          <button
            onClick={() => setOpen((v) => !v)}
            className="mt-1 text-[10.5px] text-gray-600 hover:text-gray-900"
          >
            {open ? '收起参数' : '展开参数'}
          </button>
          {open && (
            <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-white p-2 font-mono text-[11px]">
              {typeof step.args === 'string' ? step.args : JSON.stringify(step.args, null, 2)}
            </pre>
          )}
        </>
      )}
    </div>
  )
}

/** 工具输出：浅蓝虚线框 + summary_zh + 折叠 raw */
function ToolOutputCard({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="fade-in my-2 rounded-lg border border-dashed p-3"
      style={{
        borderColor: '#5DADE2',
        background: '#F4FBFE',
      }}
    >
      <div className="text-xs font-medium" style={{ color: '#5DADE2' }}>
        📋 工具结果
      </div>
      {step.summary_zh && (
        <div className="mt-1 text-sm font-semibold text-gray-900">
          {step.summary_zh}
        </div>
      )}
      <button
        onClick={() => setOpen((v) => !v)}
        className="mt-1 text-[10.5px] text-gray-600 hover:text-gray-900"
      >
        {open ? '收起原始输出' : '展开原始输出'}
      </button>
      {open && step.output && (
        <pre className="mt-1 max-h-64 overflow-auto rounded bg-white p-2 font-mono text-[11px]">
          {step.output}
        </pre>
      )}
    </div>
  )
}

/** RAG 检索：紫色粗框 + 命中 doc 列表可展开 */
function RagRetrievalCard({ step }: { step: ThoughtStep }) {
  const [open, setOpen] = useState(false)
  const docIds: string[] = step.doc_ids || []
  const titles: string[] = step.doc_titles_zh || []
  return (
    <div
      className="fade-in my-2 rounded-lg p-3"
      style={{
        border: '2px solid #8E44AD',
        background: '#F4ECF7',
      }}
    >
      <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#8E44AD' }}>
        <span>📚 检索知识库</span>
        <span className="text-xs font-normal text-gray-600">
          命中 {step.hit_count ?? docIds.length} 条 · {step.total_chars ?? 0} 字符
        </span>
      </div>
      <div className="mt-1 text-xs text-gray-700">
        检索词：{step.query}
      </div>
      {docIds.length > 0 && (
        <>
          <button
            onClick={() => setOpen((v) => !v)}
            className="mt-2 text-[10.5px] text-purple-700 underline hover:text-purple-900"
          >
            {open ? '收起命中条目' : `展开命中条目（${docIds.length}）`}
          </button>
          {open && (
            <div className="mt-2 space-y-2">
              {docIds.map((id, i) => (
                <details
                  key={id + i}
                  className="rounded bg-white p-2"
                >
                  <summary className="cursor-pointer font-mono text-xs">
                    <span style={{ color: '#8E44AD' }}>[{id}]</span> {titles[i] || id}
                  </summary>
                  {step.docs && step.docs[i] && (
                    <div className="mt-2 whitespace-pre-wrap text-xs text-gray-700">
                      {(step.docs[i].detection || step.docs[i].description || '').slice(0, 800)}
                    </div>
                  )}
                </details>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

/** RAG 无结果：浅紫虚线小条 */
function RagNoMatchBanner({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-2 rounded border border-dashed p-2 text-xs"
      style={{
        borderColor: '#D7BDE2',
        background: '#FAF4FC',
        color: '#7D3C98',
      }}
    >
      📚 知识库无相关条目：{step.intent || step.message || ''}
    </div>
  )
}

/** RAG 不可用：灰虚线警示 */
function RagUnavailableBanner({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-2 rounded border border-dashed p-2 text-xs"
      style={{
        borderColor: '#BDC3C7',
        background: '#F4F6F6',
        color: '#5D6D7E',
      }}
    >
      ⚠️ 知识库不可用：{step.error || 'KB 索引不可访问'}
    </div>
  )
}

/** 子 Agent 派遣：青色粗框 + Worker 名 badge */
function SubagentDispatchCard({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-2 rounded-lg p-3"
      style={{
        border: '2px solid #16A085',
        background: '#E8F6F3',
      }}
    >
      <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#16A085' }}>
        🚀 调度子 Agent
        <span className="rounded bg-teal-100 px-2 py-0.5 font-mono text-[10px]" style={{ color: '#16A085' }}>
          {step.worker_name}
        </span>
      </div>
      <div className="mt-1 text-sm text-gray-800">{step.task_zh}</div>
      {step.sop_phase && (
        <div className="mt-1 text-xs text-amber-700">SOP 阶段：{step.sop_phase}</div>
      )}
    </div>
  )
}

/** 子 Agent 回报：浅青虚线 */
function SubagentResultCard({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-2 rounded-lg border border-dashed p-3"
      style={{
        borderColor: '#76D7C4',
        background: '#F0F9F8',
      }}
    >
      <div className="text-sm font-medium" style={{ color: '#16A085' }}>
        ✅ {step.worker_name} 完成
      </div>
      {step.findings_zh && (
        <div className="mt-1 text-sm text-gray-800">{step.findings_zh}</div>
      )}
    </div>
  )
}

/** SOP 阶段 banner：琥珀色横条 */
function SopPhaseBanner({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-3 rounded-lg p-3"
      style={{
        border: '2px solid #F39C12',
        background: '#FEF5E7',
      }}
    >
      <div className="text-sm font-semibold" style={{ color: '#9C640C' }}>
        阶段 {step.phase_id}/{step.phase_total} · {step.phase_name_zh || step.phase_name}
        {step.strict && (
          <span className="ml-2 rounded bg-amber-600 px-2 py-0.5 text-[10px] text-white">
            强制
          </span>
        )}
      </div>
      {step.suggested_workers && (
        <div className="mt-1 text-xs" style={{ color: '#9C640C' }}>
          建议派遣：{step.suggested_workers.join(', ')}
        </div>
      )}
    </div>
  )
}

/** 错误：红色警示框 */
function ErrorBanner({ step }: { step: ThoughtStep }) {
  return (
    <div
      className="fade-in my-2 rounded-lg p-3"
      style={{
        border: '2px solid #C0392B',
        background: '#FADBD8',
      }}
    >
      <div className="text-sm font-semibold text-red-700">
        ❌ 错误
      </div>
      <div className="mt-1 text-sm text-red-900">
        {step.message || JSON.stringify(step)}
      </div>
    </div>
  )
}

/** 报告：绿色大块卡片 */
function ReportCard({ step, side }: { step: ThoughtStep; side: Side }) {
  const [open, setOpen] = useState(true)
  const meta = metaOf(step.role ?? step.agent, side)
  return (
    <div
      className="fade-in my-2 rounded-lg p-3"
      style={{
        border: '2px solid #27AE60',
        background: '#EAFAF1',
      }}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 text-sm font-semibold"
        style={{ color: '#1E8449' }}
      >
        <AgentAvatar color={meta.color} size={18} />
        {open ? '▾' : '▸'} 📄 最终报告
      </button>
      {open && step.report && (
        <div className="mt-2 rounded bg-white p-3">
          <MarkdownView markdown={step.report} />
        </div>
      )}
    </div>
  )
}

/** 思考（LLM 流式文本）：斜体灰文 */
function ThinkingView({ step, side }: { step: ThoughtStep; side: Side }) {
  if (!step.text) return null
  const meta = metaOf(step.agent, side)
  const agentName = side === 'red' ? '红方 agent' : `${meta.label} agent`
  return (
    <div className="fade-in flex gap-2 py-px">
      <AgentAvatar color={meta.color} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="text-[11px] font-semibold" style={{ color: meta.color }}>
            {agentName}
          </span>
          <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>
            {fmtTs(step.timestamp)}
          </span>
        </div>
        <div className="stream-thinking italic" style={{ color: '#666' }}>
          <MarkdownView markdown={step.text} className="md-inline" />
        </div>
      </div>
    </div>
  )
}

/** 系统事件（向后兼容） */
function SystemLine({ step }: { step: ThoughtStep }) {
  return (
    <div className="fade-in py-px text-[11px]" style={{ color: 'var(--color-fg-3)' }}>
      {step.text}
    </div>
  )
}

// =============== 路由分发 ===============

export function ChatStream({ steps, side }: { steps: ThoughtStep[]; side: Side }) {
  return (
    <div className="chat-stream space-y-1">
      {steps.map((step, i) => {
        const kind = step.kind || (step.type ? mapLegacyKind(step.type) : 'thinking')
        switch (kind) {
          case 'thinking':
            return <ThinkingView key={i} step={step} side={side} />
          case 'tool_call':
            return <ToolCallCard key={i} step={step} />
          case 'tool_output':
            return <ToolOutputCard key={i} step={step} />
          case 'rag_retrieval':
            return <RagRetrievalCard key={i} step={step} />
          case 'rag_no_match':
            return <RagNoMatchBanner key={i} step={step} />
          case 'rag_unavailable':
            return <RagUnavailableBanner key={i} step={step} />
          case 'subagent_dispatch':
            return <SubagentDispatchCard key={i} step={step} />
          case 'subagent_result':
            return <SubagentResultCard key={i} step={step} />
          case 'sop_phase':
            return <SopPhaseBanner key={i} step={step} />
          case 'report':
            return <ReportCard key={i} step={step} side={side} />
          case 'error':
            return <ErrorBanner key={i} step={step} />
          case 'system':
            return <SystemLine key={i} step={step} />
          default:
            return <ThinkingView key={i} step={step} side={side} />
        }
      })}
    </div>
  )
}

function mapLegacyKind(type: string): string {
  const map: Record<string, string> = {
    thinking: 'thinking',
    tool_call: 'tool_call',
    tool_output: 'tool_output',
    report: 'report',
    error: 'error',
    system: 'system',
  }
  return map[type] || 'thinking'
}