import type { ThoughtStep } from '../types'

interface ThoughtStreamProps {
  steps: ThoughtStep[]
  emptyHint: string
}

function formatTime(ts: number): string {
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString('zh-CN', { hour12: false }) +
    '.' + String(d.getMilliseconds()).padStart(3, '0')
}

function truncate(s: string, n: number): string {
  if (!s) return ''
  return s.length > n ? s.slice(0, n) + '… (+' + (s.length - n) + ' chars)' : s
}

export function ThoughtStream({ steps, emptyHint }: ThoughtStreamProps) {
  if (steps.length === 0) {
    return <div className="side-stream-empty">{emptyHint}</div>
  }

  return (
    <>
      {steps.map((step) => {
        if (step.kind === 'thinking') {
          return (
            <div className="step thinking" key={step.id}>
              <div className="step-head">
                <span>思考</span>
                <span className="step-time">{formatTime(step.timestamp)}</span>
              </div>
              <div className="step-body">{truncate(step.text || '', 1200)}</div>
            </div>
          )
        }
        if (step.kind === 'tool_call') {
          return (
            <div className="step tool_call" key={step.id}>
              <div className="step-head">
                <span>工具</span>
                <span className="step-tool">{step.tool}</span>
                <span className="step-time">{formatTime(step.timestamp)}</span>
              </div>
              {step.args && step.args !== '{}' && (
                <div className="step-body">{truncate(step.args, 600)}</div>
              )}
            </div>
          )
        }
        return (
          <div className="step tool_output" key={step.id}>
            <div className="step-head">
              <span>输出</span>
              <span className="step-time">{formatTime(step.timestamp)}</span>
            </div>
            <div className="step-body">{truncate(step.output || '', 1000)}</div>
          </div>
        )
      })}
    </>
  )
}
