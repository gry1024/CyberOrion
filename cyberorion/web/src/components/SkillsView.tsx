import { useEffect, useState } from 'react'
import { api } from '../api'
import type { SkillDetail, SkillInfo, SkillsCatalog } from '../types'
import { FadeIn } from './FadeIn'
import { MarkdownView } from './MarkdownView'
import { Modal } from './Modal'

export function SkillsView() {
  const [catalog, setCatalog] = useState<SkillsCatalog | null>(null)
  const [error, setError] = useState('')
  const [selectedSkill, setSelectedSkill] = useState<{ side: 'red' | 'blue'; name: string } | null>(null)
  const [skillDetail, setSkillDetail] = useState<SkillDetail | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  useEffect(() => {
    api
      .getSkills()
      .then(setCatalog)
      .catch(() => setError('技能目录加载失败 - 后端可能未就绪'))
  }, [])

  useEffect(() => {
    if (!selectedSkill) {
      setSkillDetail(null)
      return
    }
    setLoadingDetail(true)
    api
      .getSkillDetail(selectedSkill.side, selectedSkill.name)
      .then(setSkillDetail)
      .catch(() => setSkillDetail(null))
      .finally(() => setLoadingDetail(false))
  }, [selectedSkill])

  const handleCloseModal = () => {
    setSelectedSkill(null)
    setSkillDetail(null)
  }

  return (
    <main className="scroll-thin min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto max-w-[1200px] px-6 pb-10 pt-8">
        <FadeIn>
          <div className="mb-8">
            <h1 className="text-[18px] font-semibold" style={{ color: 'var(--color-fg)' }}>
              Agent Skills
            </h1>
            <p className="mt-1 text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
              渐进式技能加载 - 12个专业技能模块
            </p>
          </div>
        </FadeIn>

        {error && (
          <div className="mb-4 rounded px-3 py-2 text-[12px]" style={{ background: 'var(--color-red-soft)', color: 'var(--color-red)' }}>
            {error}
          </div>
        )}

        {!error && !catalog && (
          <div className="text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
            加载中…
          </div>
        )}

        {catalog && (
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <SkillColumn
              title="红队技能"
              icon="🔴"
              skills={catalog.red}
              side="red"
              onSelect={(name) => setSelectedSkill({ side: 'red', name })}
            />
            <SkillColumn
              title="蓝队技能"
              icon="🔵"
              skills={catalog.blue}
              side="blue"
              onSelect={(name) => setSelectedSkill({ side: 'blue', name })}
            />
          </div>
        )}
      </div>

      {selectedSkill && (
        <Modal
          title={`${selectedSkill.side === 'red' ? '红队' : '蓝队'} - ${selectedSkill.name}`}
          onClose={handleCloseModal}
          width="w-[760px]"
        >
          {loadingDetail && (
            <div className="py-8 text-center text-[12px]" style={{ color: 'var(--color-fg-3)' }}>
              加载技能文档…
            </div>
          )}
          {!loadingDetail && !skillDetail && (
            <div className="py-8 text-center text-[12px]" style={{ color: 'var(--color-red)' }}>
              技能文档加载失败
            </div>
          )}
          {skillDetail && (
            <div className="md-doc">
              <MarkdownView markdown={skillDetail.content} className="md-doc" />
            </div>
          )}
        </Modal>
      )}
    </main>
  )
}

function SkillColumn({
  title,
  icon,
  skills,
  side,
  onSelect,
}: {
  title: string
  icon: string
  skills: SkillInfo[]
  side: 'red' | 'blue'
  onSelect: (name: string) => void
}) {
  const accentVar = side === 'red' ? '--color-red' : '--color-blue'
  const accentSoftVar = side === 'red' ? '--color-red-soft' : '--color-blue-soft'

  return (
    <div>
      <div className="mb-3 flex items-center gap-2 px-1">
        <span>{icon}</span>
        <h2 className="text-[13px] font-semibold" style={{ color: `var(${accentVar})` }}>
          {title}
        </h2>
        <span className="text-[11px]" style={{ color: 'var(--color-fg-4)' }}>
          ({skills.length})
        </span>
      </div>
      <div className="flex flex-col gap-2">
        {skills.map((skill) => (
          <button
            key={skill.name}
            onClick={() => onSelect(skill.name)}
            className="group rounded-lg p-4 text-left transition-all hover:scale-[1.01]"
            style={{
              background: 'var(--color-panel-2)',
              border: `1px solid var(--color-hairline)`,
              borderLeft: `3px solid var(${accentVar})`,
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = `var(${accentSoftVar})`
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'var(--color-panel-2)'
            }}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-[12.5px] font-semibold" style={{ color: 'var(--color-fg)' }}>
                  {skill.name}
                </div>
                <div className="mt-1 text-[11.5px] leading-relaxed" style={{ color: 'var(--color-fg-3)' }}>
                  {skill.description}
                </div>
              </div>
              <span
                className="flex-none text-[11px] opacity-0 transition-opacity group-hover:opacity-100"
                style={{ color: `var(${accentVar})` }}
              >
                查看 →
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}
