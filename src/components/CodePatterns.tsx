import { useState } from 'react'
import type { CodePatternMatch } from '../types'
import { riskColor, riskLabel, riskDot } from '../utils/helpers'
import { Code, ChevronDown, ChevronRight } from 'lucide-react'

interface CodePatternsProps {
  patterns: CodePatternMatch[]
}

const categoryLabels: Record<string, string> = {
  sink: 'DOM Sinks',
  source: 'Data Sources',
  network: 'Network Activity',
  obfuscation: 'Obfuscation Signals',
}

const fileTypeLabels: Record<string, string> = {
  'content-script': 'content',
  background: 'bg',
  'web-accessible': 'web',
  other: 'other',
}

export default function CodePatterns({ patterns }: CodePatternsProps) {
  if (patterns.length === 0) return null

  const grouped = patterns.reduce<Record<string, CodePatternMatch[]>>((acc, p) => {
    if (!acc[p.category]) acc[p.category] = []
    acc[p.category].push(p)
    return acc
  }, {})

  // Limit display — show top 5 per category, with expand option
  return (
    <section>
      <div className="flex items-center gap-2 mb-4">
        <Code className="w-4 h-4 text-[var(--color-text-tertiary)]" />
        <h3 className="font-display font-semibold text-[15px] text-[var(--color-text-primary)]">
          Code Patterns
          <span className="ml-2 text-[12px] font-mono font-normal text-[var(--color-text-tertiary)]">
            {patterns.length}
          </span>
        </h3>
      </div>

      <div className="space-y-3">
        {Object.entries(grouped).map(([category, items]) => (
          <CategoryGroup key={category} category={category} items={items} />
        ))}
      </div>
    </section>
  )
}

function CategoryGroup({ category, items }: { category: string; items: CodePatternMatch[] }) {
  const [showAll, setShowAll] = useState(false)
  const displayed = showAll ? items : items.slice(0, 5)
  const hasMore = items.length > 5

  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-1)] overflow-hidden">
      <div className="px-5 py-3 border-b border-[var(--color-border-subtle)] flex items-center justify-between">
        <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] uppercase tracking-wider">
          {categoryLabels[category] || category}
        </span>
        <span className="text-[11px] font-mono text-[var(--color-text-tertiary)]">
          {items.length}
        </span>
      </div>
      <div className="divide-y divide-[var(--color-border-subtle)]">
        {displayed.map((match, i) => (
          <PatternItem key={i} match={match} />
        ))}
      </div>
      {hasMore && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="w-full px-5 py-2.5 text-[12px] font-mono text-[var(--color-text-tertiary)] hover:text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-2)]/50 transition-colors border-t border-[var(--color-border-subtle)]"
        >
          {showAll ? 'Show less' : `Show ${items.length - 5} more`}
        </button>
      )}
    </div>
  )
}

function PatternItem({ match }: { match: CodePatternMatch }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-5 py-2.5 text-left hover:bg-[var(--color-surface-2)]/30 transition-colors"
      >
        {expanded
          ? <ChevronDown className="w-3 h-3 text-[var(--color-text-tertiary)] shrink-0" />
          : <ChevronRight className="w-3 h-3 text-[var(--color-text-tertiary)] shrink-0" />
        }
        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${riskDot(match.risk)}`} />
        <span className="text-[12px] text-[var(--color-text-secondary)] flex-1 truncate">
          {match.description}
        </span>
        <span className="text-[11px] font-mono text-[var(--color-text-tertiary)] shrink-0">
          {match.filePath.split('/').pop()}:{match.lineNumber}
        </span>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--color-surface-3)] text-[var(--color-text-tertiary)] shrink-0">
          {fileTypeLabels[match.fileType] || match.fileType}
        </span>
      </button>

      {expanded && match.context.length > 0 && (
        <div className="mx-5 mb-3 rounded-lg bg-[var(--color-surface-0)] border border-[var(--color-border-subtle)] overflow-x-auto">
          <pre className="text-[11px] font-mono leading-5 p-3">
            {match.context.map((line, idx) => {
              const lineNum = match.lineNumber - Math.floor(match.context.length / 2) + idx
              const isMatch = lineNum === match.lineNumber
              return (
                <div key={idx} className={isMatch ? 'bg-amber-500/10 text-amber-300 -mx-3 px-3' : 'text-[var(--color-text-tertiary)]'}>
                  <span className="inline-block w-8 text-right mr-3 text-[var(--color-text-tertiary)]/50 select-none">
                    {lineNum}
                  </span>
                  {line}
                </div>
              )
            })}
          </pre>
        </div>
      )}
    </div>
  )
}
