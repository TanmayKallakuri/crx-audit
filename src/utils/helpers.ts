import type { RiskLevel } from '../types'

export function extractExtensionId(input: string): string | null {
  const trimmed = input.trim()
  if (/^[a-p]{32}$/.test(trimmed)) return trimmed
  const patterns = [
    /chromewebstore\.google\.com\/detail\/[^/]+\/([a-p]{32})/,
    /chrome\.google\.com\/webstore\/detail\/[^/]+\/([a-p]{32})/,
  ]
  for (const pattern of patterns) {
    const match = trimmed.match(pattern)
    if (match) return match[1]
  }
  return null
}

export function extractExtensionName(input: string): string | null {
  const patterns = [
    /chromewebstore\.google\.com\/detail\/([^/]+)\/[a-p]{32}/,
    /chrome\.google\.com\/webstore\/detail\/([^/]+)\/[a-p]{32}/,
  ]
  for (const pattern of patterns) {
    const match = input.trim().match(pattern)
    if (match && match[1]) {
      return match[1].replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    }
  }
  return null
}

export function riskColor(risk: RiskLevel): string {
  switch (risk) {
    case 'critical': return 'bg-red-500/15 text-red-400 border-red-500/25'
    case 'high': return 'bg-orange-500/15 text-orange-400 border-orange-500/25'
    case 'medium': return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/25'
    case 'low': return 'bg-blue-500/15 text-blue-400 border-blue-500/25'
    case 'none': return 'bg-zinc-500/15 text-zinc-400 border-zinc-500/25'
  }
}

export function riskBorderLeft(risk: RiskLevel): string {
  switch (risk) {
    case 'critical': return 'border-l-red-500'
    case 'high': return 'border-l-orange-500'
    case 'medium': return 'border-l-yellow-500'
    case 'low': return 'border-l-blue-500'
    case 'none': return 'border-l-zinc-600'
  }
}

export function riskDot(risk: RiskLevel): string {
  switch (risk) {
    case 'critical': return 'bg-red-500'
    case 'high': return 'bg-orange-500'
    case 'medium': return 'bg-yellow-500'
    case 'low': return 'bg-blue-500'
    case 'none': return 'bg-zinc-500'
  }
}

export function riskLabel(risk: RiskLevel): string {
  return risk.charAt(0).toUpperCase() + risk.slice(1)
}
