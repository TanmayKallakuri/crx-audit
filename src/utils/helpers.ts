import type { RiskLevel } from '../types'

/**
 * Extract a Chrome extension ID from a URL or raw 32-char ID string.
 * Supports:
 *   - Raw 32-char lowercase alpha IDs
 *   - https://chromewebstore.google.com/detail/name/ID
 *   - https://chrome.google.com/webstore/detail/name/ID
 */
export function extractExtensionId(input: string): string | null {
  const trimmed = input.trim()

  // Raw 32-char extension ID (all lowercase letters)
  if (/^[a-p]{32}$/.test(trimmed)) {
    return trimmed
  }

  // Chrome Web Store URL patterns
  const patterns = [
    /chromewebstore\.google\.com\/detail\/[^/]+\/([a-p]{32})/,
    /chrome\.google\.com\/webstore\/detail\/[^/]+\/([a-p]{32})/,
  ]

  for (const pattern of patterns) {
    const match = trimmed.match(pattern)
    if (match) {
      return match[1]
    }
  }

  return null
}

/**
 * Return Tailwind color classes for a risk level badge.
 */
export function riskColor(risk: RiskLevel): string {
  switch (risk) {
    case 'critical':
      return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low':
      return 'bg-blue-400/20 text-blue-400 border-blue-400/30'
    case 'none':
      return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  }
}

/**
 * Return a display label for a risk level.
 */
export function riskLabel(risk: RiskLevel): string {
  return risk.charAt(0).toUpperCase() + risk.slice(1)
}
