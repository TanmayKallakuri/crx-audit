import type { HostPermissionFinding } from '../types'
import { parseManifest } from './manifest-parser'
import { matchesSensitiveDomain } from '../data/sensitive-domains'

const OVERLY_BROAD_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
]

export function analyzeHostPermissions(
  manifest: Record<string, unknown>,
): HostPermissionFinding[] {
  const parsed = parseManifest(manifest)
  const findings: HostPermissionFinding[] = []
  const seen = new Set<string>()

  // Collect all host/URL patterns from all sources
  const allPatterns: Array<{ pattern: string; source: string }> = []

  for (const p of parsed.hostPermissions) {
    allPatterns.push({ pattern: p, source: 'host_permissions' })
  }
  for (const p of parsed.optionalHostPermissions) {
    allPatterns.push({ pattern: p, source: 'optional_host_permissions' })
  }
  // MV2: URL patterns were already separated into hostPermissions by parseManifest
  // Content script match patterns
  for (const cs of parsed.contentScripts) {
    for (const m of cs.matches) {
      allPatterns.push({ pattern: m, source: 'content_scripts' })
    }
  }

  for (const { pattern, source } of allPatterns) {
    // Avoid duplicate findings for same pattern
    if (seen.has(pattern)) continue
    seen.add(pattern)

    // Check for overly broad patterns
    if (OVERLY_BROAD_PATTERNS.includes(pattern)) {
      findings.push({
        pattern,
        type: 'overly-broad',
        risk: 'high',
        description: `'${pattern}' grants access to all websites — this is overly broad${source === 'content_scripts' ? ' (via content script matches)' : ''}`,
        suggestion:
          'Consider using activeTab permission instead, which only grants access to the currently active tab when the user invokes the extension.',
      })
      continue
    }

    // Check for file:/// access
    if (pattern.startsWith('file:///') || pattern === 'file://*/*') {
      findings.push({
        pattern,
        type: 'file-access',
        risk: 'high',
        description:
          'file:// access grants the extension permission to read local files on the user\'s machine',
        suggestion:
          'Users must explicitly enable this in chrome://extensions. Ensure this is truly necessary.',
      })
      continue
    }

    // Check for sensitive domains
    const sensitive = matchesSensitiveDomain(pattern)
    if (sensitive) {
      findings.push({
        pattern,
        type: 'sensitive-domain',
        risk: sensitive.risk,
        description: `${sensitive.description}${source === 'content_scripts' ? ' (via content script)' : ''}`,
        suggestion:
          'Verify this domain access is essential. Consider requesting only activeTab or narrowing the URL pattern.',
      })
    }
  }

  return findings
}
