import type { WebAccessibleResourceFinding } from '../types'
import { parseManifest } from './manifest-parser'

/**
 * Analyzes the `web_accessible_resources` (WAR) and `externally_connectable`
 * declaration for exposure risk.
 *
 * WAR exposes extension-internal files to web pages. When combined with
 * sensitive resource types (scripts, HTML, JSON) or overly broad match
 * patterns, it creates an attack surface where a malicious page can read
 * internal extension assets and — if those assets reference privileged
 * APIs — potentially chain XSS into extension privilege escalation.
 *
 * `externally_connectable` grants web pages the ability to message the
 * extension, which can trigger privileged behavior declared in
 * `onMessageExternal` handlers.
 *
 * Sources:
 * - https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
 * - https://developer.chrome.com/docs/extensions/reference/manifest/web-accessible-resources
 * - https://developer.chrome.com/docs/extensions/reference/manifest/externally-connectable
 */

// Sensitive resource extensions whose exposure to arbitrary web pages
// materially increases attack surface.
const SENSITIVE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.html', '.htm', '.json', '.wasm']

// Match patterns that expose resources to any website.
const BROAD_MATCH_PATTERNS = ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']

function isBroadMatch(pattern: string): boolean {
  return BROAD_MATCH_PATTERNS.includes(pattern)
}

function hasSensitiveExtension(resource: string): boolean {
  return SENSITIVE_EXTENSIONS.some((ext) => resource.toLowerCase().endsWith(ext))
}

function buildWarFindings(
  warEntries: Array<{ resources: string[]; matches: string[] }>,
): WebAccessibleResourceFinding[] {
  const findings: WebAccessibleResourceFinding[] = []

  for (const entry of warEntries) {
    const { resources, matches } = entry

    // 1) Overly broad exposure — any website can access these resources.
    const broadMatches = matches.filter(isBroadMatch)
    if (broadMatches.length > 0) {
      findings.push({
        type: 'broad-exposure',
        risk: 'high',
        description:
          `Web-accessible resources are exposed to all websites via ` +
          `${broadMatches.map((m) => `'${m}'`).join(', ')}. Any page the user visits can ` +
          `fetch these internal files, enabling fingerprinting, data extraction, or XSS-based ` +
          `privilege escalation when combined with sensitive assets.`,
        suggestion:
          'Restrict match patterns to the specific origins that genuinely need access, or use ' +
          'a narrowly scoped wildcard (e.g. a single trusted domain).',
      })
    }

    // 2) Sensitive resource types exposed to pages.
    const sensitiveResources = resources.filter(hasSensitiveExtension)
    if (sensitiveResources.length > 0) {
      findings.push({
        type: 'sensitive-resource',
        risk: 'high',
        description:
          `Sensitive resource types (${sensitiveResources
            .map((r) => `'${r}'`)
            .join(', ')}) are web-accessible. Scripts and HTML files may embed ` +
          `internal logic, tokens, or DOM sinks that a hostile page can read or execute.`,
        suggestion:
          'Avoid exposing executable or data-bearing assets (JS/HTML/JSON) to web pages. ' +
          'Prefer exposing only static, non-sensitive assets such as images or fonts.',
      })
    }
  }

  return findings
}

function buildExternallyConnectableFindings(
  externallyConnectable: { ids?: string[]; matches?: string[] } | null,
): WebAccessibleResourceFinding[] {
  if (!externallyConnectable) return []

  const findings: WebAccessibleResourceFinding[] = []
  const { matches } = externallyConnectable

  // Broad externally_connectable matches let any website message the extension.
  const broadMatches = (matches ?? []).filter(isBroadMatch)
  if (broadMatches.length > 0) {
    findings.push({
      type: 'broad-connectable',
      risk: 'medium',
      description:
        `externally_connectable allows any website (${broadMatches
          .map((m) => `'${m}'`)
          .join(', ')}) to send messages to this extension. If an ` +
        `onMessageExternal handler performs privileged actions without validating the sender, ` +
        `any page can trigger them.`,
      suggestion:
        'Restrict externally_connectable matches to specific trusted origins and validate ' +
        '`sender.origin` / `sender.id` inside every onMessageExternal handler.',
    })
  }

  return findings
}

export function analyzeWebAccessibleResources(
  manifest: Record<string, unknown>,
): WebAccessibleResourceFinding[] {
  const parsed = parseManifest(manifest)

  // Normalize WAR into a uniform shape regardless of MV2 (string[]) or MV3 (object[]).
  const warEntries: Array<{ resources: string[]; matches: string[] }> = []
  const war = manifest.web_accessible_resources

  if (Array.isArray(war)) {
    for (const entry of war) {
      if (typeof entry === 'string') {
        // MV2: plain string list, applies to all origins.
        warEntries.push({ resources: [entry], matches: ['<all_urls>'] })
      } else if (entry && typeof entry === 'object') {
        const obj = entry as Record<string, unknown>
        const resources = Array.isArray(obj.resources)
          ? obj.resources.filter((r): r is string => typeof r === 'string')
          : []
        const matches = Array.isArray(obj.matches)
          ? obj.matches.filter((m): m is string => typeof m === 'string')
          : []
        warEntries.push({ resources, matches })
      }
    }
  }

  const findings = buildWarFindings(warEntries)
  findings.push(...buildExternallyConnectableFindings(parsed.externallyConnectable))

  return findings
}
