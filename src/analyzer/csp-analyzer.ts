import type { CSPAnalysisResult, CSPDirectiveResult, CSPFinding } from '../types'
import { isBypassDomain } from '../data/csp-bypass-domains'

const CHROME_DEFAULT_CSP = "script-src 'self'; object-src 'self'"

interface ParsedDirective {
  name: string
  values: string[]
}

function parseCSPString(csp: string): ParsedDirective[] {
  return csp
    .split(';')
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => {
      const parts = d.split(/\s+/)
      return { name: parts[0], values: parts.slice(1) }
    })
}

function analyzeDirective(directive: ParsedDirective): CSPDirectiveResult {
  const findings: CSPFinding[] = []
  const { name, values } = directive

  for (const value of values) {
    // unsafe-eval in script-src
    if (name === 'script-src' && value === "'unsafe-eval'") {
      findings.push({
        type: 'unsafe-eval',
        risk: 'critical',
        description: `'unsafe-eval' in script-src allows eval() and similar dynamic code execution`,
        detail:
          'This completely undermines CSP protection against XSS. Any injection vulnerability can execute arbitrary code.',
      })
    }

    // unsafe-inline in script-src
    if (name === 'script-src' && value === "'unsafe-inline'") {
      findings.push({
        type: 'unsafe-inline',
        risk: 'high',
        description: `'unsafe-inline' in script-src allows inline scripts to execute`,
        detail:
          'Inline event handlers and <script> tags can be injected. This defeats most of CSP\'s XSS protection.',
      })
    }

    // Wildcard source
    if (value === '*') {
      findings.push({
        type: 'wildcard',
        risk: 'high',
        description: `Wildcard '*' in ${name} allows loading resources from any origin`,
        detail: 'Any domain can serve resources for this directive, making CSP ineffective.',
      })
    }

    // Overly permissive scheme sources
    if (['http:', 'https:', 'data:'].includes(value)) {
      findings.push({
        type: 'permissive',
        risk: 'medium',
        description: `Scheme source '${value}' in ${name} is overly permissive`,
        detail: `Allows loading resources from any ${value.replace(':', '')} URL, which significantly weakens CSP.`,
      })
    }

    // CSP bypass domains
    const bypass = isBypassDomain(value)
    if (bypass) {
      findings.push({
        type: 'bypass-domain',
        risk: 'high',
        description: `${bypass.domain} in ${name} is a known CSP bypass domain (${bypass.technique})`,
        detail: bypass.description,
      })
    }
  }

  return { directive: name, values, findings }
}

function checkMissingDirectives(
  directives: ParsedDirective[],
): CSPFinding[] {
  const findings: CSPFinding[] = []
  const directiveNames = new Set(directives.map((d) => d.name))
  const hasDefaultSrc = directiveNames.has('default-src')

  const recommended = [
    {
      name: 'form-action',
      desc: 'form-action is not set — forms can submit to any URL (does not fall back to default-src)',
    },
    {
      name: 'frame-ancestors',
      desc: 'frame-ancestors is not set — the extension page can be framed by any origin (does not fall back to default-src)',
    },
    {
      name: 'base-uri',
      desc: 'base-uri is not set — a <base> tag can change relative URL resolution (does not fall back to default-src)',
    },
  ]

  for (const rec of recommended) {
    if (!directiveNames.has(rec.name)) {
      findings.push({
        type: 'missing-directive',
        risk: 'medium',
        description: rec.desc,
      })
    }
  }

  // If no default-src and no script-src, that's notable (though Chrome enforces defaults)
  if (!hasDefaultSrc && !directiveNames.has('script-src')) {
    findings.push({
      type: 'missing-directive',
      risk: 'medium',
      description:
        'Neither default-src nor script-src is specified — relying on browser defaults',
    })
  }

  return findings
}

export function analyzeCSP(manifest: Record<string, unknown>): CSPAnalysisResult {
  const manifestVersion =
    typeof manifest.manifest_version === 'number' ? manifest.manifest_version : 2

  // Extract raw CSP string
  let rawCSP: string | null = null
  const cspField = manifest.content_security_policy

  if (typeof cspField === 'string') {
    // MV2 format
    rawCSP = cspField
  } else if (cspField && typeof cspField === 'object') {
    // MV3 format
    const cspObj = cspField as Record<string, unknown>
    if (typeof cspObj.extension_pages === 'string') {
      rawCSP = cspObj.extension_pages
    }
  }

  const isDefault = rawCSP === null

  // Use the effective CSP (declared or Chrome's default)
  const effectiveCSP = rawCSP ?? CHROME_DEFAULT_CSP
  const parsedDirectives = parseCSPString(effectiveCSP)

  // Analyze each directive
  const directiveResults = parsedDirectives.map(analyzeDirective)

  // Check for missing directives (only when a CSP is explicitly declared)
  const missingFindings = rawCSP !== null ? checkMissingDirectives(parsedDirectives) : []

  // Collect all findings
  const allFindings: CSPFinding[] = [
    ...directiveResults.flatMap((d) => d.findings),
    ...missingFindings,
  ]

  return {
    raw: rawCSP,
    isDefault,
    manifestVersion,
    directives: directiveResults,
    findings: allFindings,
  }
}
