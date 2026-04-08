import { describe, it, expect } from 'vitest'
import { analyzeCSP } from '../../src/analyzer/csp-analyzer'

describe('analyzeCSP', () => {
  describe('MV2 format', () => {
    it('parses MV2 string CSP', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self'; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      expect(result.manifestVersion).toBe(2)
      expect(result.raw).toBe("script-src 'self'; object-src 'self'")
      expect(result.isDefault).toBe(false)
      expect(result.directives).toHaveLength(2)
      expect(result.directives[0].directive).toBe('script-src')
      expect(result.directives[1].directive).toBe('object-src')
    })
  })

  describe('MV3 format', () => {
    it('parses MV3 object CSP with extension_pages', () => {
      const manifest = {
        manifest_version: 3,
        content_security_policy: {
          extension_pages: "script-src 'self'; object-src 'self'",
        },
      }
      const result = analyzeCSP(manifest)
      expect(result.manifestVersion).toBe(3)
      expect(result.raw).toBe("script-src 'self'; object-src 'self'")
      expect(result.isDefault).toBe(false)
    })
  })

  describe('missing CSP / default', () => {
    it('uses Chrome default when no CSP is declared', () => {
      const manifest = { manifest_version: 2 }
      const result = analyzeCSP(manifest)
      expect(result.isDefault).toBe(true)
      expect(result.raw).toBeNull()
      // Should not produce findings about missing directives for default CSP
      const missingFindings = result.findings.filter((f) => f.type === 'missing-directive')
      expect(missingFindings).toHaveLength(0)
    })

    it('does not penalize for missing CSP when Chrome enforces a default', () => {
      const manifest = { manifest_version: 3 }
      const result = analyzeCSP(manifest)
      expect(result.isDefault).toBe(true)
      // Should have no critical/high findings for a default CSP
      const severeFindings = result.findings.filter(
        (f) => f.risk === 'critical' || f.risk === 'high',
      )
      expect(severeFindings).toHaveLength(0)
    })
  })

  describe('unsafe-eval detection', () => {
    it('flags unsafe-eval in script-src as critical', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const evalFindings = result.findings.filter((f) => f.type === 'unsafe-eval')
      expect(evalFindings).toHaveLength(1)
      expect(evalFindings[0].risk).toBe('critical')
    })
  })

  describe('unsafe-inline detection', () => {
    it('flags unsafe-inline in script-src as high', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self' 'unsafe-inline'; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const inlineFindings = result.findings.filter((f) => f.type === 'unsafe-inline')
      expect(inlineFindings).toHaveLength(1)
      expect(inlineFindings[0].risk).toBe('high')
    })
  })

  describe('wildcard detection', () => {
    it('flags wildcard * source as high', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self' *; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const wildcardFindings = result.findings.filter((f) => f.type === 'wildcard')
      expect(wildcardFindings).toHaveLength(1)
      expect(wildcardFindings[0].risk).toBe('high')
    })
  })

  describe('bypass domain detection', () => {
    it('flags known CSP bypass domains', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy:
          "script-src 'self' https://ajax.googleapis.com https://cdn.jsdelivr.net; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const bypassFindings = result.findings.filter((f) => f.type === 'bypass-domain')
      expect(bypassFindings).toHaveLength(2)
      expect(bypassFindings[0].risk).toBe('high')
    })

    it('includes exploit explanation for bypass domains', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy:
          "script-src 'self' https://raw.githubusercontent.com; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const bypassFindings = result.findings.filter((f) => f.type === 'bypass-domain')
      expect(bypassFindings).toHaveLength(1)
      expect(bypassFindings[0].detail).toBeTruthy()
      expect(bypassFindings[0].detail!.length).toBeGreaterThan(0)
    })
  })

  describe('permissive sources', () => {
    it('flags http:, https:, and data: as medium', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self' https: data:; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const permissiveFindings = result.findings.filter((f) => f.type === 'permissive')
      expect(permissiveFindings).toHaveLength(2)
      expect(permissiveFindings.every((f) => f.risk === 'medium')).toBe(true)
    })
  })

  describe('missing directive detection', () => {
    it('flags missing form-action, frame-ancestors, and base-uri when CSP is declared', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy: "script-src 'self'; object-src 'self'",
      }
      const result = analyzeCSP(manifest)
      const missingFindings = result.findings.filter((f) => f.type === 'missing-directive')
      expect(missingFindings).toHaveLength(3)
      const missingNames = missingFindings.map((f) => f.description)
      expect(missingNames.some((d) => d.includes('form-action'))).toBe(true)
      expect(missingNames.some((d) => d.includes('frame-ancestors'))).toBe(true)
      expect(missingNames.some((d) => d.includes('base-uri'))).toBe(true)
    })

    it('does not flag missing directives when they are present', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy:
          "script-src 'self'; object-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'",
      }
      const result = analyzeCSP(manifest)
      const missingFindings = result.findings.filter((f) => f.type === 'missing-directive')
      expect(missingFindings).toHaveLength(0)
    })
  })

  describe('multiple issues combined', () => {
    it('reports all findings for a very permissive CSP', () => {
      const manifest = {
        manifest_version: 2,
        content_security_policy:
          "script-src 'self' 'unsafe-eval' 'unsafe-inline' * https://cdnjs.cloudflare.com; object-src *",
      }
      const result = analyzeCSP(manifest)
      expect(result.findings.length).toBeGreaterThanOrEqual(4)
      const types = new Set(result.findings.map((f) => f.type))
      expect(types.has('unsafe-eval')).toBe(true)
      expect(types.has('unsafe-inline')).toBe(true)
      expect(types.has('wildcard')).toBe(true)
      expect(types.has('bypass-domain')).toBe(true)
    })
  })
})
