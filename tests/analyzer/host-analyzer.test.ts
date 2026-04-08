import { describe, it, expect } from 'vitest'
import { analyzeHostPermissions } from '../../src/analyzer/host-analyzer'

describe('analyzeHostPermissions', () => {
  describe('overly broad patterns', () => {
    it('flags <all_urls> as overly broad', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['<all_urls>'],
      }
      const findings = analyzeHostPermissions(manifest)
      const broad = findings.find((f) => f.pattern === '<all_urls>')
      expect(broad).toBeDefined()
      expect(broad!.type).toBe('overly-broad')
      expect(broad!.risk).toBe('high')
    })

    it('flags *://*/* as overly broad', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['*://*/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      expect(findings.some((f) => f.type === 'overly-broad')).toBe(true)
    })

    it('flags http://*/* and https://*/* as overly broad', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['http://*/*', 'https://*/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      const broad = findings.filter((f) => f.type === 'overly-broad')
      expect(broad).toHaveLength(2)
    })

    it('flags broad patterns in MV2 permissions array', () => {
      const manifest = {
        manifest_version: 2,
        permissions: ['<all_urls>', 'tabs'],
      }
      const findings = analyzeHostPermissions(manifest)
      expect(findings.some((f) => f.pattern === '<all_urls>' && f.type === 'overly-broad')).toBe(
        true,
      )
    })
  })

  describe('activeTab suggestion', () => {
    it('suggests activeTab for overly broad patterns', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['<all_urls>'],
      }
      const findings = analyzeHostPermissions(manifest)
      const broad = findings.find((f) => f.type === 'overly-broad')
      expect(broad!.suggestion).toBeDefined()
      expect(broad!.suggestion).toContain('activeTab')
    })
  })

  describe('sensitive domains', () => {
    it('flags access to Gmail as sensitive', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['*://mail.google.com/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      const sensitive = findings.find((f) => f.type === 'sensitive-domain')
      expect(sensitive).toBeDefined()
      expect(sensitive!.description).toContain('Gmail')
    })

    it('flags access to PayPal as sensitive', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['https://*.paypal.com/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      const sensitive = findings.find((f) => f.type === 'sensitive-domain')
      expect(sensitive).toBeDefined()
      expect(sensitive!.risk).toBe('critical')
    })

    it('detects sensitive domains in content script matches', () => {
      const manifest = {
        manifest_version: 3,
        content_scripts: [
          {
            matches: ['*://github.com/*'],
            js: ['content.js'],
          },
        ],
      }
      const findings = analyzeHostPermissions(manifest)
      const sensitive = findings.find((f) => f.type === 'sensitive-domain')
      expect(sensitive).toBeDefined()
      expect(sensitive!.description).toContain('content script')
    })
  })

  describe('file access', () => {
    it('flags file:/// access', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['file:///*'],
      }
      const findings = analyzeHostPermissions(manifest)
      const fileAccess = findings.find((f) => f.type === 'file-access')
      expect(fileAccess).toBeDefined()
      expect(fileAccess!.risk).toBe('high')
    })

    it('flags file://*/* access', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['file://*/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      const fileAccess = findings.find((f) => f.type === 'file-access')
      expect(fileAccess).toBeDefined()
    })
  })

  describe('no false positives', () => {
    it('returns no findings for a non-sensitive specific domain', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['https://myapi.example.com/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      expect(findings).toHaveLength(0)
    })

    it('returns no findings for a manifest with no host permissions', () => {
      const manifest = {
        manifest_version: 3,
        permissions: ['storage', 'alarms'],
      }
      const findings = analyzeHostPermissions(manifest)
      expect(findings).toHaveLength(0)
    })
  })

  describe('deduplication', () => {
    it('does not duplicate findings for the same pattern in multiple sources', () => {
      const manifest = {
        manifest_version: 3,
        host_permissions: ['<all_urls>'],
        content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'] }],
      }
      const findings = analyzeHostPermissions(manifest)
      const allUrlsFindings = findings.filter((f) => f.pattern === '<all_urls>')
      expect(allUrlsFindings).toHaveLength(1)
    })
  })

  describe('optional host permissions', () => {
    it('analyzes optional_host_permissions in MV3', () => {
      const manifest = {
        manifest_version: 3,
        optional_host_permissions: ['*://mail.google.com/*'],
      }
      const findings = analyzeHostPermissions(manifest)
      expect(findings.some((f) => f.type === 'sensitive-domain')).toBe(true)
    })
  })
})
