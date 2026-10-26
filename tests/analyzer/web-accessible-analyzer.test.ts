import { describe, it, expect } from 'vitest'
import { analyzeWebAccessibleResources } from '../../src/analyzer/web-accessible-analyzer'

describe('analyzeWebAccessibleResources', () => {
  describe('broad exposure (MV3)', () => {
    it('flags WAR exposed to <all_urls>', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['injected.js'], matches: ['<all_urls>'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      const broad = findings.find((f) => f.type === 'broad-exposure')
      expect(broad).toBeDefined()
      expect(broad!.risk).toBe('high')
      expect(broad!.description).toContain('<all_urls>')
    })

    it('flags WAR exposed to *://*/*', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['style.css'], matches: ['*://*/*'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings.some((f) => f.type === 'broad-exposure')).toBe(true)
    })
  })

  describe('sensitive resource types', () => {
    it('flags JS resources as sensitive', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['bridge.js'], matches: ['https://trusted.example.com/*'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      const sensitive = findings.find((f) => f.type === 'sensitive-resource')
      expect(sensitive).toBeDefined()
      expect(sensitive!.risk).toBe('high')
      expect(sensitive!.description).toContain('bridge.js')
    })

    it('flags JSON and HTML resources as sensitive', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['config.json', 'page.html'], matches: ['https://a.example.com/*'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings.some((f) => f.type === 'sensitive-resource')).toBe(true)
    })

    it('does NOT flag static images as sensitive', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['logo.png', 'font.woff2'], matches: ['<all_urls>'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings.some((f) => f.type === 'sensitive-resource')).toBe(false)
    })
  })

  describe('MV2 string[] format', () => {
    it('treats MV2 string WAR as exposed to all origins', () => {
      const manifest = {
        manifest_version: 2,
        web_accessible_resources: ['injected.js'],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings.some((f) => f.type === 'broad-exposure')).toBe(true)
      expect(findings.some((f) => f.type === 'sensitive-resource')).toBe(true)
    })
  })

  describe('externally_connectable', () => {
    it('flags broad externally_connectable matches', () => {
      const manifest = {
        manifest_version: 3,
        externally_connectable: { matches: ['*://*/*'] },
      }
      const findings = analyzeWebAccessibleResources(manifest)
      const broad = findings.find((f) => f.type === 'broad-connectable')
      expect(broad).toBeDefined()
      expect(broad!.risk).toBe('medium')
    })

    it('does NOT flag narrowly scoped externally_connectable', () => {
      const manifest = {
        manifest_version: 3,
        externally_connectable: { matches: ['https://myapp.example.com/*'] },
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings.some((f) => f.type === 'broad-connectable')).toBe(false)
    })
  })

  describe('no false positives', () => {
    it('returns no findings for a manifest with no WAR or externally_connectable', () => {
      const manifest = {
        manifest_version: 3,
        permissions: ['storage', 'alarms'],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings).toHaveLength(0)
    })

    it('returns no findings for narrowly scoped WAR with static assets', () => {
      const manifest = {
        manifest_version: 3,
        web_accessible_resources: [
          { resources: ['icon.png'], matches: ['https://trusted.example.com/*'] },
        ],
      }
      const findings = analyzeWebAccessibleResources(manifest)
      expect(findings).toHaveLength(0)
    })
  })
})
