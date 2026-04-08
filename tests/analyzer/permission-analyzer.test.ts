import { describe, it, expect } from 'vitest'
import { analyzeExtension } from '../../src/analyzer'
import type { ExtensionFiles } from '../../src/types'

function makeExtensionFiles(manifest: Record<string, unknown>): ExtensionFiles {
  return { manifest, jsFiles: new Map(), allFiles: [] }
}

describe('permission analysis', () => {
  it('identifies critical permissions correctly', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['cookies', 'debugger', 'nativeMessaging'],
      host_permissions: ['<all_urls>'],
    })
    const report = analyzeExtension(files, 'paste')
    const criticals = report.permissions.filter((p) => p.risk === 'critical')
    expect(criticals.length).toBeGreaterThanOrEqual(3)
    expect(criticals.map((p) => p.name)).toContain('cookies')
    expect(criticals.map((p) => p.name)).toContain('debugger')
    expect(criticals.map((p) => p.name)).toContain('nativeMessaging')
  })

  it('distinguishes required vs optional permissions', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['tabs'],
      optional_permissions: ['history'],
    })
    const report = analyzeExtension(files, 'paste')
    const tabs = report.permissions.find((p) => p.name === 'tabs')
    const history = report.permissions.find((p) => p.name === 'history')
    expect(tabs?.isOptional).toBe(false)
    expect(history?.isOptional).toBe(true)
  })

  it('handles MV2 permissions in single array', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Test',
      version: '1.0',
      permissions: ['tabs', 'https://example.com/*'],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.permissions.length).toBeGreaterThanOrEqual(2)
  })

  it('handles MV3 host_permissions separately', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['storage'],
      host_permissions: ['https://example.com/*'],
    })
    const report = analyzeExtension(files, 'paste')
    const hostPerm = report.permissions.find((p) => p.name === 'https://example.com/*')
    expect(hostPerm?.isHostPermission).toBe(true)
  })

  it('rates low-risk permissions correctly', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['storage', 'alarms', 'activeTab'],
    })
    const report = analyzeExtension(files, 'paste')
    const storage = report.permissions.find((p) => p.name === 'storage')
    const alarms = report.permissions.find((p) => p.name === 'alarms')
    expect(storage?.risk).toBe('low')
    expect(alarms?.risk).toBe('low')
  })
})

describe('combination analysis', () => {
  it('detects cookies + all_urls as session hijacking', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Test',
      version: '1.0',
      permissions: ['cookies', '<all_urls>'],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.combinations.length).toBeGreaterThanOrEqual(1)
    const sessionHijack = report.combinations.find((c) =>
      c.permissions.includes('cookies') && c.permissions.includes('<all_urls>')
    )
    expect(sessionHijack).toBeDefined()
    expect(sessionHijack!.risk).toBe('critical')
  })

  it('does not flag combos when permissions are missing', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: ['storage', 'alarms'],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.combinations.length).toBe(0)
  })

  it('detects multiple combinations at once', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Test',
      version: '1.0',
      permissions: [
        '<all_urls>', 'cookies', 'webRequestBlocking',
        'nativeMessaging', 'management', 'debugger', 'tabs',
      ],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.combinations.length).toBeGreaterThanOrEqual(4)
  })

  it('includes real-world examples in every combination', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Test',
      version: '1.0',
      permissions: ['<all_urls>', 'cookies'],
    })
    const report = analyzeExtension(files, 'paste')
    for (const combo of report.combinations) {
      expect(combo.realWorldExample).toBeTruthy()
      expect(combo.realWorldExample.length).toBeGreaterThan(20)
    }
  })
})

describe('manifest version analysis', () => {
  it('flags MV2 as medium risk', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Test',
      version: '1.0',
      permissions: [],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.manifestVersionAnalysis.manifestVersion).toBe(2)
    expect(report.manifestVersionAnalysis.risk).toBe('medium')
  })

  it('rates MV3 as low or none risk', () => {
    const files = makeExtensionFiles({
      manifest_version: 3,
      name: 'Test',
      version: '1.0',
      permissions: [],
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.manifestVersionAnalysis.manifestVersion).toBe(3)
    expect(['low', 'none']).toContain(report.manifestVersionAnalysis.risk)
  })
})

describe('summary counts', () => {
  it('computes correct summary for a risky extension', () => {
    const files = makeExtensionFiles({
      manifest_version: 2,
      name: 'Risky',
      version: '2.0',
      permissions: ['<all_urls>', 'cookies', 'tabs', 'debugger', 'storage'],
      content_security_policy: "script-src 'self' 'unsafe-eval'; object-src 'self'",
    })
    const report = analyzeExtension(files, 'paste')
    expect(report.summary.totalPermissions).toBe(5)
    expect(report.summary.criticalPermissions).toBeGreaterThanOrEqual(2)
    expect(report.summary.combinationsFound).toBeGreaterThanOrEqual(1)
    expect(report.summary.cspFindings).toBeGreaterThanOrEqual(1)
  })
})
