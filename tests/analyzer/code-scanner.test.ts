import { describe, it, expect } from 'vitest'
import { scanCode } from '../../src/analyzer/code-scanner'

const baseManifest = {
  manifest_version: 2,
  content_scripts: [{ matches: ['<all_urls>'], js: ['content.js'] }],
  background: { scripts: ['background.js'] },
  web_accessible_resources: ['injectable.js'],
}

function makeFiles(files: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(files))
}

describe('scanCode', () => {
  describe('sink patterns', () => {
    it('detects eval() as critical', () => {
      const files = makeFiles({ 'background.js': 'const x = eval(userInput);' })
      const results = scanCode(files, baseManifest)
      const evalMatch = results.find((r) => r.pattern === 'eval')
      expect(evalMatch).toBeDefined()
      expect(evalMatch!.risk).toBe('critical')
      expect(evalMatch!.category).toBe('sink')
    })

    it('detects new Function() as critical', () => {
      const files = makeFiles({ 'background.js': 'const fn = new Function("return 1");' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'new-function')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('critical')
    })

    it('detects innerHTML assignment as high', () => {
      const files = makeFiles({ 'content.js': 'element.innerHTML = data;' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'innerhtml')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('high')
    })

    it('detects document.write as high', () => {
      const files = makeFiles({ 'content.js': 'document.write("<p>hello</p>");' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'document-write')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('high')
    })

    it('detects setTimeout with string argument', () => {
      const files = makeFiles({ 'background.js': 'setTimeout("doStuff()", 100);' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'settimeout-string')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('high')
    })
  })

  describe('source patterns', () => {
    it('detects postMessage listener as high', () => {
      const files = makeFiles({
        'content.js': 'window.addEventListener("message", handler);',
      })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'postmessage-listener')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('high')
    })

    it('detects onMessageExternal as high', () => {
      const files = makeFiles({
        'background.js': 'chrome.runtime.onMessageExternal.addListener(handler);',
      })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'external-message-listener')
      expect(match).toBeDefined()
    })
  })

  describe('network patterns', () => {
    it('detects dynamic script creation as critical', () => {
      const files = makeFiles({
        'background.js': 'const s = document.createElement("script");',
      })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'dynamic-script')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('critical')
    })

    it('detects fetch calls as medium', () => {
      const files = makeFiles({ 'background.js': 'fetch("https://example.com/api");' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'fetch-call')
      expect(match).toBeDefined()
      expect(match!.risk).toBe('medium')
    })
  })

  describe('obfuscation patterns', () => {
    it('detects atob as medium', () => {
      const files = makeFiles({ 'background.js': 'const decoded = atob(encoded);' })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'atob-general')
      expect(match).toBeDefined()
      expect(match!.category).toBe('obfuscation')
    })

    it('detects String.fromCharCode as medium', () => {
      const files = makeFiles({
        'background.js': 'const s = String.fromCharCode(72, 101);',
      })
      const results = scanCode(files, baseManifest)
      const match = results.find((r) => r.pattern === 'charcode')
      expect(match).toBeDefined()
    })
  })

  describe('file type detection', () => {
    it('identifies content scripts from manifest', () => {
      const files = makeFiles({ 'content.js': 'eval("test");' })
      const results = scanCode(files, baseManifest)
      expect(results[0].fileType).toBe('content-script')
    })

    it('identifies background scripts from manifest', () => {
      const files = makeFiles({ 'background.js': 'eval("test");' })
      const results = scanCode(files, baseManifest)
      expect(results[0].fileType).toBe('background')
    })

    it('identifies web-accessible resources from manifest', () => {
      const files = makeFiles({ 'injectable.js': 'eval("test");' })
      const results = scanCode(files, baseManifest)
      expect(results[0].fileType).toBe('web-accessible')
    })

    it('marks unknown files as other', () => {
      const files = makeFiles({ 'utils/helper.js': 'eval("test");' })
      const results = scanCode(files, baseManifest)
      expect(results[0].fileType).toBe('other')
    })

    it('identifies service worker in MV3', () => {
      const mv3Manifest = {
        manifest_version: 3,
        background: { service_worker: 'sw.js' },
      }
      const files = makeFiles({ 'sw.js': 'eval("test");' })
      const results = scanCode(files, mv3Manifest)
      expect(results[0].fileType).toBe('background')
    })
  })

  describe('context-dependent patterns', () => {
    it('only flags window.name in web-accessible and content-script files', () => {
      const files = makeFiles({
        'content.js': 'const name = window.name;',
        'background.js': 'const name = window.name;',
        'injectable.js': 'const name = window.name;',
      })
      const results = scanCode(files, baseManifest)
      const windowNameMatches = results.filter((r) => r.pattern === 'window-name')
      // Should only match content.js and injectable.js, not background.js
      expect(windowNameMatches).toHaveLength(2)
      const fileTypes = windowNameMatches.map((m) => m.fileType)
      expect(fileTypes).toContain('content-script')
      expect(fileTypes).toContain('web-accessible')
      expect(fileTypes).not.toContain('background')
    })
  })

  describe('comment skipping', () => {
    it('skips lines starting with //', () => {
      const files = makeFiles({ 'background.js': '// eval("test");' })
      const results = scanCode(files, baseManifest)
      const evalMatches = results.filter((r) => r.pattern === 'eval')
      expect(evalMatches).toHaveLength(0)
    })

    it('skips lines starting with *', () => {
      const files = makeFiles({ 'background.js': ' * eval("test");' })
      const results = scanCode(files, baseManifest)
      const evalMatches = results.filter((r) => r.pattern === 'eval')
      expect(evalMatches).toHaveLength(0)
    })

    it('skips lines starting with /*', () => {
      const files = makeFiles({ 'background.js': '/* eval("test"); */' })
      const results = scanCode(files, baseManifest)
      const evalMatches = results.filter((r) => r.pattern === 'eval')
      expect(evalMatches).toHaveLength(0)
    })
  })

  describe('sorting and context', () => {
    it('sorts results by risk level (critical first)', () => {
      const files = makeFiles({
        'background.js': 'fetch("url");\neval("code");\nelement.innerHTML = x;',
      })
      const results = scanCode(files, baseManifest)
      expect(results.length).toBeGreaterThanOrEqual(3)
      // First result should be critical (eval)
      expect(results[0].risk).toBe('critical')
    })

    it('captures context lines around matches', () => {
      const files = makeFiles({
        'background.js': 'const a = 1;\neval("code");\nconst b = 2;',
      })
      const results = scanCode(files, baseManifest)
      const evalMatch = results.find((r) => r.pattern === 'eval')
      expect(evalMatch).toBeDefined()
      expect(evalMatch!.context).toHaveLength(3)
      expect(evalMatch!.context[0]).toContain('const a')
      expect(evalMatch!.context[1]).toContain('eval')
      expect(evalMatch!.context[2]).toContain('const b')
    })

    it('captures line number correctly', () => {
      const files = makeFiles({
        'background.js': 'line1\nline2\neval("code");\nline4',
      })
      const results = scanCode(files, baseManifest)
      const evalMatch = results.find((r) => r.pattern === 'eval')
      expect(evalMatch!.lineNumber).toBe(3)
    })
  })
})
