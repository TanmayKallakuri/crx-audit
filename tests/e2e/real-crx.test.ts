import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import JSZip from 'jszip'
import { analyzeExtension } from '../../src/analyzer'
import type { ExtensionFiles } from '../../src/types'

async function extractCRX(filePath: string): Promise<ExtensionFiles> {
  const buffer = readFileSync(filePath)

  // CRX3 header: magic(4) + version(4) + header_length(4) + header + ZIP
  const magic = buffer.toString('ascii', 0, 4)
  let zipStart = 0

  if (magic === 'Cr24') {
    const headerLen = buffer.readUInt32LE(8)
    zipStart = 12 + headerLen
  }

  const zipData = buffer.subarray(zipStart)
  const zip = await JSZip.loadAsync(zipData)

  const manifestFile = zip.file('manifest.json')
  if (!manifestFile) throw new Error('No manifest.json found')
  const manifestText = await manifestFile.async('string')
  const manifest = JSON.parse(manifestText)

  const jsFiles = new Map<string, string>()
  const allFiles: string[] = []

  for (const [path, file] of Object.entries(zip.files)) {
    if (file.dir) continue
    allFiles.push(path)
    if (path.endsWith('.js')) {
      const content = await (file as JSZip.JSZipObject).async('string')
      jsFiles.set(path, content)
    }
  }

  return { manifest, jsFiles, allFiles }
}

describe('real CRX analysis - uBlock Origin', () => {
  it('extracts and analyzes uBlock Origin successfully', async () => {
    const crxPath = path.resolve(__dirname, '../fixtures/ublock.crx')
    const files = await extractCRX(crxPath)

    // Verify manifest was parsed
    expect(files.manifest).toBeDefined()
    expect(files.manifest.name).toBeDefined()
    expect(files.allFiles.length).toBeGreaterThan(10)
    expect(files.jsFiles.size).toBeGreaterThan(5)

    // Run full analysis
    const report = analyzeExtension(files, 'upload')

    // Verify report structure
    expect(report.metadata.extensionName).toBeTruthy()
    expect(report.metadata.manifestVersion).toBeGreaterThanOrEqual(2)
    expect(report.permissions.length).toBeGreaterThan(0)
    expect(report.summary.totalPermissions).toBeGreaterThan(0)

    // uBlock Origin should have some permissions flagged
    const hasWebRequest = report.permissions.some((p) => p.name === 'webRequest')
    expect(hasWebRequest).toBe(true)

    // Should have code pattern findings (it's a large extension with lots of JS)
    expect(report.codePatterns.length).toBeGreaterThan(0)

    // Verify no crash and report is complete
    expect(report.csp).toBeDefined()
    expect(report.hostPermissions).toBeDefined()
    expect(report.manifestVersionAnalysis).toBeDefined()

    console.log(`uBlock Origin analysis complete:`)
    console.log(`  Name: ${report.metadata.extensionName}`)
    console.log(`  Version: ${report.metadata.version}`)
    console.log(`  Manifest: V${report.metadata.manifestVersion}`)
    console.log(`  Permissions: ${report.summary.totalPermissions}`)
    console.log(`  Critical: ${report.summary.criticalPermissions}`)
    console.log(`  Combinations: ${report.summary.combinationsFound}`)
    console.log(`  CSP findings: ${report.summary.cspFindings}`)
    console.log(`  Code patterns: ${report.summary.codePatterns}`)
    console.log(`  Host issues: ${report.summary.hostFindings}`)
  }, 30000)
})
