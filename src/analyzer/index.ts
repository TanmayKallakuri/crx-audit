import type {
  AnalysisReport,
  ExtensionFiles,
  InputMethod,
  PermissionInfo,
  PermissionCombination,
  ManifestVersionFinding,
} from '../types'
import { analyzeCSP } from './csp-analyzer'
import { scanCode } from './code-scanner'
import { analyzeHostPermissions } from './host-analyzer'
import { parseManifest } from './manifest-parser'
import { permissionMap } from '../data/permissions'
import { dangerousCombinations } from '../data/dangerous-combos'

function analyzePermissions(manifest: Record<string, unknown>): PermissionInfo[] {
  const parsed = parseManifest(manifest)
  const results: PermissionInfo[] = []

  const addPermission = (name: string, isOptional: boolean, isHost: boolean) => {
    const detail = permissionMap[name]
    results.push({
      name,
      description: detail?.description ?? 'Unknown permission',
      risk: detail?.risk ?? 'medium',
      isOptional,
      isHostPermission: isHost,
    })
  }

  for (const p of parsed.permissions) {
    addPermission(p, false, false)
  }
  for (const p of parsed.optionalPermissions) {
    addPermission(p, true, false)
  }
  for (const p of parsed.hostPermissions) {
    addPermission(p, false, true)
  }
  for (const p of parsed.optionalHostPermissions) {
    addPermission(p, true, true)
  }

  return results
}

function findDangerousCombinations(manifest: Record<string, unknown>): PermissionCombination[] {
  const parsed = parseManifest(manifest)
  const allPermissions = new Set([
    ...parsed.permissions,
    ...parsed.hostPermissions,
  ])

  return dangerousCombinations.filter((combo) =>
    combo.permissions.every((p: string) => allPermissions.has(p)),
  )
}

function analyzeManifestVersion(manifest: Record<string, unknown>): ManifestVersionFinding {
  const mv = typeof manifest.manifest_version === 'number' ? manifest.manifest_version : 2

  if (mv === 2) {
    return {
      manifestVersion: 2,
      risk: 'medium',
      description: 'Manifest V2 has weaker security defaults than V3',
      details: [
        'Background pages run persistently, increasing attack surface',
        'Content Security Policy defaults are less restrictive',
        'Remote code execution via eval() is possible if CSP allows it',
        'MV2 is deprecated and will eventually be removed from Chrome',
      ],
    }
  }

  return {
    manifestVersion: mv,
    risk: 'none',
    description: 'Manifest V3 enforces stricter security defaults',
    details: [
      'Service workers replace persistent background pages',
      'Remote code execution is blocked by default',
      'Host permissions are separated and can be optional',
      'Declarative Net Request replaces webRequestBlocking',
    ],
  }
}

export function analyzeExtension(
  files: ExtensionFiles,
  inputMethod: InputMethod,
): AnalysisReport {
  const { manifest, jsFiles } = files
  const parsed = parseManifest(manifest)

  const permissions = analyzePermissions(manifest)
  const combinations = findDangerousCombinations(manifest)
  const csp = analyzeCSP(manifest)
  const codePatterns = scanCode(jsFiles, manifest)
  const hostPermissions = analyzeHostPermissions(manifest)
  const manifestVersionAnalysis = analyzeManifestVersion(manifest)

  const summary = {
    totalPermissions: permissions.length,
    criticalPermissions: permissions.filter((p) => p.risk === 'critical').length,
    highPermissions: permissions.filter((p) => p.risk === 'high').length,
    combinationsFound: combinations.length,
    cspFindings: csp.findings.length,
    codePatterns: codePatterns.length,
    hostFindings: hostPermissions.length,
  }

  return {
    metadata: {
      extensionName: parsed.name,
      version: parsed.version,
      manifestVersion: parsed.manifestVersion,
      inputMethod,
      analyzedAt: new Date().toISOString(),
    },
    permissions,
    combinations,
    csp,
    codePatterns,
    hostPermissions,
    manifestVersionAnalysis,
    summary,
  }
}
