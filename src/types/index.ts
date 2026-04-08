export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export interface PermissionInfo {
  name: string
  description: string
  risk: RiskLevel
  isOptional: boolean
  isHostPermission: boolean
}

export interface PermissionCombination {
  permissions: string[]
  risk: RiskLevel
  title: string
  description: string
  realWorldExample: string
}

export interface CSPDirectiveResult {
  directive: string
  values: string[]
  findings: CSPFinding[]
}

export interface CSPFinding {
  type: 'unsafe-eval' | 'unsafe-inline' | 'wildcard' | 'bypass-domain' | 'missing-directive' | 'permissive'
  risk: RiskLevel
  description: string
  detail?: string
}

export interface CSPAnalysisResult {
  raw: string | null
  isDefault: boolean
  manifestVersion: number
  directives: CSPDirectiveResult[]
  findings: CSPFinding[]
}

export interface CodePatternMatch {
  pattern: string
  category: 'sink' | 'source' | 'network' | 'obfuscation'
  description: string
  filePath: string
  lineNumber: number
  context: string[]
  fileType: 'content-script' | 'background' | 'web-accessible' | 'other'
  risk: RiskLevel
}

export interface HostPermissionFinding {
  pattern: string
  type: 'overly-broad' | 'sensitive-domain' | 'file-access'
  risk: RiskLevel
  description: string
  suggestion?: string
}

export interface ManifestVersionFinding {
  manifestVersion: number
  risk: RiskLevel
  description: string
  details: string[]
}

export interface AnalysisReport {
  metadata: {
    extensionName: string
    version: string
    manifestVersion: number
    inputMethod: 'id' | 'upload' | 'paste'
    analyzedAt: string
  }
  permissions: PermissionInfo[]
  combinations: PermissionCombination[]
  csp: CSPAnalysisResult
  codePatterns: CodePatternMatch[]
  hostPermissions: HostPermissionFinding[]
  manifestVersionAnalysis: ManifestVersionFinding
  summary: {
    totalPermissions: number
    criticalPermissions: number
    highPermissions: number
    combinationsFound: number
    cspFindings: number
    codePatterns: number
    hostFindings: number
  }
}

export interface ExtensionFiles {
  manifest: Record<string, unknown>
  jsFiles: Map<string, string>
  allFiles: string[]
}

export type InputMethod = 'id' | 'upload' | 'paste'
