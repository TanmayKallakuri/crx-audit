import type { CodePatternMatch } from '../types'
import { codePatterns } from '../data/code-patterns'
import { parseManifest } from './manifest-parser'

type FileType = 'content-script' | 'background' | 'web-accessible' | 'other'

function isCommentLine(line: string): boolean {
  const trimmed = line.trim()
  return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')
}

function determineFileType(
  filePath: string,
  manifest: Record<string, unknown>,
): FileType {
  const parsed = parseManifest(manifest)
  const normalized = filePath.replace(/\\/g, '/')

  // Content scripts
  for (const cs of parsed.contentScripts) {
    for (const jsPath of cs.js) {
      if (normalized === jsPath || normalized.endsWith('/' + jsPath)) {
        return 'content-script'
      }
    }
  }

  // Background scripts
  for (const bgScript of parsed.backgroundScripts) {
    if (normalized === bgScript || normalized.endsWith('/' + bgScript)) {
      return 'background'
    }
  }
  if (
    parsed.serviceWorker &&
    (normalized === parsed.serviceWorker || normalized.endsWith('/' + parsed.serviceWorker))
  ) {
    return 'background'
  }

  // Web-accessible resources — simple glob matching
  for (const warPattern of parsed.webAccessibleResources) {
    if (matchesGlobPattern(normalized, warPattern)) {
      return 'web-accessible'
    }
  }

  return 'other'
}

function matchesGlobPattern(filePath: string, pattern: string): boolean {
  // Convert simple glob patterns to regex
  // Handles *, **, and ? wildcards
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '___DOUBLESTAR___')
    .replace(/\*/g, '[^/]*')
    .replace(/___DOUBLESTAR___/g, '.*')
    .replace(/\?/g, '.')

  const regex = new RegExp(`(^|/)${regexStr}$`)
  return regex.test(filePath)
}

const riskOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
}

export function scanCode(
  jsFiles: Map<string, string>,
  manifest: Record<string, unknown>,
): CodePatternMatch[] {
  const matches: CodePatternMatch[] = []

  for (const [filePath, content] of jsFiles) {
    const fileType = determineFileType(filePath, manifest)
    const lines = content.split('\n')

    for (const codePattern of codePatterns) {
      // Skip context-dependent patterns that don't apply to this file type
      if (codePattern.contextDependent) {
        if (!codePattern.contextDependent.onlyInFileTypes.includes(fileType)) {
          continue
        }
      }

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]

        if (isCommentLine(line)) continue

        if (codePattern.pattern.test(line)) {
          // Build 3-line context: line before, matching line, line after
          const context: string[] = []
          if (i > 0) context.push(lines[i - 1])
          context.push(line)
          if (i < lines.length - 1) context.push(lines[i + 1])

          matches.push({
            pattern: codePattern.id,
            category: codePattern.category,
            description: codePattern.description,
            filePath,
            lineNumber: i + 1,
            context,
            fileType,
            risk: codePattern.risk,
          })
        }
      }
    }
  }

  // Sort by risk level (critical first)
  matches.sort((a, b) => (riskOrder[a.risk] ?? 4) - (riskOrder[b.risk] ?? 4))

  return matches
}
