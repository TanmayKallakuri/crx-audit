import type { AnalysisReport, RiskLevel } from '../types'

function riskBadge(risk: RiskLevel): string {
  const colors: Record<RiskLevel, string> = {
    critical: 'background:#991b1b;color:#fecaca',
    high: 'background:#9a3412;color:#fed7aa',
    medium: 'background:#854d0e;color:#fef08a',
    low: 'background:#1e3a5f;color:#93c5fd',
    none: 'background:#374151;color:#d1d5db',
  }
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;${colors[risk]}">${risk}</span>`
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function generateReport(report: AnalysisReport): string {
  const { metadata, summary, permissions, combinations, csp, codePatterns, hostPermissions, manifestVersionAnalysis } = report
  const date = new Date(metadata.analyzedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })

  const criticalFindings = summary.criticalPermissions + combinations.filter(c => c.risk === 'critical').length
  const overallRisk: RiskLevel = criticalFindings >= 3 ? 'critical' : criticalFindings >= 1 ? 'high' : summary.combinationsFound > 0 ? 'medium' : 'low'

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Report — ${escapeHtml(metadata.extensionName)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Inter',sans-serif; color:#1a1a2e; background:#fff; line-height:1.6; }
  .page { max-width:800px; margin:0 auto; padding:60px 48px; }

  /* Cover */
  .cover { border-bottom:3px solid #1a1a2e; padding-bottom:40px; margin-bottom:40px; }
  .cover-label { font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:2px; color:#6b7280; margin-bottom:4px; }
  .cover-title { font-size:28px; font-weight:700; color:#1a1a2e; margin-bottom:6px; }
  .cover-ext { font-size:20px; font-weight:600; color:#f59e0b; margin-bottom:20px; }
  .cover-meta { display:flex; gap:24px; font-size:13px; color:#6b7280; }
  .cover-meta span { display:flex; align-items:center; gap:6px; }

  /* Summary */
  .summary { background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:24px; margin-bottom:36px; }
  .summary h2 { font-size:14px; font-weight:600; text-transform:uppercase; letter-spacing:1px; color:#6b7280; margin-bottom:16px; }
  .summary-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; }
  .stat { text-align:center; }
  .stat-value { font-size:28px; font-weight:700; }
  .stat-label { font-size:11px; font-weight:500; text-transform:uppercase; letter-spacing:0.5px; color:#6b7280; }
  .stat-critical .stat-value { color:#dc2626; }
  .stat-high .stat-value { color:#ea580c; }
  .stat-medium .stat-value { color:#ca8a04; }
  .stat-low .stat-value { color:#2563eb; }
  .stat-none .stat-value { color:#6b7280; }

  /* Sections */
  .section { margin-bottom:36px; page-break-inside:avoid; }
  .section-header { display:flex; align-items:center; gap:10px; border-bottom:2px solid #e2e8f0; padding-bottom:8px; margin-bottom:16px; }
  .section-num { font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:600; color:#f59e0b; background:#fef3c7; width:24px; height:24px; display:flex; align-items:center; justify-content:center; border-radius:4px; }
  .section-title { font-size:16px; font-weight:700; color:#1a1a2e; }

  /* Tables */
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:8px; }
  th { text-align:left; font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:#6b7280; border-bottom:2px solid #e2e8f0; padding:8px 12px; }
  td { padding:8px 12px; border-bottom:1px solid #f1f5f9; vertical-align:top; }
  .mono { font-family:'JetBrains Mono',monospace; font-size:12px; }

  /* Finding cards */
  .finding { border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin-bottom:12px; border-left:4px solid; }
  .finding-critical { border-left-color:#dc2626; background:#fef2f2; }
  .finding-high { border-left-color:#ea580c; background:#fff7ed; }
  .finding-medium { border-left-color:#ca8a04; background:#fefce8; }
  .finding-low { border-left-color:#2563eb; background:#eff6ff; }
  .finding-title { font-size:14px; font-weight:600; color:#1a1a2e; margin-bottom:6px; display:flex; align-items:center; gap:8px; }
  .finding-desc { font-size:13px; color:#374151; margin-bottom:8px; }
  .finding-example { font-size:12px; color:#6b7280; background:#f8fafc; border:1px solid #e2e8f0; border-radius:4px; padding:10px; }
  .finding-example strong { font-size:10px; text-transform:uppercase; letter-spacing:0.5px; color:#9ca3af; display:block; margin-bottom:4px; }
  .perm-tags { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:8px; }
  .perm-tag { font-family:'JetBrains Mono',monospace; font-size:11px; background:#e2e8f0; color:#374151; padding:2px 8px; border-radius:3px; }

  /* CSP */
  .csp-raw { font-family:'JetBrains Mono',monospace; font-size:12px; background:#1a1a2e; color:#a5f3fc; padding:12px 16px; border-radius:6px; margin-bottom:12px; word-break:break-all; line-height:1.8; }

  /* Code patterns */
  .pattern-group { margin-bottom:12px; }
  .pattern-group-title { font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:#6b7280; margin-bottom:8px; }
  .pattern-item { font-size:12px; color:#374151; padding:4px 0; display:flex; align-items:center; gap:8px; border-bottom:1px solid #f8fafc; }
  .pattern-file { font-family:'JetBrains Mono',monospace; font-size:11px; color:#6b7280; }

  /* Footer */
  .footer { border-top:2px solid #1a1a2e; padding-top:20px; margin-top:48px; display:flex; justify-content:space-between; font-size:11px; color:#9ca3af; }

  /* Print */
  @media print {
    body { font-size:12px; }
    .page { padding:20px; }
    .finding { page-break-inside:avoid; }
  }
</style>
</head>
<body>
<div class="page">

<!-- Cover -->
<div class="cover">
  <div class="cover-label">Security Analysis Report</div>
  <div class="cover-title">CRX Audit</div>
  <div class="cover-ext">${escapeHtml(metadata.extensionName || 'Unknown Extension')}</div>
  <div class="cover-meta">
    <span>Version ${escapeHtml(metadata.version || '—')}</span>
    <span>Manifest V${metadata.manifestVersion}</span>
    <span>${date}</span>
    <span>Overall: ${riskBadge(overallRisk)}</span>
  </div>
</div>

<!-- Executive Summary -->
<div class="summary">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat stat-critical"><div class="stat-value">${summary.criticalPermissions}</div><div class="stat-label">Critical Permissions</div></div>
    <div class="stat stat-high"><div class="stat-value">${summary.highPermissions}</div><div class="stat-label">High Permissions</div></div>
    <div class="stat stat-medium"><div class="stat-value">${summary.combinationsFound}</div><div class="stat-label">Dangerous Combos</div></div>
    <div class="stat stat-medium"><div class="stat-value">${summary.cspFindings}</div><div class="stat-label">CSP Issues</div></div>
    <div class="stat stat-low"><div class="stat-value">${summary.codePatterns}</div><div class="stat-label">Code Patterns</div></div>
    <div class="stat stat-none"><div class="stat-value">${summary.hostFindings}</div><div class="stat-label">Host Issues</div></div>
  </div>
</div>

<!-- 1. Permissions -->
<div class="section">
  <div class="section-header">
    <div class="section-num">1</div>
    <div class="section-title">Permissions (${permissions.length})</div>
  </div>
  <table>
    <thead><tr><th>Permission</th><th>Capability</th><th>Risk</th><th>Type</th></tr></thead>
    <tbody>
${permissions.map(p => `      <tr><td class="mono">${escapeHtml(p.name)}</td><td>${escapeHtml(p.description)}</td><td>${riskBadge(p.risk)}</td><td>${p.isOptional ? 'Optional' : 'Required'}</td></tr>`).join('\n')}
    </tbody>
  </table>
</div>

${combinations.length > 0 ? `
<!-- 2. Dangerous Combinations -->
<div class="section">
  <div class="section-header">
    <div class="section-num">2</div>
    <div class="section-title">Dangerous Combinations (${combinations.length})</div>
  </div>
${combinations.map(c => `  <div class="finding finding-${c.risk}">
    <div class="finding-title">${riskBadge(c.risk)} ${escapeHtml(c.title)}</div>
    <div class="perm-tags">${c.permissions.map(p => `<span class="perm-tag">${escapeHtml(p)}</span>`).join('')}</div>
    <div class="finding-desc">${escapeHtml(c.description)}</div>
    <div class="finding-example"><strong>Real-World Precedent</strong>${escapeHtml(c.realWorldExample)}</div>
  </div>`).join('\n')}
</div>
` : ''}

<!-- 3. Content Security Policy -->
<div class="section">
  <div class="section-header">
    <div class="section-num">3</div>
    <div class="section-title">Content Security Policy (${csp.findings.length} findings)</div>
  </div>
  <div class="csp-raw">${escapeHtml(csp.raw || "script-src 'self'; object-src 'self' (Chrome default)")}</div>
${csp.findings.map(f => `  <div class="finding finding-${f.risk}">
    <div class="finding-title">${riskBadge(f.risk)} ${escapeHtml(f.description)}</div>
    ${f.detail ? `<div class="finding-desc">${escapeHtml(f.detail)}</div>` : ''}
  </div>`).join('\n')}
</div>

${codePatterns.length > 0 ? `
<!-- 4. Code Patterns -->
<div class="section">
  <div class="section-header">
    <div class="section-num">4</div>
    <div class="section-title">Code Patterns (${codePatterns.length})</div>
  </div>
${['sink', 'source', 'network', 'obfuscation'].map(cat => {
  const items = codePatterns.filter(p => p.category === cat)
  if (items.length === 0) return ''
  const label: Record<string, string> = { sink: 'DOM Sinks', source: 'Data Sources', network: 'Network Activity', obfuscation: 'Obfuscation Signals' }
  return `  <div class="pattern-group">
    <div class="pattern-group-title">${label[cat] || cat} (${items.length})</div>
${items.slice(0, 15).map(p => `    <div class="pattern-item">${riskBadge(p.risk)} ${escapeHtml(p.description)} <span class="pattern-file">${escapeHtml(p.filePath.split('/').pop() || '')}:${p.lineNumber}</span></div>`).join('\n')}
${items.length > 15 ? `    <div class="pattern-item" style="color:#9ca3af;font-style:italic">... and ${items.length - 15} more</div>` : ''}
  </div>`
}).join('\n')}
</div>
` : ''}

${hostPermissions.length > 0 ? `
<!-- 5. Host Permissions -->
<div class="section">
  <div class="section-header">
    <div class="section-num">5</div>
    <div class="section-title">Host Permissions (${hostPermissions.length})</div>
  </div>
${hostPermissions.map(h => `  <div class="finding finding-${h.risk}">
    <div class="finding-title">${riskBadge(h.risk)} <span class="mono">${escapeHtml(h.pattern)}</span></div>
    <div class="finding-desc">${escapeHtml(h.description)}</div>
    ${h.suggestion ? `<div class="finding-desc" style="color:#059669;font-size:12px">${escapeHtml(h.suggestion)}</div>` : ''}
  </div>`).join('\n')}
</div>
` : ''}

<!-- 6. Manifest Version -->
<div class="section">
  <div class="section-header">
    <div class="section-num">6</div>
    <div class="section-title">Manifest Version Assessment</div>
  </div>
  <div class="finding finding-${manifestVersionAnalysis.risk}">
    <div class="finding-title">${riskBadge(manifestVersionAnalysis.risk)} Manifest V${manifestVersionAnalysis.manifestVersion}</div>
    <div class="finding-desc">${escapeHtml(manifestVersionAnalysis.description)}</div>
  </div>
</div>

<!-- Footer -->
<div class="footer">
  <span>Generated by CRX Audit — https://crx-audit.vercel.app</span>
  <span>Static analysis only. Does not execute extension code.</span>
</div>

</div>
</body>
</html>`
}

export function downloadReport(report: AnalysisReport) {
  const html = generateReport(report)
  const blob = new Blob([html], { type: 'text/html' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `crx-audit-${(report.metadata.extensionName || 'report').toLowerCase().replace(/\s+/g, '-')}-${new Date().toISOString().slice(0, 10)}.html`
  a.click()
  URL.revokeObjectURL(url)
}
