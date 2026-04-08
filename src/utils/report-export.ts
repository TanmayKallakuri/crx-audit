import type { AnalysisReport, RiskLevel } from '../types'

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function badge(risk: RiskLevel): string {
  const c: Record<RiskLevel, string> = {
    critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', none: '#6b7280',
  }
  return `<span class="badge" style="background:${c[risk]}15;color:${c[risk]};border:1px solid ${c[risk]}30">${risk.toUpperCase()}</span>`
}

function riskWord(risk: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: 'Critical', high: 'High', medium: 'Moderate', low: 'Low', none: 'Informational',
  }
  return map[risk]
}

export function generateReport(report: AnalysisReport): string {
  const { metadata, summary, permissions, combinations, csp, codePatterns, hostPermissions, manifestVersionAnalysis } = report
  const date = new Date(metadata.analyzedAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const time = new Date(metadata.analyzedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })

  const critCount = summary.criticalPermissions + combinations.filter(c => c.risk === 'critical').length
  const overallRisk: RiskLevel = critCount >= 3 ? 'critical' : critCount >= 1 ? 'high' : summary.combinationsFound > 0 ? 'medium' : 'low'
  const totalFindings = summary.criticalPermissions + summary.highPermissions + summary.combinationsFound + summary.cspFindings + summary.hostFindings

  const sinkPatterns = codePatterns.filter(p => p.category === 'sink')
  const sourcePatterns = codePatterns.filter(p => p.category === 'source')
  const networkPatterns = codePatterns.filter(p => p.category === 'network')
  const obfuscationPatterns = codePatterns.filter(p => p.category === 'obfuscation')

  let sectionNum = 0
  const section = (title: string) => `<div class="section-header"><span class="section-num">${++sectionNum}</span><h2>${title}</h2></div>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Analysis — ${esc(metadata.extensionName)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;color:#1e293b;background:#fff;font-size:13.5px;line-height:1.65}
.page{max-width:820px;margin:0 auto;padding:48px}

/* Cover */
.cover{padding:48px 0 36px;border-bottom:1px solid #e2e8f0;margin-bottom:36px}
.cover-org{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:3px;color:#94a3b8;margin-bottom:24px}
.cover-type{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;color:#64748b;margin-bottom:8px}
.cover-name{font-size:32px;font-weight:700;color:#0f172a;line-height:1.2;margin-bottom:24px}
.cover-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;font-size:12.5px;color:#475569;border:1px solid #e2e8f0;border-radius:6px;overflow:hidden}
.cover-grid dt{background:#f8fafc;padding:8px 14px;font-weight:600;color:#64748b;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #e2e8f0}
.cover-grid dd{padding:8px 14px;border-bottom:1px solid #e2e8f0}

/* Risk banner */
.risk-banner{display:flex;align-items:center;gap:12px;padding:14px 18px;border-radius:8px;margin-bottom:36px;font-size:13px;font-weight:500}
.risk-critical{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
.risk-high{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412}
.risk-medium{background:#fefce8;border:1px solid #fde68a;color:#854d0e}
.risk-low{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af}
.risk-dot{width:10px;height:10px;border-radius:50%}
.risk-critical .risk-dot{background:#dc2626}
.risk-high .risk-dot{background:#ea580c}
.risk-medium .risk-dot{background:#ca8a04}
.risk-low .risk-dot{background:#2563eb}

/* Summary boxes */
.summary-row{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:#e2e8f0;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden;margin-bottom:36px}
.sbox{background:#fff;padding:16px 8px;text-align:center}
.sbox-val{font-size:24px;font-weight:700;line-height:1}
.sbox-label{font-size:9.5px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#94a3b8;margin-top:6px}
.sbox-critical .sbox-val{color:#dc2626}
.sbox-high .sbox-val{color:#ea580c}
.sbox-amber .sbox-val{color:#d97706}
.sbox-blue .sbox-val{color:#2563eb}
.sbox-gray .sbox-val{color:#64748b}

/* Sections */
.section{margin-bottom:32px;page-break-inside:avoid}
.section-header{display:flex;align-items:center;gap:10px;border-bottom:2px solid #0f172a;padding-bottom:6px;margin-bottom:16px}
.section-num{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;color:#fff;background:#0f172a;min-width:22px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:4px}
h2{font-size:15px;font-weight:700;color:#0f172a}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-bottom:8px}
th{text-align:left;font-size:9.5px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#94a3b8;padding:6px 10px;border-bottom:2px solid #e2e8f0}
td{padding:7px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:hover td{background:#f8fafc}
.mono{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:500}

/* Badges */
.badge{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:600;letter-spacing:0.5px;font-family:'JetBrains Mono',monospace}

/* Findings */
.finding{border:1px solid #e2e8f0;border-radius:8px;padding:18px;margin-bottom:14px;page-break-inside:avoid}
.finding-critical{border-left:4px solid #dc2626}
.finding-high{border-left:4px solid #ea580c}
.finding-medium{border-left:4px solid #ca8a04}
.finding-low{border-left:4px solid #2563eb}
.finding-none{border-left:4px solid #94a3b8}
.finding-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.finding-title{font-size:14px;font-weight:600;color:#0f172a}
.finding-body{font-size:13px;color:#475569;line-height:1.7}
.finding-body p{margin-bottom:8px}
.finding-body p:last-child{margin-bottom:0}
.finding-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#94a3b8;margin-top:12px;margin-bottom:4px}
.finding-example{font-size:12px;color:#64748b;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;padding:10px 12px;line-height:1.6}
.tags{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px}
.tag{font-family:'JetBrains Mono',monospace;font-size:10.5px;background:#f1f5f9;color:#475569;padding:2px 7px;border-radius:3px;border:1px solid #e2e8f0}

/* CSP */
.csp-block{font-family:'JetBrains Mono',monospace;font-size:11.5px;background:#0f172a;color:#94a3b8;padding:14px 18px;border-radius:6px;margin-bottom:14px;word-break:break-all;line-height:1.9;white-space:pre-wrap}
.csp-block b{color:#f0abfc}

/* Code patterns */
.pattern-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #f8fafc;font-size:12px}
.pattern-row:last-child{border:none}
.pattern-desc{flex:1;color:#475569}
.pattern-file{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:#94a3b8}
.pattern-category{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#64748b;margin:14px 0 6px;padding-bottom:4px;border-bottom:1px solid #f1f5f9}

/* Methodology */
.method-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:8px}
.method-item{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 14px}
.method-item strong{display:block;font-size:12px;color:#0f172a;margin-bottom:3px}
.method-item span{font-size:11.5px;color:#64748b}

/* Footer */
.footer{border-top:1px solid #e2e8f0;padding-top:16px;margin-top:40px;font-size:10.5px;color:#94a3b8;display:flex;justify-content:space-between}
.disclaimer{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 14px;font-size:11px;color:#64748b;margin-top:20px;line-height:1.6}

@media print{
  body{font-size:11px}
  .page{padding:24px}
  .finding,.section{page-break-inside:avoid}
  .cover{page-break-after:always}
}
</style>
</head>
<body>
<div class="page">

<!-- Cover -->
<div class="cover">
  <div class="cover-org">CRX Audit</div>
  <div class="cover-type">Chrome Extension Security Analysis Report</div>
  <div class="cover-name">${esc(metadata.extensionName || 'Unknown Extension')}</div>
  <dl class="cover-grid">
    <dt>Extension Version</dt><dd>${esc(metadata.version || '—')}</dd>
    <dt>Manifest Version</dt><dd>V${metadata.manifestVersion}</dd>
    <dt>Analysis Date</dt><dd>${date} at ${time}</dd>
    <dt>Analysis Method</dt><dd>${metadata.inputMethod === 'id' ? 'Web Store download' : metadata.inputMethod === 'upload' ? 'CRX file upload' : 'Manifest review'}</dd>
    <dt>Overall Risk</dt><dd>${badge(overallRisk)} ${riskWord(overallRisk)}</dd>
    <dt>Total Findings</dt><dd>${totalFindings} actionable findings</dd>
  </dl>
</div>

<!-- Risk Banner -->
<div class="risk-banner risk-${overallRisk}">
  <div class="risk-dot"></div>
  <div>
    <strong>Overall Risk Assessment: ${riskWord(overallRisk)}</strong>
    — ${critCount >= 3
      ? 'This extension requests an unusually broad set of critical permissions with multiple dangerous combinations. A thorough manual review is strongly recommended before deployment.'
      : critCount >= 1
        ? 'This extension has critical-level permissions that grant broad access to user data. Review the specific combinations below to assess whether the access is justified by the extension\'s stated functionality.'
        : summary.combinationsFound > 0
          ? 'This extension has permission combinations that could be misused. Verify that the stated functionality justifies the access requested.'
          : 'No critical findings. The extension requests a reasonable permission scope for its stated functionality.'
    }
  </div>
</div>

<!-- Summary -->
<div class="summary-row">
  <div class="sbox sbox-critical"><div class="sbox-val">${summary.criticalPermissions}</div><div class="sbox-label">Critical</div></div>
  <div class="sbox sbox-high"><div class="sbox-val">${summary.highPermissions}</div><div class="sbox-label">High</div></div>
  <div class="sbox sbox-amber"><div class="sbox-val">${summary.combinationsFound}</div><div class="sbox-label">Combos</div></div>
  <div class="sbox sbox-amber"><div class="sbox-val">${summary.cspFindings}</div><div class="sbox-label">CSP</div></div>
  <div class="sbox sbox-blue"><div class="sbox-val">${summary.codePatterns}</div><div class="sbox-label">Code</div></div>
  <div class="sbox sbox-gray"><div class="sbox-val">${summary.hostFindings}</div><div class="sbox-label">Host</div></div>
</div>

<!-- Methodology -->
<div class="section">
  ${section('Methodology')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">This report was generated using automated static analysis. The extension package was extracted and analyzed without executing any code. The following analysis modules were applied:</p>
  <div class="method-grid">
    <div class="method-item"><strong>Permission Analysis</strong><span>Mapped ${permissions.length} permissions against Chrome's documented capability model and risk tiers.</span></div>
    <div class="method-item"><strong>Combination Detection</strong><span>Checked ${combinations.length > 0 ? combinations.length : 'all known'} dangerous permission combinations against documented attack vectors.</span></div>
    <div class="method-item"><strong>CSP Evaluation</strong><span>Parsed Content Security Policy directives and checked against ${csp.findings.length > 0 ? '14+' : 'known'} CSP bypass domains.</span></div>
    <div class="method-item"><strong>Code Pattern Scan</strong><span>Scanned ${report.metadata.inputMethod === 'paste' ? 'N/A (manifest only)' : `all JavaScript files for 40+ sink, source, network, and obfuscation patterns`}.</span></div>
    <div class="method-item"><strong>Host Permission Scope</strong><span>Evaluated host permission breadth and checked for access to sensitive domains.</span></div>
    <div class="method-item"><strong>Manifest Version</strong><span>Assessed security implications of the extension's manifest version.</span></div>
  </div>
</div>

<!-- Permissions -->
<div class="section">
  ${section('Permission Analysis')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">Each permission grants specific capabilities to the extension. Permissions are rated based on the sensitivity of data they expose and the actions they enable.</p>
  <table>
    <thead><tr><th style="width:160px">Permission</th><th>What This Grants</th><th style="width:80px">Risk</th><th style="width:70px">Type</th></tr></thead>
    <tbody>
${permissions.map(p => `      <tr><td class="mono">${esc(p.name)}</td><td>${esc(p.description)}</td><td>${badge(p.risk)}</td><td style="font-size:11px;color:#94a3b8">${p.isOptional ? 'Optional' : 'Required'}</td></tr>`).join('\n')}
    </tbody>
  </table>
</div>

${combinations.length > 0 ? `
<!-- Dangerous Combinations -->
<div class="section">
  ${section('Dangerous Permission Combinations')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">Individual permissions may be benign on their own but create compound risk when combined. The following combinations were detected in this extension's manifest.</p>
${combinations.map(c => `
  <div class="finding finding-${c.risk}">
    <div class="finding-head">
      <div class="finding-title">${esc(c.title)}</div>
      ${badge(c.risk)}
    </div>
    <div class="tags">${c.permissions.map(p => `<span class="tag">${esc(p)}</span>`).join('')}</div>
    <div class="finding-body">
      <p><strong>Impact:</strong> ${esc(c.description)}</p>
    </div>
    <div class="finding-label">Documented Precedent</div>
    <div class="finding-example">${esc(c.realWorldExample)}</div>
  </div>`).join('\n')}
</div>
` : ''}

<!-- CSP -->
<div class="section">
  ${section('Content Security Policy')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">${csp.isDefault
    ? 'This extension does not declare a custom CSP. Chrome enforces the default policy shown below.'
    : 'The extension declares the following Content Security Policy. Each directive controls what resources the extension pages can load.'
  }</p>
  <div class="csp-block">${esc(csp.raw || "script-src 'self'; object-src 'self'")}</div>
${csp.findings.length > 0 ? csp.findings.map(f => `
  <div class="finding finding-${f.risk}">
    <div class="finding-head">
      <div style="flex:1">
        <div class="finding-title" style="font-size:13px">${esc(f.description)}</div>
      </div>
      ${badge(f.risk)}
    </div>
    ${f.detail ? `<div class="finding-body"><p><strong>Impact:</strong> ${esc(f.detail)}</p></div>` : ''}
  </div>`).join('\n') : '<p style="font-size:13px;color:#16a34a">No CSP issues identified. The policy is appropriately restrictive.</p>'}
</div>

${codePatterns.length > 0 ? `
<!-- Code Patterns -->
<div class="section">
  ${section('Code Pattern Analysis')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">JavaScript files were scanned for patterns associated with security risks. A match does not indicate malicious intent — it indicates a pattern that warrants manual review in context.</p>
${[
  { items: sinkPatterns, title: 'DOM Sinks', desc: 'Functions that execute or inject content — potential XSS vectors if used with untrusted input.' },
  { items: sourcePatterns, title: 'Data Sources', desc: 'Entry points where attacker-controlled data can enter the extension.' },
  { items: networkPatterns, title: 'Network Activity', desc: 'External communication that could be used for data exfiltration or remote code loading.' },
  { items: obfuscationPatterns, title: 'Obfuscation Signals', desc: 'Patterns suggesting code may be intentionally obscured to evade review.' },
].filter(g => g.items.length > 0).map(g => `
    <div class="pattern-category">${g.title} (${g.items.length}) — <span style="font-weight:400;text-transform:none;letter-spacing:0;font-size:11px">${g.desc}</span></div>
${g.items.slice(0, 20).map(p => `    <div class="pattern-row">${badge(p.risk)} <span class="pattern-desc">${esc(p.description)}</span><span class="pattern-file">${esc(p.filePath.split('/').pop() || '')}:${p.lineNumber}</span></div>`).join('\n')}
${g.items.length > 20 ? `    <div class="pattern-row" style="color:#94a3b8;font-style:italic;justify-content:center">+ ${g.items.length - 20} additional matches</div>` : ''}`).join('\n')}
</div>
` : ''}

${hostPermissions.length > 0 ? `
<!-- Host Permissions -->
<div class="section">
  ${section('Host Permission Scope')}
  <p style="font-size:13px;color:#475569;margin-bottom:14px">Host permissions define which websites the extension can access. Overly broad patterns grant unnecessary access and increase risk if the extension is compromised.</p>
${hostPermissions.map(h => `
  <div class="finding finding-${h.risk}">
    <div class="finding-head">
      <div>
        <div class="finding-title"><span class="mono">${esc(h.pattern)}</span></div>
      </div>
      ${badge(h.risk)}
    </div>
    <div class="finding-body">
      <p><strong>Impact:</strong> ${esc(h.description)}</p>
      ${h.suggestion ? `<p style="color:#16a34a"><strong>Recommendation:</strong> ${esc(h.suggestion)}</p>` : ''}
    </div>
  </div>`).join('\n')}
</div>
` : ''}

<!-- Manifest Version -->
<div class="section">
  ${section('Manifest Version Assessment')}
  <div class="finding finding-${manifestVersionAnalysis.risk}">
    <div class="finding-head">
      <div class="finding-title">Manifest V${manifestVersionAnalysis.manifestVersion}</div>
      ${badge(manifestVersionAnalysis.risk)}
    </div>
    <div class="finding-body">
      <p><strong>Assessment:</strong> ${esc(manifestVersionAnalysis.description)}</p>
${manifestVersionAnalysis.details.length > 0 ? `      <ul style="margin:8px 0 0 18px;color:#64748b;font-size:12px">${manifestVersionAnalysis.details.map(d => `<li style="margin-bottom:3px">${esc(d)}</li>`).join('')}</ul>` : ''}
    </div>
  </div>
</div>

<!-- Disclaimer -->
<div class="disclaimer">
  <strong>Disclaimer:</strong> This report is generated by automated static analysis and does not constitute a complete security audit. Static analysis identifies capabilities and patterns but cannot determine intent. All findings should be verified through manual review. The extension's code was not executed during analysis.
</div>

<!-- Footer -->
<div class="footer">
  <span>Generated by CRX Audit — crx-audit.vercel.app</span>
  <span>${date}</span>
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
  a.download = `crx-audit-${(report.metadata.extensionName || 'report').toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${new Date().toISOString().slice(0, 10)}.html`
  a.click()
  URL.revokeObjectURL(url)
}
