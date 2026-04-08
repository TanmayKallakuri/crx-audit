import type { AnalysisReport, RiskLevel } from '../types'

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function badge(risk: RiskLevel): string {
  const c: Record<RiskLevel, [string, string]> = {
    critical: ['#dc2626', '#fef2f2'], high: ['#ea580c', '#fff7ed'],
    medium: ['#ca8a04', '#fefce8'], low: ['#2563eb', '#eff6ff'], none: ['#64748b', '#f8fafc'],
  }
  const [fg, bg] = c[risk]
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:0.6px;font-family:'JetBrains Mono',monospace;color:${fg};background:${bg};border:1px solid ${fg}20">${risk.toUpperCase()}</span>`
}

function riskWord(risk: RiskLevel): string {
  return { critical: 'Critical', high: 'High', medium: 'Moderate', low: 'Low', none: 'Informational' }[risk]
}

function riskColor(risk: RiskLevel): string {
  return { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', none: '#64748b' }[risk]
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

  // Risk meter segments
  const maxSeg = Math.max(summary.criticalPermissions + summary.highPermissions + summary.combinationsFound, 1)
  const critPct = Math.round((summary.criticalPermissions / maxSeg) * 100)
  const highPct = Math.round((summary.highPermissions / maxSeg) * 100)
  const comboPct = Math.round((summary.combinationsFound / maxSeg) * 100)
  const safePct = Math.max(0, 100 - critPct - highPct - comboPct)

  let sn = 0
  const sec = (t: string) => `<div class="sh"><div class="sn">${String(++sn).padStart(2, '0')}</div><h2>${t}</h2></div>`

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Analysis — ${esc(metadata.extensionName)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{--serif:'Instrument Serif',Georgia,serif;--sans:'Plus Jakarta Sans',system-ui,sans-serif;--mono:'JetBrains Mono',monospace;--ink:#0c0c0f;--dim:#64748b;--faint:#94a3b8;--line:#e2e8f0;--wash:#f8fafc;--bg:#ffffff}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--sans);color:var(--ink);background:var(--bg);font-size:13.5px;line-height:1.7}
.page{max-width:800px;margin:0 auto;padding:56px 48px}

/* ── Cover ── */
.cover{padding:0 0 44px;margin-bottom:44px;position:relative}
.cover::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,var(--ink) 40%,transparent)}
.cover-eyebrow{font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:3px;text-transform:uppercase;color:var(--faint);margin-bottom:32px;display:flex;align-items:center;gap:10px}
.cover-eyebrow::before{content:'';width:24px;height:1px;background:var(--faint)}
.cover-title{font-family:var(--serif);font-size:44px;font-weight:400;color:var(--ink);line-height:1.1;margin-bottom:8px;letter-spacing:-0.5px}
.cover-subtitle{font-family:var(--serif);font-size:22px;font-weight:400;color:var(--dim);font-style:italic;margin-bottom:32px}
.cover-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.cm{padding:14px 16px;border-right:1px solid var(--line)}
.cm:nth-child(3n){border-right:none}
.cm:nth-child(n+4){border-top:1px solid var(--line)}
.cm-label{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--faint);margin-bottom:3px}
.cm-value{font-size:13px;font-weight:600;color:var(--ink)}

/* ── Risk meter ── */
.risk-section{margin-bottom:40px}
.risk-bar{height:8px;border-radius:4px;display:flex;overflow:hidden;margin-bottom:14px;background:var(--wash);border:1px solid var(--line)}
.risk-bar div{height:100%;transition:width 0.3s}
.risk-statement{font-size:14px;color:#334155;line-height:1.75;padding:18px 20px;border-radius:8px;border-left:4px solid ${riskColor(overallRisk)};background:${riskColor(overallRisk)}08}
.risk-statement strong{color:var(--ink)}

/* ── Summary ── */
.sum{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin-bottom:44px}
.s{background:var(--bg);padding:18px 8px;text-align:center}
.sv{font-family:var(--mono);font-size:26px;font-weight:700;line-height:1}
.sl{font-family:var(--mono);font-size:8.5px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--faint);margin-top:6px}

/* ── Sections ── */
.section{margin-bottom:36px;page-break-inside:avoid}
.sh{display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.sn{font-family:var(--mono);font-size:11px;font-weight:600;color:var(--bg);background:var(--ink);width:26px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:6px}
h2{font-family:var(--sans);font-size:16px;font-weight:700;color:var(--ink);letter-spacing:-0.2px}
.section-intro{font-size:13.5px;color:var(--dim);margin-bottom:16px;line-height:1.7}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--faint);padding:8px 10px;border-bottom:2px solid var(--ink)}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.mono{font-family:var(--mono);font-size:12px;font-weight:500}

/* ── Findings ── */
.f{border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:14px;page-break-inside:avoid;position:relative;overflow:hidden}
.f::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px}
.f-critical::before{background:#dc2626}.f-high::before{background:#ea580c}.f-medium::before{background:#ca8a04}.f-low::before{background:#2563eb}.f-none::before{background:#94a3b8}
.f-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.f-title{font-size:15px;font-weight:700;color:var(--ink);letter-spacing:-0.2px}
.f-body{font-size:13px;color:#475569;line-height:1.75}
.f-body p{margin-bottom:8px}
.f-body p:last-child{margin-bottom:0}
.f-label{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--faint);margin-top:14px;margin-bottom:6px}
.f-quote{font-size:12px;color:var(--dim);background:var(--wash);border-left:3px solid var(--line);padding:10px 14px;border-radius:0 4px 4px 0;line-height:1.65}
.tags{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:10px}
.tag{font-family:var(--mono);font-size:10.5px;background:var(--wash);color:#475569;padding:2px 8px;border-radius:3px;border:1px solid var(--line)}

/* ── CSP ── */
.csp{font-family:var(--mono);font-size:11.5px;background:#0c0c0f;color:#a5b4c4;padding:16px 20px;border-radius:8px;margin-bottom:16px;word-break:break-all;line-height:2;white-space:pre-wrap}

/* ── Code ── */
.pat{display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:12px}
.pat:last-child{border:none}
.pat-d{flex:1;color:#475569}
.pat-f{font-family:var(--mono);font-size:10.5px;color:var(--faint)}
.pcat{font-family:var(--mono);font-size:9px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--dim);margin:18px 0 8px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.pcat-desc{font-size:11px;color:var(--faint);font-family:var(--sans);letter-spacing:0;text-transform:none;font-weight:400;margin-left:8px}

/* ── Methodology ── */
.mgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.mbox{background:var(--wash);border:1px solid var(--line);border-radius:6px;padding:14px 16px}
.mbox strong{display:block;font-size:12px;color:var(--ink);margin-bottom:2px}
.mbox span{font-size:11.5px;color:var(--dim);line-height:1.5}

/* ── Footer ── */
.disc{background:var(--wash);border:1px solid var(--line);border-radius:8px;padding:14px 18px;font-size:11.5px;color:var(--dim);line-height:1.6;margin-top:28px}
.foot{border-top:1px solid var(--line);padding-top:14px;margin-top:32px;font-family:var(--mono);font-size:10px;color:var(--faint);display:flex;justify-content:space-between;letter-spacing:0.3px}

@media print{
  body{font-size:11px}
  .page{padding:20px}
  .cover{page-break-after:always}
  .f,.section{page-break-inside:avoid}
}
</style>
</head>
<body>
<div class="page">

<!-- COVER -->
<div class="cover">
  <div class="cover-eyebrow">Security Analysis Report</div>
  <div class="cover-title">${esc(metadata.extensionName || 'Unknown Extension')}</div>
  <div class="cover-subtitle">Chrome Extension Security Analysis</div>
  <div class="cover-meta">
    <div class="cm"><div class="cm-label">Version</div><div class="cm-value">${esc(metadata.version || '—')}</div></div>
    <div class="cm"><div class="cm-label">Manifest</div><div class="cm-value">V${metadata.manifestVersion}</div></div>
    <div class="cm"><div class="cm-label">Overall Risk</div><div class="cm-value">${badge(overallRisk)}</div></div>
    <div class="cm"><div class="cm-label">Analyzed</div><div class="cm-value">${date}</div></div>
    <div class="cm"><div class="cm-label">Method</div><div class="cm-value">${metadata.inputMethod === 'id' ? 'Web Store' : metadata.inputMethod === 'upload' ? 'CRX Upload' : 'Manifest'}</div></div>
    <div class="cm"><div class="cm-label">Findings</div><div class="cm-value">${totalFindings} actionable</div></div>
  </div>
</div>

<!-- RISK -->
<div class="risk-section">
  <div class="risk-bar">
    ${critPct > 0 ? `<div style="width:${critPct}%;background:#dc2626"></div>` : ''}
    ${highPct > 0 ? `<div style="width:${highPct}%;background:#ea580c"></div>` : ''}
    ${comboPct > 0 ? `<div style="width:${comboPct}%;background:#eab308"></div>` : ''}
    <div style="width:${safePct}%;background:#e2e8f0"></div>
  </div>
  <div class="risk-statement">
    <strong>Overall Risk: ${riskWord(overallRisk)}.</strong>
    ${critCount >= 3
      ? ' This extension requests an unusually broad set of critical permissions with multiple dangerous combinations. These permissions, taken together, would allow the extension to read and modify virtually all browsing data, intercept network traffic, and communicate with external systems. A thorough manual review is strongly recommended before deployment in any environment.'
      : critCount >= 1
        ? ' This extension holds critical-level permissions that grant broad access to user data and browsing activity. While these may be justified by the extension\'s stated functionality, the specific permission combinations identified below should be reviewed to confirm they are necessary and appropriately scoped.'
        : summary.combinationsFound > 0
          ? ' This extension has permission combinations that could be leveraged if the extension were compromised or acting maliciously. The stated functionality should be reviewed against the access requested to confirm proportionality.'
          : ' This extension requests a reasonable permission scope for its stated functionality. No critical-severity findings were identified. Standard deployment practices are sufficient.'
    }
  </div>
</div>

<!-- SUMMARY -->
<div class="sum">
  <div class="s"><div class="sv" style="color:#dc2626">${summary.criticalPermissions}</div><div class="sl">Critical</div></div>
  <div class="s"><div class="sv" style="color:#ea580c">${summary.highPermissions}</div><div class="sl">High</div></div>
  <div class="s"><div class="sv" style="color:#d97706">${summary.combinationsFound}</div><div class="sl">Combos</div></div>
  <div class="s"><div class="sv" style="color:#ca8a04">${summary.cspFindings}</div><div class="sl">CSP</div></div>
  <div class="s"><div class="sv" style="color:#2563eb">${summary.codePatterns}</div><div class="sl">Code</div></div>
  <div class="s"><div class="sv" style="color:#64748b">${summary.hostFindings}</div><div class="sl">Host</div></div>
</div>

<!-- METHODOLOGY -->
<div class="section">
  ${sec('Methodology')}
  <p class="section-intro">This report was produced through automated static analysis of the extension package. No code was executed during the assessment. The following modules were applied:</p>
  <div class="mgrid">
    <div class="mbox"><strong>Permission Analysis</strong><span>${permissions.length} permissions mapped against Chrome's documented capability model across 5 risk tiers.</span></div>
    <div class="mbox"><strong>Combination Detection</strong><span>Cross-referenced permissions against ${combinations.length > 0 ? combinations.length : '10+'} known dangerous multi-permission attack patterns.</span></div>
    <div class="mbox"><strong>CSP Evaluation</strong><span>Parsed Content Security Policy directives. Checked against 14+ known CSP bypass domains with documented exploit techniques.</span></div>
    <div class="mbox"><strong>Code Pattern Scan</strong><span>${metadata.inputMethod === 'paste' ? 'Not available — manifest-only analysis.' : 'All JavaScript files scanned for 40+ patterns across sinks, sources, network, and obfuscation categories.'}</span></div>
    <div class="mbox"><strong>Host Scope Analysis</strong><span>Evaluated host permission breadth and cross-referenced against sensitive domain categories (banking, crypto, email, CI/CD).</span></div>
    <div class="mbox"><strong>Manifest Assessment</strong><span>Evaluated manifest version security implications and MV2 deprecation status.</span></div>
  </div>
</div>

<!-- PERMISSIONS -->
<div class="section">
  ${sec('Permission Analysis')}
  <p class="section-intro">Each Chrome extension permission grants specific capabilities. The table below maps every declared permission to its actual capability and assessed risk level. Permissions rated Critical or High warrant particular scrutiny.</p>
  <table>
    <thead><tr><th style="width:155px">Permission</th><th>Capability Granted</th><th style="width:75px">Risk</th><th style="width:65px">Type</th></tr></thead>
    <tbody>
${[...permissions].sort((a, b) => ['critical','high','medium','low','none'].indexOf(a.risk) - ['critical','high','medium','low','none'].indexOf(b.risk)).map(p =>
  `      <tr><td class="mono">${esc(p.name)}</td><td>${esc(p.description)}</td><td>${badge(p.risk)}</td><td style="font-size:11px;color:var(--faint)">${p.isOptional ? 'Optional' : 'Required'}</td></tr>`
).join('\n')}
    </tbody>
  </table>
</div>

${combinations.length > 0 ? `
<!-- COMBINATIONS -->
<div class="section">
  ${sec('Dangerous Permission Combinations')}
  <p class="section-intro">Individual permissions may be low-risk in isolation but create compound threats when held together. Each combination below describes a specific attack scenario enabled by the extension's current permission set, supported by documented real-world precedent.</p>
${combinations.map(c => `
  <div class="f f-${c.risk}">
    <div class="f-head">
      <div class="f-title">${esc(c.title)}</div>
      ${badge(c.risk)}
    </div>
    <div class="tags">${c.permissions.map(p => `<span class="tag">${esc(p)}</span>`).join('')}</div>
    <div class="f-body">
      <p><strong>Impact:</strong> ${esc(c.description)}</p>
    </div>
    <div class="f-label">Documented Precedent</div>
    <div class="f-quote">${esc(c.realWorldExample)}</div>
  </div>`).join('\n')}
</div>
` : ''}

<!-- CSP -->
<div class="section">
  ${sec('Content Security Policy Analysis')}
  <p class="section-intro">${csp.isDefault
    ? 'This extension does not declare a custom Content Security Policy. Chrome enforces the default policy shown below, which restricts script and object sources to the extension itself.'
    : 'The extension declares a custom Content Security Policy. Each directive controls which external resources the extension\'s pages may load. Weaknesses in CSP can allow injected scripts to execute or data to be exfiltrated.'
  }</p>
  <div class="csp">${esc(csp.raw || "script-src 'self'; object-src 'self'")}</div>
${csp.findings.length > 0 ? csp.findings.map(f => `
  <div class="f f-${f.risk}">
    <div class="f-head">
      <div style="flex:1"><div class="f-title" style="font-size:13.5px">${esc(f.description)}</div></div>
      ${badge(f.risk)}
    </div>
    ${f.detail ? `<div class="f-body"><p><strong>Impact:</strong> ${esc(f.detail)}</p></div>` : ''}
  </div>`).join('\n') : `<p style="font-size:13px;color:#16a34a;margin-top:4px">No CSP weaknesses identified. The policy appropriately restricts resource loading.</p>`}
</div>

${codePatterns.length > 0 ? `
<!-- CODE PATTERNS -->
<div class="section">
  ${sec('Code Pattern Analysis')}
  <p class="section-intro">All JavaScript files in the extension package were scanned for patterns associated with known security risks. A pattern match indicates code that warrants manual review — it does not indicate malicious behavior. Context determines whether a pattern represents a genuine risk.</p>
${[
  { items: sinkPatterns, title: 'DOM Sinks', desc: 'Functions that execute or inject content. Potential XSS vectors when used with untrusted input.' },
  { items: sourcePatterns, title: 'Attacker-Controlled Sources', desc: 'Entry points where external data enters the extension context.' },
  { items: networkPatterns, title: 'Network Activity', desc: 'External communication channels that could facilitate data exfiltration or remote code loading.' },
  { items: obfuscationPatterns, title: 'Obfuscation Signals', desc: 'Patterns suggesting code may be intentionally obscured to evade static review.' },
].filter(g => g.items.length > 0).map(g => `
  <div class="pcat">${g.title} &nbsp;(${g.items.length})<span class="pcat-desc">${g.desc}</span></div>
${g.items.slice(0, 20).map(p => `  <div class="pat">${badge(p.risk)}<span class="pat-d">${esc(p.description)}</span><span class="pat-f">${esc(p.filePath.split('/').pop() || '')}:${p.lineNumber}</span></div>`).join('\n')}
${g.items.length > 20 ? `  <div class="pat" style="color:var(--faint);font-style:italic;justify-content:center">+ ${g.items.length - 20} additional matches omitted for brevity</div>` : ''}`).join('\n')}
</div>
` : ''}

${hostPermissions.length > 0 ? `
<!-- HOST PERMISSIONS -->
<div class="section">
  ${sec('Host Permission Scope')}
  <p class="section-intro">Host permissions define which websites the extension can read and modify. Broad patterns like <code style="font-family:var(--mono);font-size:12px;background:var(--wash);padding:1px 5px;border-radius:3px">&lt;all_urls&gt;</code> grant access to every site the user visits, including banking, email, and authentication pages.</p>
${hostPermissions.map(h => `
  <div class="f f-${h.risk}">
    <div class="f-head">
      <div><div class="f-title"><span class="mono">${esc(h.pattern)}</span></div></div>
      ${badge(h.risk)}
    </div>
    <div class="f-body">
      <p><strong>Impact:</strong> ${esc(h.description)}</p>
      ${h.suggestion ? `<p style="color:#16a34a"><strong>Recommendation:</strong> ${esc(h.suggestion)}</p>` : ''}
    </div>
  </div>`).join('\n')}
</div>
` : ''}

<!-- MANIFEST VERSION -->
<div class="section">
  ${sec('Manifest Version Assessment')}
  <div class="f f-${manifestVersionAnalysis.risk}">
    <div class="f-head">
      <div class="f-title">Manifest V${manifestVersionAnalysis.manifestVersion}</div>
      ${badge(manifestVersionAnalysis.risk)}
    </div>
    <div class="f-body">
      <p><strong>Assessment:</strong> ${esc(manifestVersionAnalysis.description)}</p>
${manifestVersionAnalysis.details.length > 0 ? `      <ul style="margin:10px 0 0 18px;color:var(--dim);font-size:12.5px;line-height:1.7">${manifestVersionAnalysis.details.map(d => `<li style="margin-bottom:2px">${esc(d)}</li>`).join('')}</ul>` : ''}
    </div>
  </div>
</div>

<!-- DISCLAIMER -->
<div class="disc">
  <strong>Disclaimer.</strong> This report was generated through automated static analysis and does not constitute a comprehensive security audit. Static analysis identifies capabilities and code patterns but cannot determine developer intent or runtime behavior. All findings should be verified through manual code review before making deployment decisions. The extension's code was not executed at any point during this analysis.
</div>

<!-- FOOTER -->
<div class="foot">
  <span>Generated by CRX Audit &middot; crx-audit.vercel.app</span>
  <span>${date} at ${time}</span>
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
