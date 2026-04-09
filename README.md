# CRX Audit

An open-source Chrome extension security analyzer. Paste a Chrome Web Store URL, upload a `.crx` file, or paste a `manifest.json` — get a transparent security report with downloadable audit document.

All analysis runs client-side. No extension data leaves your browser.

**Live:** [crx-audit.vercel.app](https://crx-audit.vercel.app)

---

## Why — The Problem

Chrome extensions operate with significant trust. A single extension can read every page you visit, access your cookies, intercept your network traffic, and communicate with external servers. Chrome's Web Store review process catches some threats, but it has real limitations:

- **Reviews are a gatekeeping snapshot** — users never see the analysis. They either trust the extension or don't, with almost no information to make that decision.
- **Post-review changes slip through** — extensions can change behavior via server-side config flags, time-delayed activation, or supply chain compromise of the developer account.
- **Permission dialogs are meaningless to most users** — "This extension can read and change all your data on all websites" is technically accurate but tells a user nothing actionable.
- **CRXcavator is gone** — The most widely used free analyzer (by Duo Security/Cisco) shut down with no open-source replacement. What remains is either enterprise SaaS with black-box scoring (Spin.AI, Secure Annex), closed-source (CRXplorer), or abandoned (Tarnish, ExtAnalysis).

There is no user-facing or developer-facing tool to independently audit what a Chrome extension can actually do. CRX Audit fills that gap.

## What — The Tool

CRX Audit is a static analysis tool that takes any Chrome extension and produces a transparent security report answering one question: **"What can this extension actually do, and what should I be concerned about?"**

It analyzes six dimensions:

| Module | What It Checks | Why It Matters |
|---|---|---|
| **Permission Analysis** | Maps 50+ Chrome permissions to plain-English capabilities across 5 risk tiers | Translates opaque permission names into concrete actions the extension can take |
| **Combination Detection** | Flags 10+ dangerous multi-permission patterns with documented real-world precedents | Individual permissions may be benign; certain combinations create compound attack capabilities that are worse than the sum of their parts |
| **CSP Evaluation** | Parses Content Security Policy, checks 14+ known bypass domains with exploit techniques | A weak CSP can allow injected scripts to execute even when the extension code itself is clean |
| **Code Scanner** | Scans all JS files for 40+ patterns across sinks, sources, network, and obfuscation categories | Detects code constructs associated with data exfiltration, remote code loading, keylogging, and evasion techniques |
| **Host Scope Analysis** | Flags overly broad host patterns and access to sensitive domains (banking, crypto, email, CI/CD) | Broad host permissions mean the extension can read and modify content on sites where compromise would be most damaging |
| **Manifest Version** | Assesses MV2 vs MV3 security implications | MV2 extensions have weaker security defaults — remote code execution, persistent background pages, synchronous request blocking |

### What makes this different from existing tools

- **Transparent analysis** — every finding explains *what* was found, *why* it matters, and includes documented real-world precedent. No opaque risk scores or black-box AI verdicts.
- **Dangerous combination detection** — no other open-source tool flags permission combinations. `cookies` alone is moderate risk; `cookies + <all_urls>` is session hijacking capability across every site. That distinction matters.
- **Manifest V3 awareness** — understands `host_permissions`, `service_worker`, MV3 CSP object format, `declarativeNetRequest`, and `optional_host_permissions`. Correctly handles MV2/MV3 differences rather than treating them the same.
- **Downloadable audit report** — generates a professional security analysis document (HTML, print to PDF) with cover page, risk assessment, methodology, numbered findings, and disclaimer. Suitable for sharing with security teams or attaching to compliance documentation.
- **Client-side only** — the extension package is extracted and analyzed entirely in the browser. No data is sent to any server. The optional CORS proxy only forwards CRX download requests — it never sees the analysis.

## How — Architecture

```
Chrome Web Store URL / .crx upload / manifest.json paste
        │
        ▼
┌───────────────────────────┐
│   CRX Extraction          │  CRX3 header parsing → ZIP extraction via JSZip
│   (runs in browser)       │  Resolves __MSG_*__ i18n strings from _locales/
└──────────┬────────────────┘
           │
           ▼
┌───────────────────────────┐
│   Manifest Parser         │  Extracts permissions, host_permissions,
│                           │  content_scripts, CSP, background config,
│                           │  web_accessible_resources, externally_connectable
└──────────┬────────────────┘
           │
           ├──► Permission Analyzer ──► Risk tier mapping for each permission
           ├──► Combination Analyzer ──► Cross-reference against known attack patterns
           ├──► CSP Analyzer ──► Directive parsing + bypass domain detection
           ├──► Code Scanner ──► Regex pattern matching across all JS files
           ├──► Host Analyzer ──► Breadth assessment + sensitive domain matching
           └──► MV2/MV3 Assessment ──► Security model comparison
                    │
                    ▼
           ┌────────────────┐
           │ Security Report │──► Web UI (interactive)
           │                 │──► HTML Export (printable audit document)
           └────────────────┘
```

### CRX Download Flow (Extension ID input)

Browsers cannot directly download CRX files from Google due to CORS restrictions. A lightweight Cloudflare Worker proxy (55 lines) sits between the app and Google:

```
Browser  ──fetch──►  Cloudflare Worker  ──fetch──►  clients2.google.com
                     validates ID (^[a-p]{32}$)      returns .crx
                     adds CORS headers
                     NOT an open proxy
```

The proxy only accepts valid 32-character extension IDs and only forwards to one hardcoded Google endpoint. It cannot be used to fetch arbitrary URLs.

## Quick Start

```bash
git clone https://github.com/TanmayKallakuri/crx-audit.git
cd crx-audit
npm install
npm run dev
```

Open `http://localhost:5173`, paste a Chrome Web Store URL, and scan.

### Enable Extension ID Lookup

To scan extensions by URL/ID (not just file upload), deploy the CORS proxy:

```bash
cd proxy
npx wrangler login
npx wrangler deploy
```

Then create a `.env` file:

```
VITE_PROXY_URL=https://crx-audit-proxy.<your-subdomain>.workers.dev
```

## Testing

```bash
npm test
```

63 tests across 5 test files:
- **Unit tests** — CSP analyzer, code scanner, host permission analyzer, permission/combination analysis
- **E2E** — Full analysis pipeline against real uBlock Origin CRX (4.3MB, 776 files, 10 permissions, 113 code patterns)

## Tech Stack

- TypeScript, React 18, Vite
- Tailwind CSS v4
- JSZip (client-side CRX extraction)
- Vitest (testing)
- Cloudflare Workers (optional CORS proxy)

## Honest Limitations

This tool has clear boundaries, and understanding them is as important as understanding its capabilities:

- **No malware verdicts.** Static analysis identifies capabilities and patterns, not intent. A finding means "this warrants review," not "this is malicious." A password manager legitimately needs broad permissions — the same permissions a malicious extension would abuse.
- **No magic risk scores.** Numeric scores without defensible methodology are security theater. The report shows what the extension *can* do and explains why specific combinations are concerning. The user decides what's acceptable.
- **No dynamic analysis.** The extension is never executed. Code patterns are identified statically. Time-delayed behavior, server-side gating, and runtime-generated code are invisible to static analysis.
- **No data collection.** All analysis runs in the browser. Nothing is sent to any server except the optional CORS proxy, which only forwards CRX download requests and logs nothing.

## License

MIT
