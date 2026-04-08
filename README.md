# CRX Audit

A transparent, open-source Chrome extension security analyzer. Enter an extension ID, upload a `.crx` file, or paste a `manifest.json` — get a detailed security report covering permissions, dangerous combinations, CSP weaknesses, suspicious code patterns, and host permission scope.

All analysis runs client-side. No extension data leaves your browser.

## Why This Exists

[CRXcavator](https://crxcavator.io) by Duo Security — the most widely used free extension analyzer — shut down with no open-source replacement. The remaining tools are either enterprise SaaS with black-box scoring, closed-source, or abandoned.

CRX Audit fills that gap with:

- **Transparent analysis** — every finding explains *what* was found and *why* it matters. No opaque risk scores.
- **Dangerous combination detection** — flags permission pairs that create compound risk (e.g., `cookies` + `<all_urls>` = session hijacking capability). No other open-source tool does this.
- **Manifest V3 awareness** — understands `host_permissions`, `service_worker`, MV3 CSP format, and `declarativeNetRequest`. Flags MV2 deprecation.
- **CSP bypass detection** — checks against 14+ known CSP bypass domains with specific exploit explanations.
- **40+ code patterns** — detects dangerous sinks, attacker-controlled data sources, network exfiltration vectors, and obfuscation signals across all JS files.

## How It Works

```
Extension ID / .crx file / manifest.json
        │
        ▼
┌─────────────────────────┐
│   CRX Extraction        │  Parse CRX3 header, extract ZIP via JSZip
│   (client-side)         │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│   Manifest Parser       │  Extract permissions, host_permissions,
│                         │  content_scripts, CSP, background scripts,
│                         │  web_accessible_resources
└────────┬────────────────┘
         │
         ├──► Permission Analyzer ──► Individual risk assessment
         ├──► Combination Analyzer ──► Compound risk detection
         ├──► CSP Analyzer ──► Directive evaluation + bypass domains
         ├──► Code Scanner ──► Pattern matching across all JS files
         ├──► Host Analyzer ──► Broad access + sensitive domain flags
         └──► MV2/MV3 Assessment
                  │
                  ▼
         Security Report
```

## Analysis Modules

### Permission Analysis
Maps 50+ Chrome permissions to plain-English capabilities and risk tiers (Critical / High / Medium / Low / None). Distinguishes required vs. optional permissions and handles MV2/MV3 permission field differences.

### Dangerous Combinations
Detects 10+ permission combinations that create compound risk beyond individual permissions. Each combination includes:
- The specific attack it enables
- Why the combination is worse than its parts
- A documented real-world precedent

Examples: `cookies + <all_urls>` (session hijacking), `nativeMessaging + host permissions` (browser-to-OS bridge), `debugger + tabs` (full browser remote control).

### CSP Analysis
Parses Content Security Policy for both MV2 (string) and MV3 (object) formats. Checks for:
- `unsafe-eval` and `unsafe-inline` in script-src
- Known CSP bypass domains (ajax.googleapis.com, cdn.jsdelivr.net, etc.) with specific exploit techniques
- Missing directives that don't fall back to default-src
- Respects Chrome's default CSP — does not penalize extensions that rely on it

### Code Scanner
Scans all JavaScript files for 40+ patterns across four categories:
- **Sinks** — `eval()`, `innerHTML`, `document.write()`, dynamic script creation
- **Sources** — `onMessageExternal`, `postMessage` listeners, `window.name`
- **Network** — `fetch()`, `WebSocket`, `sendBeacon()`, `importScripts()`
- **Obfuscation** — hex-encoded strings, `String.fromCharCode` chains, JS obfuscator variable patterns

Each finding includes the file path, line number, surrounding code context, and whether the file is a content script, background script, or web-accessible resource.

### Host Permission Analysis
Flags overly broad host patterns (`<all_urls>`, `*://*/*`) and detects access to sensitive domains (banking, crypto, email, CI/CD platforms). Suggests `activeTab` as a least-privilege alternative where applicable.

## Quick Start

```bash
git clone https://github.com/TanmayKallakuri/crx-audit.git
cd crx-audit
npm install
npm run dev
```

Open `http://localhost:5173` and paste a manifest or upload a `.crx` file.

### Extension ID Lookup (Optional)

To scan extensions by ID, deploy the CORS proxy:

```bash
cd proxy
npx wrangler deploy
```

Then set the proxy URL:

```bash
# .env
VITE_PROXY_URL=https://crx-audit-proxy.<your-subdomain>.workers.dev
```

The proxy is 55 lines of code. It validates extension IDs (`^[a-p]{32}$`), forwards to Google's CRX endpoint, and adds CORS headers. It is not an open proxy.

## Testing

```bash
npm test
```

63 tests across 5 test files:
- **Unit tests** — CSP analyzer, code scanner, host permission analyzer, permission/combination analysis
- **E2E** — Full analysis pipeline with real uBlock Origin CRX (4.3MB, 776 files)

## Tech Stack

- TypeScript, React 18, Vite
- Tailwind CSS v4
- JSZip (client-side extraction)
- Vitest (testing)
- Cloudflare Workers (optional CORS proxy)

## What This Does NOT Do

- **No malware verdicts.** Static analysis identifies capabilities and patterns, not intent. A finding means "this warrants review," not "this is malicious."
- **No magic risk scores.** Scores without defensible methodology are security theater. The report shows what the extension *can* do.
- **No dynamic analysis.** The extension is never executed. Code patterns are identified statically.
- **No data collection.** All analysis runs in your browser. Nothing is sent to any server (except the optional proxy, which only forwards CRX downloads).

## License

MIT
