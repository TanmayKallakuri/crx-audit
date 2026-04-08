# CRX Audit — Chrome Extension Security Analyzer

**Date:** 2026-04-08
**Author:** Tanmay Kallakuri
**Purpose:** Portfolio project for Google Chrome Trust & Safety interview (April 13)

---

## Overview

An open-source, web-based Chrome extension security analyzer that takes an extension ID or uploaded CRX/ZIP file and produces a transparent, explainable security report. All analysis runs client-side in the browser — no data leaves the user's machine.

**What it is:** A tool that answers "What can this extension actually do, and what should I be concerned about?"

**What it is NOT:** A malware detector. It identifies capabilities and patterns that warrant review, not verdicts.

### Why This Exists

CRXcavator (Duo/Cisco) — the most widely used free extension analyzer — shut down with no open-source replacement. Remaining tools are either enterprise SaaS (Spin.AI, Secure Annex), closed-source (CRXplorer), or abandoned/broken (Tarnish, ExtAnalysis). No existing tool is:
- Open-source and self-hostable
- Manifest V3-aware
- Transparent in its analysis (no black-box scoring)
- Focused on dangerous permission *combinations*, not just individual permissions

---

## Tech Stack

- **Language:** TypeScript
- **Framework:** React 18 + Vite
- **Styling:** Tailwind CSS
- **ZIP Extraction:** JSZip (client-side)
- **Testing:** Vitest + React Testing Library
- **CRX Proxy:** Cloudflare Worker (optional, ~20 lines)
- **Deployment:** Vercel or GitHub Pages (static site)

---

## Input Methods

1. **Extension ID** — User pastes a Chrome Web Store extension ID (32 chars) or full URL. The app fetches the CRX via a lightweight CORS proxy (Cloudflare Worker) that forwards requests to `clients2.google.com/service/update2/crx`.

2. **File Upload** — User uploads a .crx or .zip file directly. Works for sideloaded extensions, enterprise extensions, and as a fallback if the proxy is unavailable.

3. **Manifest Paste** — User pastes raw manifest.json for quick permission-only analysis (no code scanning).

---

## Analysis Modules

### 1. Manifest Parser

Parses `manifest.json` and extracts all security-relevant fields:
- `manifest_version` (2 vs 3)
- `permissions`, `optional_permissions`
- `host_permissions`, `optional_host_permissions` (MV3)
- `content_scripts[].matches` — what pages content scripts run on
- `content_security_policy` — string (MV2) or object (MV3)
- `background.scripts` / `background.service_worker`
- `web_accessible_resources` — flat array (MV2) or array of objects (MV3)
- `externally_connectable`

### 2. Permission Analyzer

**Individual permissions:** Maps every Chrome permission to:
- **What it does** — plain English capability description
- **Risk tier** — NONE / LOW / MEDIUM / HIGH / CRITICAL
- Derived from Chrome's official documentation, not opinions

**Risk tier criteria (defensible):**
- CRITICAL: Can access all browsing data, intercept all traffic, or bridge to OS (`<all_urls>`, `debugger`, `cookies` with broad hosts, `nativeMessaging`, `webRequestBlocking`)
- HIGH: Can access sensitive user data or modify security settings (`history`, `tabs`, `clipboardRead`, `privacy`, `proxy`, `contentSettings`)
- MEDIUM: Can access moderate user data or system info (`bookmarks`, `geolocation`, `downloads`, `management`, `webNavigation`)
- LOW: Limited capability, minimal user data exposure (`activeTab`, `alarms`, `storage`, `contextMenus`, `notifications`)
- NONE: No meaningful security implication (`idle`, `power`, `tts`)

**Permission combinations (the differentiator):** Flags specific multi-permission combinations that create compound risk:

| Combination | Risk | Explanation |
|---|---|---|
| `cookies` + `<all_urls>` | Session hijacking | Can read session cookies for every site |
| `nativeMessaging` + host permissions | Browser-to-OS bridge | Can exfiltrate browsing data to a native process with full OS access |
| `debugger` + `<all_urls>` | Full tab control | Chrome DevTools Protocol access to any tab — read traffic, execute JS, screenshot |
| `webRequestBlocking` + `<all_urls>` (MV2) | MITM capability | Can intercept, read, and modify all HTTP requests including POST bodies |
| `tabs` + `history` + `cookies` | Complete surveillance | Full browsing history + open tabs + session cookies |
| `management` + any | Security tool bypass | Can disable other extensions including ad blockers and security tools |
| `proxy` + `cookies` | Traffic routing + theft | Route traffic through attacker proxy AND steal cookies directly |
| `scripting` + `<all_urls>` | Universal XSS | Can inject arbitrary JavaScript into any page |
| `downloads` + `downloads.open` | Malware delivery | Can download and auto-open executable files |
| `clipboardRead` + host permissions | Clipboard hijacking | Can monitor clipboard for passwords/crypto addresses and inject into pages |

### 3. CSP Analyzer

Parses the extension's Content Security Policy and evaluates it:

- **Format detection:** Handles MV2 string format and MV3 object format (`{extension_pages: "...", sandbox: "..."}`)
- **Default CSP awareness:** If no CSP declared, Chrome enforces `script-src 'self'; object-src 'self'`. We note this rather than penalizing (unlike CRXcavator which unfairly added 425 points for missing CSP).
- **Directive-level analysis:** For each directive (script-src, connect-src, object-src, etc.):
  - Flag `unsafe-eval`, `unsafe-inline`
  - Flag wildcard sources (`*`)
  - Flag overly permissive domains
  - Flag known CSP bypass domains (from Tarnish + additions):
    - `ajax.googleapis.com` (JSONP)
    - `cdn.jsdelivr.net` (npm proxy)
    - `cdnjs.cloudflare.com` (old Angular sandbox escape)
    - `raw.githubusercontent.com` (anyone can upload)
    - `*.s3.amazonaws.com` (shared hosting)
    - `*.cloudfront.com` (shared CDN)
    - `*.herokuapp.com` (shared hosting)
    - `*.appspot.com` (shared hosting)
    - `*.googleusercontent.com` (user uploads)
    - `code.angularjs.org` (sandbox escape)
    - And others with specific exploit explanations
- **Missing directive warnings:** Flag missing critical directives that don't fall back to default-src

### 4. Code Scanner

Scans all JavaScript files for patterns that warrant review. Results are presented as "patterns found" with context, NOT as malware verdicts.

**Dangerous sinks (things that execute or inject):**
- `eval()`, `new Function()`, `setTimeout/setInterval` with string args
- `.innerHTML`, `.outerHTML` assignment
- `document.write()`, `document.writeln()`
- `chrome.tabs.executeScript()` (MV2), `chrome.scripting.executeScript()` (MV3)
- jQuery equivalents: `.html()`, `.append()`, `.prepend()`, `.before()`, `.after()`

**Data sources (entry points for attacker-controlled data):**
- `chrome.runtime.onMessage`, `chrome.runtime.onMessageExternal`
- `chrome.runtime.onConnect`, `chrome.runtime.onConnectExternal`
- `window.addEventListener("message", ...)` on web-accessible pages
- `chrome.tabs.query()`, `location.hash`, `location.href`, `window.name`

**Network activity:**
- `fetch()` and `XMLHttpRequest` to external domains
- Dynamic script creation (`document.createElement('script')`)

**Obfuscation indicators:**
- String concatenation building API names (e.g., `chrome['run' + 'time']`)
- Hex/unicode escape sequences in suspicious contexts
- Extremely long single-line strings (potential encoded payloads)

**Context:** Each finding includes the file path, line number, 3 lines of surrounding code, and whether the file is a content script, background script/service worker, or web-accessible resource.

### 5. Host Permission Analyzer

- **Broad pattern detection:** Flags `<all_urls>`, `*://*/*`, `http://*/*`, `https://*/*` with explanations of what they mean
- **Sensitive domain detection:** Flags host permissions matching banking, crypto, email, social media, CI/CD, and package registry domains (~60+ patterns from CRXaminer's research)
- **activeTab suggestion:** When broad host permissions are detected, suggests `activeTab` as a least-privilege alternative where applicable
- **Content script scope:** Flags content scripts with overly broad match patterns

### 6. Manifest Version Analysis

- Flags MV2 extensions with specific risks: remote code execution allowed, webRequestBlocking available, weaker CSP defaults
- Notes MV3 security improvements: no remote code, declarativeNetRequest instead of webRequestBlocking, stricter CSP
- Flags MV2 extensions that should have migrated (Google's MV2 deprecation timeline)

---

## Report Structure

The report is organized into clear sections, each answerable to "what did you find and why does it matter?"

### Overview Card
- Extension name, version, manifest version
- Input method used (ID / upload / paste)
- Summary: X permissions analyzed, Y combinations flagged, Z code patterns found

### Permission Capabilities
- Table of all permissions with plain-English capability descriptions
- Color-coded risk tier badges
- Required vs. optional distinction

### Dangerous Combinations
- Each flagged combination as a card with:
  - The permissions involved
  - What the combination enables (concrete attack scenario)
  - Real-world examples of this abuse pattern

### Content Security Policy
- Raw CSP displayed
- Per-directive breakdown with findings
- CSP bypass domain warnings with exploit explanations

### Code Patterns
- Grouped by category (sinks, sources, network, obfuscation)
- Each finding: file, line, code context, what file type (content script / background / web-accessible)
- Expandable code blocks with syntax highlighting

### Host Permissions
- Scope visualization: what sites this extension can access
- Sensitive domain matches
- Overly broad pattern warnings

### MV2/MV3 Assessment
- Manifest version with security implications
- Specific risks for MV2 extensions

---

## Project Structure

```
crx-audit/
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.ts
├── postcss.config.js
├── proxy/
│   └── worker.ts                 # Cloudflare Worker for CRX downloads
├── src/
│   ├── main.tsx                  # React entry
│   ├── App.tsx                   # Main app component
│   ├── types/
│   │   └── index.ts              # Shared types
│   ├── analyzer/
│   │   ├── crx-extractor.ts      # CRX download + ZIP extraction
│   │   ├── manifest-parser.ts    # Manifest parsing
│   │   ├── permission-analyzer.ts # Permission risk analysis
│   │   ├── combination-analyzer.ts # Dangerous combo detection
│   │   ├── csp-analyzer.ts       # CSP parsing + evaluation
│   │   ├── code-scanner.ts       # JS pattern detection
│   │   ├── host-analyzer.ts      # Host permission analysis
│   │   └── index.ts              # Orchestrator: runs all analyzers
│   ├── data/
│   │   ├── permissions.ts        # Permission → capability + risk mapping
│   │   ├── dangerous-combos.ts   # Permission combination definitions
│   │   ├── csp-bypass-domains.ts # Known CSP bypass domains + exploits
│   │   ├── code-patterns.ts      # Sink/source/network/obfuscation patterns
│   │   └── sensitive-domains.ts  # Banking, crypto, email, etc. patterns
│   ├── components/
│   │   ├── ExtensionInput.tsx     # ID input + file upload + manifest paste
│   │   ├── Report.tsx             # Report container
│   │   ├── OverviewCard.tsx       # Summary card
│   │   ├── PermissionTable.tsx    # Permission capabilities table
│   │   ├── CombinationCards.tsx   # Dangerous combination cards
│   │   ├── CSPSection.tsx         # CSP analysis section
│   │   ├── CodePatterns.tsx       # Code pattern findings
│   │   ├── HostPermissions.tsx    # Host permission analysis
│   │   └── ManifestVersion.tsx    # MV2/MV3 assessment
│   └── utils/
│       └── helpers.ts             # URL parsing, formatting, etc.
├── tests/
│   ├── analyzer/
│   │   ├── manifest-parser.test.ts
│   │   ├── permission-analyzer.test.ts
│   │   ├── combination-analyzer.test.ts
│   │   ├── csp-analyzer.test.ts
│   │   ├── code-scanner.test.ts
│   │   └── host-analyzer.test.ts
│   └── fixtures/
│       ├── manifests/             # Real and synthetic test manifests
│       └── extensions/            # Minimal test extensions
└── docs/
    └── superpowers/
        └── specs/
            └── 2026-04-08-crx-audit-design.md
```

---

## What This Deliberately Does NOT Do

1. **No "malware" / "safe" verdict** — Static analysis cannot determine intent. We surface capabilities and patterns, not judgments.
2. **No magic risk score** — Scores without defensible methodology are security theater. We show what the extension CAN do.
3. **No dynamic/behavioral analysis** — Out of scope. Would require running the extension, which is a fundamentally different tool.
4. **No RetireJS / vulnerability scanning** — Useful but tangential to the core value prop. Can be added later.
5. **No AI/LLM analysis** — Black box. Can't explain methodology in an interview.

---

## Testing Strategy

- **Unit tests:** Each analyzer module tested with real-world manifest snippets and synthetic edge cases
- **Integration tests:** Full analysis pipeline with known extensions (uBlock Origin, React DevTools, etc.) to verify accuracy
- **Regression fixtures:** Known-dangerous permission combos and CSP configurations that must always be caught
- **Manual verification:** Test with 5-10 real extensions and verify every finding is factually correct

---

## Interview Talking Points

This project demonstrates understanding of:
1. Chrome's extension permission model and trust boundaries
2. Real-world extension abuse vectors (supply chain attacks, permission over-requesting, post-review code loading)
3. The gap left by CRXcavator's shutdown and why transparent analysis matters
4. MV3's security improvements and remaining attack surface
5. Why static analysis has limits and what those limits are (honest engineering)
6. CSP bypass techniques and why certain CDN domains are dangerous in extension CSPs
