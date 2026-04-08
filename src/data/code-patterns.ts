import type { RiskLevel } from '../types'

export interface CodePattern {
  id: string
  pattern: RegExp
  category: 'sink' | 'source' | 'network' | 'obfuscation'
  risk: RiskLevel
  description: string
  contextDependent?: {
    onlyInFileTypes: ('content-script' | 'background' | 'web-accessible' | 'other')[]
  }
}

export const codePatterns: CodePattern[] = [
  // ── Sinks: code execution ─────────────────────────────────────────────────

  {
    id: 'eval',
    pattern: /\beval\s*\(/,
    category: 'sink',
    risk: 'critical',
    description: 'eval() executes arbitrary code from a string — primary injection vector',
  },
  {
    id: 'new-function',
    pattern: /new\s+Function\s*\(/,
    category: 'sink',
    risk: 'critical',
    description: 'new Function() dynamically creates executable code from strings, equivalent to eval()',
  },
  {
    id: 'innerhtml',
    pattern: /\.innerHTML\s*=/,
    category: 'sink',
    risk: 'high',
    description: 'innerHTML assignment can inject executable HTML including scripts and event handlers',
  },
  {
    id: 'outerhtml',
    pattern: /\.outerHTML\s*=/,
    category: 'sink',
    risk: 'high',
    description: 'outerHTML assignment replaces an element and its content with raw HTML — same XSS risk as innerHTML',
  },
  {
    id: 'document-write',
    pattern: /document\.write(ln)?\s*\(/,
    category: 'sink',
    risk: 'high',
    description: 'document.write()/writeln() injects raw HTML into the document, enabling XSS',
  },
  {
    id: 'insertadjacenthtml',
    pattern: /\.insertAdjacentHTML\s*\(/,
    category: 'sink',
    risk: 'high',
    description: 'insertAdjacentHTML() inserts raw HTML at a specified position — XSS risk with untrusted input',
  },
  {
    id: 'settimeout-string',
    pattern: /setTimeout\s*\(\s*["'`]/,
    category: 'sink',
    risk: 'high',
    description: 'setTimeout() with a string argument acts like eval()',
  },
  {
    id: 'setinterval-string',
    pattern: /setInterval\s*\(\s*["'`]/,
    category: 'sink',
    risk: 'high',
    description: 'setInterval() with a string argument acts like eval()',
  },
  {
    id: 'create-contextual-fragment',
    pattern: /\.createContextualFragment\s*\(/,
    category: 'sink',
    risk: 'high',
    description: 'createContextualFragment() creates DOM from HTML strings — can execute scripts when inserted',
  },
  {
    id: 'chrome-scripting-execute',
    pattern: /chrome\.scripting\.executeScript\s*\(/,
    category: 'sink',
    risk: 'high',
    description: 'Injects JavaScript into web pages — if script content is dynamic, enables arbitrary code execution in page context',
  },
  {
    id: 'chrome-tabs-execute-mv2',
    pattern: /chrome\.tabs\.executeScript\s*\(/,
    category: 'sink',
    risk: 'high',
    description: 'MV2 API to inject JavaScript into tabs — if script content is dynamic, enables code execution',
  },
  {
    id: 'dynamic-src-assignment',
    pattern: /\.src\s*=\s*[^;]*(?:user|input|param|query|url|data|response)/,
    category: 'sink',
    risk: 'medium',
    description: 'Setting element src to a dynamic value can load attacker-controlled scripts or resources',
  },
  {
    id: 'dynamic-href-assignment',
    pattern: /\.href\s*=\s*[^;]*(?:user|input|param|query|url|data)/,
    category: 'sink',
    risk: 'medium',
    description: 'Setting href to a dynamic value can redirect users or enable javascript: URL injection',
  },
  {
    id: 'postmessage-send',
    pattern: /\.postMessage\s*\(/,
    category: 'sink',
    risk: 'medium',
    description: 'postMessage() sends data cross-origin — must validate target origin to prevent data leaks',
  },
  {
    id: 'window-location-assign',
    pattern: /window\.location\s*=/,
    category: 'sink',
    risk: 'medium',
    description: 'Assigning window.location navigates the page — can redirect to phishing sites or javascript: URLs',
  },

  // ── Sources: attacker-controlled data entry points ────────────────────────

  {
    id: 'window-name',
    pattern: /window\.name\b/,
    category: 'source',
    risk: 'high',
    description:
      'window.name can be set by any page that previously held the frame — attacker-controlled in web-accessible pages',
    contextDependent: {
      onlyInFileTypes: ['web-accessible', 'content-script'],
    },
  },
  {
    id: 'location-href',
    pattern: /location\.(href|hash|search)\b/,
    category: 'source',
    risk: 'medium',
    description: 'URL components (href, hash, search) can be attacker-controlled in content scripts and web-accessible resources',
    contextDependent: {
      onlyInFileTypes: ['content-script', 'web-accessible'],
    },
  },
  {
    id: 'postmessage-listener',
    pattern: /addEventListener\s*\(\s*['"]message['"]/,
    category: 'source',
    risk: 'high',
    description:
      'Window message event listener — without origin check, any page can send attacker-controlled data',
  },
  {
    id: 'external-message-listener',
    pattern: /chrome\.runtime\.onMessageExternal/,
    category: 'source',
    risk: 'high',
    description:
      'onMessageExternal receives messages from other extensions or web pages (if externally_connectable) — must validate sender',
  },
  {
    id: 'connect-external-listener',
    pattern: /chrome\.runtime\.onConnectExternal/,
    category: 'source',
    risk: 'high',
    description:
      'onConnectExternal opens a persistent channel from external sources — must validate sender',
  },
  {
    id: 'internal-message-listener',
    pattern: /chrome\.runtime\.onMessage\b/,
    category: 'source',
    risk: 'medium',
    description:
      'onMessage receives messages from content scripts and extension pages — content scripts can be influenced by web pages',
  },
  {
    id: 'document-referrer',
    pattern: /document\.referrer\b/,
    category: 'source',
    risk: 'low',
    description: 'document.referrer is controlled by the referring page — can be spoofed',
    contextDependent: {
      onlyInFileTypes: ['content-script', 'web-accessible'],
    },
  },
  {
    id: 'storage-get',
    pattern: /chrome\.storage\.(local|sync|session)\.get\b/,
    category: 'source',
    risk: 'low',
    description:
      'Reads from extension storage — if written by a content script processing page data, stored values may be tainted',
  },
  {
    id: 'cookie-read',
    pattern: /chrome\.cookies\.(get|getAll)\b/,
    category: 'source',
    risk: 'medium',
    description: 'Reads browser cookies — cookie values may contain attacker-controlled data or sensitive session tokens',
  },
  {
    id: 'url-searchparams',
    pattern: /new\s+URLSearchParams\b/,
    category: 'source',
    risk: 'low',
    description: 'Parses URL query parameters — if used with dynamic URLs, can process attacker-controlled input',
  },

  // ── Network: data exfiltration / remote code loading ──────────────────────

  {
    id: 'fetch-call',
    pattern: /\bfetch\s*\(/,
    category: 'network',
    risk: 'medium',
    description: 'fetch() — verify the URL is not attacker-controlled and responses are not used unsafely',
  },
  {
    id: 'xmlhttprequest',
    pattern: /new\s+XMLHttpRequest/,
    category: 'network',
    risk: 'medium',
    description: 'XMLHttpRequest — verify the URL is not attacker-controlled',
  },
  {
    id: 'dynamic-script',
    pattern: /document\.createElement\s*\(\s*['"]script['"]\s*\)/,
    category: 'network',
    risk: 'critical',
    description: 'Dynamically creating script elements can load and execute remote code',
  },
  {
    id: 'websocket',
    pattern: /new\s+WebSocket\s*\(/,
    category: 'network',
    risk: 'high',
    description: 'WebSocket — persistent bidirectional connection can be used as a C2 channel for real-time command execution',
  },
  {
    id: 'eventsource',
    pattern: /new\s+EventSource\s*\(/,
    category: 'network',
    risk: 'medium',
    description: 'Server-Sent Events — persistent server-to-client connection can receive commands from a C2 server',
  },
  {
    id: 'sendbeacon',
    pattern: /navigator\.sendBeacon\s*\(/,
    category: 'network',
    risk: 'high',
    description: 'sendBeacon() sends data asynchronously, guaranteed to complete even during page unload — common exfiltration technique',
  },
  {
    id: 'image-beacon',
    pattern: /new\s+Image\s*\(\s*\)[\s\S]*?\.src\s*=/,
    category: 'network',
    risk: 'high',
    description: 'Creates an image element with a dynamic src to silently send data via URL parameters — classic exfiltration technique',
  },
  {
    id: 'importscripts',
    pattern: /importScripts\s*\(/,
    category: 'network',
    risk: 'high',
    description: 'importScripts() loads and executes scripts in a worker context — if URL is dynamic, enables remote code execution',
  },
  {
    id: 'webrequest-intercept',
    pattern: /chrome\.webRequest\.onBeforeRequest/,
    category: 'network',
    risk: 'high',
    description: 'Intercepting web requests — can redirect, block, or observe all network traffic',
  },
  {
    id: 'webrequest-headers',
    pattern: /chrome\.webRequest\.onBeforeSendHeaders/,
    category: 'network',
    risk: 'high',
    description: 'Intercepting outgoing request headers — can read/modify authentication tokens, cookies, and sensitive headers',
  },
  {
    id: 'webrequest-auth',
    pattern: /chrome\.webRequest\.onAuthRequired/,
    category: 'network',
    risk: 'critical',
    description: 'Intercepts HTTP authentication challenges — can capture or provide credentials',
  },
  {
    id: 'chrome-cookies-getall',
    pattern: /chrome\.cookies\.getAll/,
    category: 'network',
    risk: 'high',
    description: 'Reading all cookies for a domain or all domains — potential credential/session theft vector',
  },

  // ── Obfuscation: suspicious patterns suggesting hidden behavior ───────────

  {
    id: 'atob-long',
    pattern: /\batob\s*\(\s*["'][A-Za-z0-9+/=]{50,}/,
    category: 'obfuscation',
    risk: 'high',
    description: 'Decoding a long base64 string at runtime — commonly used to hide malicious payloads',
  },
  {
    id: 'atob-general',
    pattern: /\batob\s*\(/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Base64 decoding — may be hiding payloads; inspect the decoded value',
  },
  {
    id: 'charcode-chain',
    pattern: /String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){5,}\)/,
    category: 'obfuscation',
    risk: 'high',
    description: 'Building strings from long character code sequences — hides readable strings from static analysis',
  },
  {
    id: 'charcode',
    pattern: /String\.fromCharCode/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Building strings from char codes — common obfuscation technique',
  },
  {
    id: 'hex-encoded-string',
    pattern: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Long hex-escaped string sequences suggest intentional string obfuscation',
  },
  {
    id: 'escaped-unicode',
    pattern: /\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}.*\\u[0-9a-fA-F]{4}/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Heavy use of Unicode escapes — may indicate obfuscated code',
  },
  {
    id: 'array-join-construction',
    pattern: /\[\s*["'][^"']{1,3}["']\s*(,\s*["'][^"']{1,3}["']\s*){20,}\]\s*\.join\s*\(/,
    category: 'obfuscation',
    risk: 'high',
    description: 'Builds strings by joining arrays of short fragments — evades keyword scanning',
  },
  {
    id: 'url-encoded-payload',
    pattern: /decodeURIComponent\s*\(\s*["'][%0-9a-fA-F]{20,}/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Decodes a URL-encoded string at runtime — used to hide malicious URLs or code',
  },
  {
    id: 'js-obfuscator-vars',
    pattern: /(?:_0x[a-f0-9]{4,}|_0x[a-f0-9]{2,}\[)/,
    category: 'obfuscation',
    risk: 'high',
    description: 'Variable names matching javascript-obfuscator / JScrambler output patterns',
  },
  {
    id: 'bracket-notation-chain',
    pattern: /\bwindow\s*\[\s*["']\w+["']\s*\]\s*\[\s*["']\w+["']\s*\]/,
    category: 'obfuscation',
    risk: 'high',
    description: 'Accesses nested properties via bracket notation (e.g., window["eval"]) to avoid static method name detection',
  },
  {
    id: 'regex-replace-callback',
    pattern: /\.replace\s*\(\s*\/[^/]+\/g?i?\s*,\s*function/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'Regex replacement with function callback can decode or transform obfuscated strings at runtime',
  },
  {
    id: 'webcrypto-decrypt',
    pattern: /crypto\.subtle\.decrypt\b/,
    category: 'obfuscation',
    risk: 'medium',
    description: 'WebCrypto decryption at runtime — legitimate for secure comms, but also used to decrypt and eval hidden payloads',
  },
]
