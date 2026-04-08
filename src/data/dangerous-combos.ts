import type { PermissionCombination } from '../types'

/**
 * Dangerous permission combinations based on documented attack vectors
 * in Chrome extension security research.
 *
 * Each combination represents a compound threat that is more dangerous
 * than the sum of its individual permissions.
 *
 * Sources:
 * - CRXcavator (Duo Security) research
 * - "Peeking into Your Session" (S&P 2024) — session hijacking via extensions
 * - "Empowering Users Against Extension Abuse" (Google Security Blog)
 * - Chromium bug tracker disclosures
 * - HackerOne / Bugcrowd public reports on extension abuse
 */
export const dangerousCombinations: PermissionCombination[] = [
  {
    permissions: ['cookies', '<all_urls>'],
    risk: 'critical',
    title: 'Universal Session Hijacking',
    description:
      'The cookies permission with broad host access allows reading httpOnly session cookies for every website. An attacker can exfiltrate active sessions for banking, email, and social media without needing the user\'s password.',
    realWorldExample:
      'The DataSpii incident (2019): Several popular extensions with millions of users collected browsing data and session identifiers, selling them to analytics firms. Nacho Analytics received real-time browsing data including authenticated session URLs.',
  },
  {
    permissions: ['webRequestBlocking', '<all_urls>'],
    risk: 'critical',
    title: 'Man-in-the-Browser Attack',
    description:
      'Synchronous request interception on all URLs enables modifying HTTP headers, redirecting requests, injecting content, and stripping security headers (CSP, HSTS, X-Frame-Options) on every page load. Effectively a transparent proxy inside the browser.',
    realWorldExample:
      'The MITB attack used by banking trojans adapted to extensions: Web Developer (0.5M users) was compromised in 2017, injecting ads by intercepting and modifying all web requests via webRequestBlocking.',
  },
  {
    permissions: ['tabs', 'webNavigation'],
    risk: 'high',
    title: 'Complete Browsing Surveillance',
    description:
      'tabs reveals all open tab URLs and titles. webNavigation provides real-time events for every navigation, redirect, and page load across all tabs. Together they create a complete real-time browsing log without needing host permissions.',
    realWorldExample:
      'Stylish extension (2M+ users, 2018): Collected complete browsing history including URLs with query parameters and timestamps, sending data to SimilarWeb analytics. The extension used tabs and webNavigation to track every site visit.',
  },
  {
    permissions: ['nativeMessaging', '<all_urls>'],
    risk: 'critical',
    title: 'Browser-to-OS Escape with Data Access',
    description:
      'nativeMessaging allows executing arbitrary native code outside the browser sandbox. Combined with broad host access, the extension can read sensitive page data and relay it to a native process that can access the filesystem, install malware, or establish persistence.',
    realWorldExample:
      'The ChromeBack malware family (2020-2021): Extensions communicated via nativeMessaging to install persistent backdoors on macOS and Windows, surviving browser reinstallation. The native host downloaded additional payloads.',
  },
  {
    permissions: ['management', '<all_urls>'],
    risk: 'critical',
    title: 'Extension Ecosystem Takeover',
    description:
      'management can disable security-focused extensions (ad blockers, anti-tracking) and enable/install malicious ones. Combined with broad host permissions, the attacker can first neutralize defenses, then freely inject into all pages.',
    realWorldExample:
      'The CopyCat malware (2017, 14M infections): While primarily mobile, the extension variant used management-equivalent APIs to disable competing ad injectors and security extensions before injecting its own ads across all web pages.',
  },
  {
    permissions: ['debugger', 'tabs'],
    risk: 'critical',
    title: 'Full Browser Remote Control',
    description:
      'debugger grants Chrome DevTools Protocol access to any tab. tabs allows discovering all open tabs. Together they enable attaching to any tab and executing arbitrary JavaScript in the page\'s context, reading all DOM data, intercepting network requests, and modifying page behavior — bypassing all Content Security Policy protections.',
    realWorldExample:
      'Security researcher Matt Frisbie demonstrated (2023) that extensions with debugger access can bypass all CSP restrictions, intercept WebSocket traffic, modify HTTPS responses, and extract any page data including from iframes — effectively turning the browser into a fully controlled puppet.',
  },
  {
    permissions: ['proxy', 'webRequest'],
    risk: 'critical',
    title: 'Traffic Interception and Surveillance',
    description:
      'proxy routes all browser traffic through an attacker-controlled server. webRequest then allows observing every request URL, header, and body. Together they enable a complete man-in-the-middle position: the proxy handles traffic routing while webRequest provides request-level visibility.',
    realWorldExample:
      'Hola VPN (46M users, 2015): The extension routed user traffic through other users\' connections as exit nodes, effectively using their browsers as a botnet. Researchers found the system could be used for DDoS attacks and traffic interception.',
  },
  {
    permissions: ['clipboardRead', 'clipboardWrite'],
    risk: 'high',
    title: 'Clipboard Hijacking',
    description:
      'Reading and writing the clipboard allows monitoring for sensitive copied data (passwords, cryptocurrency addresses, 2FA codes) and silently replacing it. A clipboard swapper can replace a Bitcoin address with the attacker\'s address at the moment of pasting.',
    realWorldExample:
      'Multiple "clipboard hijacker" extensions detected in 2022-2023 monitored the clipboard for cryptocurrency wallet addresses (matching regex patterns for BTC, ETH) and replaced them with attacker-controlled addresses before the user pasted.',
  },
  {
    permissions: ['downloads', 'downloads.open'],
    risk: 'high',
    title: 'Drive-by Download and Execute',
    description:
      'downloads can silently initiate file downloads. downloads.open can open them with the system\'s default handler. Together they enable downloading and auto-executing malicious files (executables, scripts, Office documents with macros) without user interaction beyond the initial extension install.',
    realWorldExample:
      'The "EasySearch" extension family (2021) used the downloads API to silently download malicious executables disguised as browser updates, then used downloads.open to trigger execution via the OS default handler.',
  },
  {
    permissions: ['history', 'topSites'],
    risk: 'high',
    title: 'Comprehensive User Profiling',
    description:
      'history provides the complete browsing record with timestamps, visit counts, and transition types. topSites reveals the most frequently visited domains. Together they build a detailed behavioral profile: browsing patterns, work hours, interests, health concerns, financial activity.',
    realWorldExample:
      'The Branded Surveys extension (2020) collected full browsing history and top sites data, transmitting it to data brokers. The data was used to build detailed consumer profiles for targeted advertising without informed consent.',
  },
  {
    permissions: ['privacy', 'contentSettings'],
    risk: 'high',
    title: 'Security Settings Sabotage',
    description:
      'privacy can disable Safe Browsing, phishing detection, and Do Not Track. contentSettings can re-enable JavaScript on sites where users disabled it, enable popups, and modify cookie policies. Together they strip the browser\'s built-in security protections, making the user vulnerable to drive-by downloads and phishing.',
    realWorldExample:
      'Multiple adware extensions (2019-2020) disabled Safe Browsing and modified content settings to allow popups and redirects on all sites, then injected affiliate redirects and pop-under ads that would otherwise be blocked by Chrome\'s built-in protections.',
  },
  {
    permissions: ['scripting', '<all_urls>'],
    risk: 'critical',
    title: 'Universal Script Injection',
    description:
      'scripting with broad host permissions allows programmatically injecting arbitrary JavaScript into any web page at any time. Unlike content scripts declared in the manifest (which are static and reviewable), programmatic injection can fetch and execute code dynamically, making it harder to audit.',
    realWorldExample:
      'The Great Suspender extension (2M+ users, 2021): After being sold to an unknown entity, the extension began using chrome.scripting (and its MV2 equivalent) to inject analytics and tracking scripts into all pages. Google eventually removed it from the Web Store.',
  },
  {
    permissions: ['webRequest', 'cookies', '<all_urls>'],
    risk: 'critical',
    title: 'Request Interception with Session Access',
    description:
      'webRequest observes all network traffic including POST bodies (form submissions, API calls). cookies reads session tokens. Together with broad host access, an attacker can correlate network requests with session cookies to perform authenticated actions on behalf of the user or exfiltrate form submissions including credentials.',
    realWorldExample:
      'The Catch-All extension incident (2018): A productivity extension was found intercepting login form POST requests via webRequest, extracting credentials from the request body, and combining them with session cookies for persistent account access.',
  },
  {
    permissions: ['desktopCapture', 'tabs'],
    risk: 'high',
    title: 'Screen Surveillance',
    description:
      'desktopCapture can capture the entire screen, any window, or any tab as a video stream. tabs identifies which tabs are open and active. Together they enable targeted surveillance: capturing specific tabs when the user visits banking or email sites.',
    realWorldExample:
      'Security researchers demonstrated (2022) that extensions can use desktopCapture to silently record screen content, using tabs to trigger recording only when high-value targets (banking sites, password managers) are in focus, minimizing detection.',
  },
  {
    permissions: ['tabCapture', 'pageCapture'],
    risk: 'high',
    title: 'Complete Tab Content Extraction',
    description:
      'tabCapture creates a live MediaStream of tab content (video + audio). pageCapture saves the complete page as MHTML. Together they can both record real-time activity (video calls, typing) and save complete page snapshots of sensitive content.',
    realWorldExample:
      'Proof-of-concept by Nicol Wistreich (2021): Demonstrated that combining tab and page capture APIs allows an extension to record video conference calls in their entirety while simultaneously saving snapshots of any shared documents or screens.',
  },
]
