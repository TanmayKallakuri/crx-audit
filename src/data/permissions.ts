import type { RiskLevel } from '../types'

export interface PermissionDetail {
  description: string
  risk: RiskLevel
  capability: string
}

/**
 * Comprehensive mapping of Chrome extension permissions to their capabilities and risk levels.
 *
 * Risk tier rationale:
 * - CRITICAL: Grants ability to intercept/modify all web traffic, execute native code,
 *   access authenticated sessions across sites, or fully control browser debugging.
 * - HIGH: Grants access to sensitive user data (browsing history, clipboard, tab URLs),
 *   can modify browser privacy settings, or manage other extensions.
 * - MEDIUM: Grants access to moderate user data (bookmarks, downloads) or ability to
 *   observe/modify navigation and network requests with declarative rules.
 * - LOW: Grants limited capabilities scoped to active interaction or extension-local data.
 * - NONE: Grants no access to user data and cannot observe user behavior.
 *
 * Sources: https://developer.chrome.com/docs/extensions/reference/permissions-list
 *          https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions
 */
export const permissionMap: Record<string, PermissionDetail> = {
  // ── CRITICAL ──────────────────────────────────────────────────────────────

  '<all_urls>': {
    description: 'Access all websites and their data',
    risk: 'critical',
    capability:
      'Read and modify content on every website. Inject scripts into any page, intercept form submissions, read page DOM including passwords and tokens.',
  },

  '*://*/*': {
    description: 'Access all HTTP and HTTPS websites',
    risk: 'critical',
    capability:
      'Equivalent to <all_urls> for web content. Can read/modify DOM on every HTTP/HTTPS page, inject content scripts universally.',
  },

  'http://*/*': {
    description: 'Access all HTTP websites',
    risk: 'critical',
    capability:
      'Read and modify content on every HTTP website. HTTP traffic is unencrypted, making injected scripts especially dangerous for credential theft.',
  },

  'https://*/*': {
    description: 'Access all HTTPS websites',
    risk: 'critical',
    capability:
      'Read and modify content on every HTTPS website. Can access authenticated sessions, read page content including banking and email.',
  },

  debugger: {
    description: 'Access the Chrome DevTools Protocol (chrome.debugger API)',
    risk: 'critical',
    capability:
      'Attach to any tab and use the full Chrome DevTools Protocol. Can read/modify network requests, execute JavaScript in page context, access cookies, modify DOM, capture screenshots, and intercept all page data.',
  },

  cookies: {
    description: 'Read and modify cookies for sites the extension has host permissions for',
    risk: 'critical',
    capability:
      'Read, set, and remove cookies including httpOnly cookies. When combined with broad host permissions, enables session hijacking across all sites. Can exfiltrate authentication tokens.',
  },

  nativeMessaging: {
    description: 'Exchange messages with native applications on the user\'s computer',
    risk: 'critical',
    capability:
      'Communicate with a native application installed on the host machine. Enables arbitrary code execution outside the browser sandbox, file system access, and OS-level operations.',
  },

  webRequestBlocking: {
    description: 'Intercept and modify network requests synchronously (MV2 only)',
    risk: 'critical',
    capability:
      'Block, redirect, or modify HTTP headers on any network request in real-time. Can inject malicious redirects, strip security headers (CSP, HSTS), modify authentication tokens, and perform invisible MITM attacks.',
  },

  proxy: {
    description: 'Manage Chrome\'s proxy settings',
    risk: 'critical',
    capability:
      'Route all browser traffic through an arbitrary proxy server. Enables traffic interception, credential harvesting, DNS manipulation, and invisible surveillance of all browsing activity.',
  },

  // ── HIGH ──────────────────────────────────────────────────────────────────

  history: {
    description: 'Read and modify browsing history',
    risk: 'high',
    capability:
      'Read the user\'s complete browsing history including URLs, visit times, and frequency. Can delete history entries. Reveals sensitive browsing patterns, medical searches, financial sites visited.',
  },

  tabs: {
    description: 'Access tab URLs, titles, and status for all tabs',
    risk: 'high',
    capability:
      'Query all open tabs and read their URLs and titles. Reveals currently active sites, can detect when user visits banking/email. In MV2, also grants access to tab.url and tab.title without activeTab.',
  },

  clipboardRead: {
    description: 'Read data from the system clipboard',
    risk: 'high',
    capability:
      'Read clipboard contents at any time, not just during paste events. Can capture copied passwords, credit card numbers, private messages, cryptocurrency addresses, and 2FA codes.',
  },

  privacy: {
    description: 'Control Chrome privacy settings',
    risk: 'high',
    capability:
      'Read and modify privacy-related browser settings. Can disable Safe Browsing, enable third-party cookie tracking, disable Do Not Track, and weaken browser security protections.',
  },

  contentSettings: {
    description: 'Change settings that control content features (cookies, JavaScript, plugins)',
    risk: 'high',
    capability:
      'Modify per-site content settings for cookies, images, JavaScript, plugins, popups, and notifications. Can enable JavaScript on sites where user disabled it, or enable popups globally.',
  },

  desktopCapture: {
    description: 'Capture screen, window, or tab content',
    risk: 'high',
    capability:
      'Capture screenshots or video of the entire desktop, specific windows, or tabs. Can record sensitive information displayed on screen including other applications.',
  },

  tabCapture: {
    description: 'Capture tab audio and video streams',
    risk: 'high',
    capability:
      'Create a MediaStream from any tab\'s visible content and audio. Can record video calls, streaming content, or any visual/audio content in a tab.',
  },

  pageCapture: {
    description: 'Save complete web pages as MHTML',
    risk: 'high',
    capability:
      'Save the complete rendered content of any tab as MHTML, including all resources. Can capture pages with sensitive data like email inboxes, bank statements, and medical records.',
  },

  management: {
    description: 'Manage other installed extensions and apps',
    risk: 'high',
    capability:
      'List, enable, disable, and uninstall other extensions. Can disable security extensions (ad blockers, privacy tools), enable malicious extensions, and enumerate installed extensions for fingerprinting.',
  },

  // ── MEDIUM ────────────────────────────────────────────────────────────────

  bookmarks: {
    description: 'Read and modify bookmarks',
    risk: 'medium',
    capability:
      'Read, create, modify, and delete all bookmarks. Reveals saved URLs which may include internal corporate tools, personal accounts, and sensitive resources.',
  },

  geolocation: {
    description: 'Access geographic location without user prompt',
    risk: 'medium',
    capability:
      'Access the device\'s geographic location without triggering the browser\'s native permission prompt. Can continuously track user\'s physical location.',
  },

  downloads: {
    description: 'Manage downloads and access the download shelf',
    risk: 'medium',
    capability:
      'Initiate downloads, monitor download activity, access downloaded file paths, and open downloaded files. Can download malicious files and observe what the user downloads.',
  },

  'downloads.open': {
    description: 'Open downloaded files',
    risk: 'medium',
    capability:
      'Open downloaded files using the system\'s default handler. Combined with downloads permission, can download and auto-execute malicious files.',
  },

  webNavigation: {
    description: 'Observe and analyze navigation events',
    risk: 'medium',
    capability:
      'Receive notifications about navigation events in all tabs: when pages load, redirect, or complete. Can track all browsing activity in real-time including URLs with query parameters.',
  },

  webRequest: {
    description: 'Observe network requests (read-only in MV3)',
    risk: 'medium',
    capability:
      'Observe all network requests including URLs, headers, and request bodies. Can monitor API calls, form submissions, and authentication flows. In MV3, read-only observation without blocking.',
  },

  declarativeNetRequest: {
    description: 'Block or modify network requests using declarative rules',
    risk: 'medium',
    capability:
      'Block, redirect, or modify headers on network requests using predefined rules. Can redirect URLs, strip security headers, or block specific resources. More limited than webRequestBlocking.',
  },

  declarativeNetRequestWithHostAccess: {
    description: 'Declarative net request with host-aware redirect actions',
    risk: 'medium',
    capability:
      'Same as declarativeNetRequest but can redirect to URLs that require host permission. Enables more flexible request modification.',
  },

  declarativeNetRequestFeedback: {
    description: 'Access matched declarativeNetRequest rules for debugging',
    risk: 'medium',
    capability:
      'View which declarativeNetRequest rules matched specific requests. Intended for debugging but can reveal browsing patterns.',
  },

  scripting: {
    description: 'Execute scripts in web page contexts',
    risk: 'medium',
    capability:
      'Programmatically inject JavaScript and CSS into web pages. Requires host permissions to specify targets. Can modify page content, read DOM data, and intercept user interactions.',
  },

  topSites: {
    description: 'Access list of most frequently visited sites',
    risk: 'medium',
    capability:
      'Read the user\'s most visited websites. Reveals browsing habits and frequently accessed services, useful for targeted phishing.',
  },

  browsingData: {
    description: 'Remove browsing data (history, cookies, cache, etc.)',
    risk: 'medium',
    capability:
      'Delete browsing data including history, cookies, cache, passwords, form data, and downloads. Can clear forensic evidence or disrupt user sessions.',
  },

  // ── LOW ───────────────────────────────────────────────────────────────────

  activeTab: {
    description: 'Temporary access to the active tab when the user invokes the extension',
    risk: 'low',
    capability:
      'Get temporary host permission for the currently active tab only when user clicks the extension icon or uses a keyboard shortcut. Access is revoked when the user navigates away.',
  },

  storage: {
    description: 'Store and retrieve data using chrome.storage API',
    risk: 'low',
    capability:
      'Store extension data locally or synced across the user\'s Chrome instances. Cannot access other extensions\' storage. Used for settings and state.',
  },

  alarms: {
    description: 'Schedule code to run at periodic intervals',
    risk: 'low',
    capability:
      'Set timers and periodic alarms to wake the service worker. Can schedule background tasks but cannot access user data directly.',
  },

  contextMenus: {
    description: 'Add items to the browser\'s right-click context menu',
    risk: 'low',
    capability:
      'Create custom context menu items. Can see selected text when the menu item is clicked, but only for that specific interaction.',
  },

  notifications: {
    description: 'Display system notifications',
    risk: 'low',
    capability:
      'Show desktop notifications to the user. Can be used for social engineering (fake alerts) but cannot access user data.',
  },

  identity: {
    description: 'Access the signed-in Google account\'s OAuth2 tokens',
    risk: 'low',
    capability:
      'Get OAuth2 access tokens for the user\'s Google account for specified scopes. Scopes are declared in the manifest and shown during install. Cannot access tokens beyond declared scopes.',
  },

  'identity.email': {
    description: 'Access the signed-in user\'s email address',
    risk: 'low',
    capability:
      'Read the email address of the user\'s signed-in Chrome profile. Limited PII exposure.',
  },

  idle: {
    description: 'Detect when the machine enters idle state',
    risk: 'low',
    capability:
      'Detect whether the user is active, idle, or has locked the screen. Can be used to time actions when user is away, but reveals minimal information.',
  },

  offscreen: {
    description: 'Create offscreen documents for DOM APIs in MV3 service workers',
    risk: 'low',
    capability:
      'Create hidden documents to use DOM APIs that aren\'t available in service workers (audio playback, DOM parsing). Cannot access web content.',
  },

  sidePanel: {
    description: 'Open and manage the extension\'s side panel',
    risk: 'low',
    capability:
      'Display the extension\'s UI in Chrome\'s side panel. No access to user data beyond what other permissions grant.',
  },

  action: {
    description: 'Control the extension\'s toolbar icon (MV3)',
    risk: 'low',
    capability:
      'Set badge text, icon, popup, and title for the extension\'s toolbar button. UI-only capability.',
  },

  browserAction: {
    description: 'Control the extension\'s toolbar icon (MV2)',
    risk: 'low',
    capability:
      'MV2 equivalent of "action". Set badge text, icon, popup, and title for the toolbar button.',
  },

  pageAction: {
    description: 'Control a page-specific toolbar icon (MV2)',
    risk: 'low',
    capability:
      'MV2 API to show/hide a page-specific icon in the address bar. UI-only capability.',
  },

  commands: {
    description: 'Add keyboard shortcut handlers',
    risk: 'low',
    capability:
      'Register keyboard shortcuts for extension actions. Can detect when specific key combinations are pressed but only for registered shortcuts.',
  },

  declarativeContent: {
    description: 'Show page action based on page content without host permissions',
    risk: 'low',
    capability:
      'Enable the page action icon based on URL patterns or CSS selectors on the page. Can detect if certain elements exist on a page but cannot read their content.',
  },

  'enterprise.deviceAttributes': {
    description: 'Read enterprise device attributes',
    risk: 'low',
    capability:
      'Read device attributes set by enterprise policy (device ID, serial number, asset ID). Only available to force-installed extensions.',
  },

  'enterprise.hardwarePlatform': {
    description: 'Read hardware platform info in enterprise context',
    risk: 'low',
    capability:
      'Read hardware manufacturer and model. Only meaningful in enterprise-managed Chrome.',
  },

  'enterprise.platformKeys': {
    description: 'Access enterprise platform keys for client certificates',
    risk: 'low',
    capability:
      'Generate and use keys backed by hardware tokens for enterprise authentication. Enterprise-managed only.',
  },

  'enterprise.networkingAttributes': {
    description: 'Read network configuration in enterprise context',
    risk: 'low',
    capability:
      'Read enterprise network adapter MAC address and IP. Enterprise-managed only.',
  },

  gcm: {
    description: 'Use Google Cloud Messaging',
    risk: 'low',
    capability:
      'Send and receive messages through Google Cloud Messaging / Firebase Cloud Messaging. Enables push notifications from the extension\'s server.',
  },

  'system.cpu': {
    description: 'Read CPU information',
    risk: 'low',
    capability:
      'Query CPU architecture, model, features, and usage. Useful for fingerprinting but limited sensitivity.',
  },

  'system.memory': {
    description: 'Read system memory information',
    risk: 'low',
    capability:
      'Query total and available physical memory. Useful for fingerprinting.',
  },

  'system.display': {
    description: 'Read display information',
    risk: 'low',
    capability:
      'Query connected display properties (resolution, bounds, rotation). Useful for fingerprinting.',
  },

  'system.storage': {
    description: 'Read storage device information',
    risk: 'low',
    capability:
      'Query storage device capacity and type. Minimal sensitivity.',
  },

  tabGroups: {
    description: 'Interact with Chrome\'s tab grouping system',
    risk: 'low',
    capability:
      'Query and modify tab groups (create, update, move). Can read group titles but not tab content.',
  },

  search: {
    description: 'Trigger searches using the default search engine',
    risk: 'low',
    capability:
      'Initiate a search via Chrome\'s omnibox with the default search engine. Cannot read search results.',
  },

  'runtime.connectNative': {
    description: 'Required subset for nativeMessaging',
    risk: 'low',
    capability:
      'Connect to a native messaging host. This is typically requested as part of nativeMessaging permission.',
  },

  favicon: {
    description: 'Access website favicons via chrome://favicon URL',
    risk: 'low',
    capability:
      'Load favicons for any URL. May reveal browsing history if favicons are cached, but limited impact.',
  },

  readingList: {
    description: 'Access and modify the reading list',
    risk: 'low',
    capability:
      'Read and modify Chrome\'s reading list entries. Reveals saved articles but limited sensitivity.',
  },

  // ── NONE ──────────────────────────────────────────────────────────────────

  power: {
    description: 'Override system power management',
    risk: 'none',
    capability:
      'Prevent the display from dimming or the system from sleeping. No access to user data.',
  },

  tts: {
    description: 'Use text-to-speech synthesis',
    risk: 'none',
    capability:
      'Convert text to speech using the system\'s speech synthesis engine. Output only — no data access.',
  },

  ttsEngine: {
    description: 'Implement a text-to-speech engine',
    risk: 'none',
    capability:
      'Register the extension as a TTS engine for Chrome. Receives text to speak but this is explicitly provided by other extensions or pages.',
  },

  fontSettings: {
    description: 'Manage Chrome\'s font settings',
    risk: 'none',
    capability:
      'Read and modify default font families and sizes. Pure preference — no user data access.',
  },

  unlimitedStorage: {
    description: 'Remove quota limits on client-side storage',
    risk: 'none',
    capability:
      'Remove the 10 MB quota on chrome.storage.local and other client-side storage. Does not grant access to any new data.',
  },

  'file://': {
    description: 'Access local files via file:// URLs',
    risk: 'critical',
    capability:
      'Read content of local files on the user\'s filesystem when opened in the browser. Can access sensitive local files.',
  },

  'chrome://favicon': {
    description: 'Access Chrome internal favicon service',
    risk: 'low',
    capability:
      'Access the chrome://favicon/ URL scheme to retrieve site favicons. May leak visited-site information.',
  },

  accessibilityFeatures: {
    description: 'Read and modify Chrome accessibility settings',
    risk: 'low',
    capability:
      'Control accessibility features like high contrast mode, virtual keyboard, and screen magnifier. No direct data access.',
  },

  'accessibilityFeatures.read': {
    description: 'Read Chrome accessibility settings',
    risk: 'none',
    capability:
      'Read current accessibility feature states. No modification ability.',
  },

  'accessibilityFeatures.modify': {
    description: 'Modify Chrome accessibility settings',
    risk: 'low',
    capability:
      'Change accessibility features. Could disrupt user experience but no data access.',
  },

  certificateProvider: {
    description: 'Provide client certificates for TLS authentication',
    risk: 'low',
    capability:
      'Expose certificates to Chrome for TLS client authentication. Enterprise use case.',
  },

  documentScan: {
    description: 'Access document scanner devices',
    risk: 'low',
    capability:
      'Discover and interact with document scanners attached to the device. ChromeOS only.',
  },

  fileBrowserHandler: {
    description: 'Extend ChromeOS file browser',
    risk: 'low',
    capability:
      'Add custom file handlers to the ChromeOS file browser. Can access files user selects.',
  },

  fileSystemProvider: {
    description: 'Create virtual file systems in ChromeOS',
    risk: 'low',
    capability:
      'Provide a virtual file system accessible from the ChromeOS file browser. Can serve files from cloud or network.',
  },

  loginState: {
    description: 'Read ChromeOS login state',
    risk: 'none',
    capability:
      'Read whether a user session is active on ChromeOS. Minimal information.',
  },

  platformKeys: {
    description: 'Access platform-provided client certificates',
    risk: 'low',
    capability:
      'Access client certificates provisioned by the platform. Enterprise/ChromeOS focused.',
  },

  printing: {
    description: 'Send print jobs to printers',
    risk: 'low',
    capability:
      'Submit print jobs and query printer capabilities. Could print unwanted content but limited data access.',
  },

  printingMetrics: {
    description: 'Access printing usage data',
    risk: 'low',
    capability:
      'Read printing usage metrics. Enterprise-focused, minimal sensitivity.',
  },

  processes: {
    description: 'Interact with browser process information',
    risk: 'low',
    capability:
      'Read process IDs, CPU/memory usage for browser processes. Useful for task manager extensions.',
  },

  signedInDevices: {
    description: 'List devices signed into the same Google account',
    risk: 'low',
    capability:
      'Read the list of devices connected to the user\'s Google account. Reveals device names and types.',
  },

  vpnProvider: {
    description: 'Implement a VPN client (ChromeOS)',
    risk: 'high',
    capability:
      'Create VPN configurations and tunnel network traffic. On ChromeOS, can route all traffic through the extension\'s VPN, enabling traffic interception.',
  },

  wallpaper: {
    description: 'Set ChromeOS wallpaper',
    risk: 'none',
    capability:
      'Change the desktop wallpaper on ChromeOS. Cosmetic only.',
  },

  webAuthenticationProxy: {
    description: 'Proxy WebAuthn (FIDO2) requests',
    risk: 'high',
    capability:
      'Intercept and handle WebAuthn API requests. Can interfere with hardware security key authentication flows.',
  },

  clipboardWrite: {
    description: 'Write data to the system clipboard',
    risk: 'low',
    capability:
      'Write text or images to the clipboard. Can replace copied content (e.g., swap cryptocurrency addresses) but cannot read existing clipboard data.',
  },
}

/**
 * Checks if a string looks like a host permission pattern rather than an API permission.
 */
export function isHostPermission(permission: string): boolean {
  return (
    permission.includes('://') ||
    permission === '<all_urls>' ||
    permission.startsWith('*:')
  )
}

/**
 * Returns true if the host pattern is "broad" — meaning it covers all or nearly all sites.
 */
export function isBroadHostPermission(permission: string): boolean {
  const broadPatterns = [
    '<all_urls>',
    '*://*/*',
    'http://*/*',
    'https://*/*',
    '*://*.com/*',
    '*://*.net/*',
    '*://*.org/*',
  ]
  return broadPatterns.includes(permission)
}
