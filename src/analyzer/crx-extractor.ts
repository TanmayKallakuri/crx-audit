import JSZip from 'jszip'
import type { ExtensionFiles } from '../types'

/**
 * Parse a CRX3 file and return the ZIP portion as an ArrayBuffer.
 * CRX3 format:
 *   - 4 bytes magic: "Cr24" (0x43723234)
 *   - 4 bytes version (uint32 LE, should be 3)
 *   - 4 bytes header length (uint32 LE)
 *   - <header_length> bytes of protobuf header
 *   - rest is ZIP data
 */
function extractZipFromCrx(buffer: ArrayBuffer): ArrayBuffer {
  const view = new DataView(buffer)

  // Check magic bytes "Cr24"
  const magic = String.fromCharCode(
    view.getUint8(0),
    view.getUint8(1),
    view.getUint8(2),
    view.getUint8(3),
  )

  if (magic !== 'Cr24') {
    // Not a CRX file — return as-is and let JSZip try it as a plain ZIP
    return buffer
  }

  const version = view.getUint32(4, true)
  if (version !== 3) {
    throw new Error(`Unsupported CRX version: ${version}. Only CRX3 is supported.`)
  }

  const headerLength = view.getUint32(8, true)
  const zipStart = 12 + headerLength

  return buffer.slice(zipStart)
}

/**
 * Load a ZIP buffer and extract manifest.json + all .js files.
 */
async function extractFromZip(zipData: ArrayBuffer): Promise<ExtensionFiles> {
  const zip = await JSZip.loadAsync(zipData)

  // Find manifest.json
  const manifestFile = zip.file('manifest.json')
  if (!manifestFile) {
    throw new Error('No manifest.json found in the extension archive.')
  }

  const manifestText = await manifestFile.async('text')
  let manifest: Record<string, unknown>
  try {
    manifest = JSON.parse(manifestText)
  } catch {
    throw new Error('Failed to parse manifest.json — invalid JSON.')
  }

  // Extract all JS files
  const jsFiles = new Map<string, string>()
  const allFiles: string[] = []

  const filePromises: Promise<void>[] = []

  zip.forEach((relativePath, entry) => {
    if (entry.dir) return
    allFiles.push(relativePath)

    if (relativePath.endsWith('.js') || relativePath.endsWith('.mjs')) {
      filePromises.push(
        entry.async('text').then((content) => {
          jsFiles.set(relativePath, content)
        }),
      )
    }
  })

  await Promise.all(filePromises)

  // Resolve __MSG_*__ i18n strings in manifest
  await resolveI18n(manifest, zip)

  return { manifest, jsFiles, allFiles }
}

/**
 * Extract extension files from an uploaded .crx or .zip file.
 */
export async function extractFromFile(file: File): Promise<ExtensionFiles> {
  const buffer = await file.arrayBuffer()
  const zipData = extractZipFromCrx(buffer)
  return extractFromZip(zipData)
}

/**
 * Parse a pasted manifest JSON string and return ExtensionFiles
 * with an empty JS files map.
 */
export function extractFromManifest(json: string): ExtensionFiles {
  let manifest: Record<string, unknown>
  try {
    manifest = JSON.parse(json)
  } catch {
    throw new Error('Invalid JSON — could not parse the pasted manifest.')
  }

  if (!manifest.manifest_version) {
    throw new Error('This does not look like a manifest.json — missing manifest_version field.')
  }

  return {
    manifest,
    jsFiles: new Map(),
    allFiles: ['manifest.json'],
  }
}

/**
 * Resolve __MSG_key__ i18n placeholders in manifest fields.
 * Looks up the default_locale (or 'en') messages.json from _locales/.
 */
async function resolveI18n(manifest: Record<string, unknown>, zip: JSZip): Promise<void> {
  const defaultLocale = (typeof manifest.default_locale === 'string' ? manifest.default_locale : 'en').toLowerCase()
  const localePaths = [`_locales/${defaultLocale}/messages.json`, '_locales/en/messages.json']

  let messages: Record<string, { message?: string }> = {}
  for (const p of localePaths) {
    const file = zip.file(p)
    if (file) {
      try {
        messages = JSON.parse(await file.async('text'))
        break
      } catch { /* skip bad json */ }
    }
  }

  if (Object.keys(messages).length === 0) return

  const resolve = (val: unknown): unknown => {
    if (typeof val === 'string') {
      return val.replace(/__MSG_(\w+)__/g, (_, key: string) => {
        const entry = messages[key] || messages[key.toLowerCase()]
        return entry?.message ?? `__MSG_${key}__`
      })
    }
    return val
  }

  // Resolve common string fields
  for (const field of ['name', 'short_name', 'description', 'author']) {
    if (typeof manifest[field] === 'string') {
      manifest[field] = resolve(manifest[field])
    }
  }
}

// Default proxy URL — set via VITE_PROXY_URL env var or falls back to this.
// Deploy your own using proxy/worker.ts on Cloudflare Workers.
const DEFAULT_PROXY = import.meta.env.VITE_PROXY_URL as string | undefined

/**
 * Fetch a CRX via the CORS proxy and extract it.
 * The proxy validates the ID and forwards to Google's update endpoint.
 */
export async function extractFromId(
  extensionId: string,
  proxyUrl?: string,
): Promise<ExtensionFiles> {
  const base = proxyUrl || DEFAULT_PROXY
  if (!base) {
    throw new Error(
      'No proxy configured. Set VITE_PROXY_URL or deploy proxy/worker.ts to Cloudflare Workers. ' +
        'Meanwhile, use file upload or paste manifest.',
    )
  }

  const url = `${base.replace(/\/+$/, '')}?id=${extensionId}`
  const response = await fetch(url)

  if (!response.ok) {
    const body = await response.text().catch(() => '')
    throw new Error(`Proxy returned ${response.status}: ${body || response.statusText}`)
  }

  const buffer = await response.arrayBuffer()
  if (buffer.byteLength < 100) {
    throw new Error('Response too small — extension may not exist or was removed from the Web Store.')
  }

  const zipData = extractZipFromCrx(buffer)
  return extractFromZip(zipData)
}
