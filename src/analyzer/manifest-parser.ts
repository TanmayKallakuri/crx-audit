export interface ContentScriptEntry {
  matches: string[]
  js: string[]
}

export interface ParsedManifest {
  manifestVersion: number
  name: string
  version: string
  permissions: string[]
  optionalPermissions: string[]
  hostPermissions: string[]
  optionalHostPermissions: string[]
  contentScripts: ContentScriptEntry[]
  backgroundScripts: string[]
  serviceWorker: string | null
  webAccessibleResources: string[]
  csp: string | null
  externallyConnectable: {
    ids?: string[]
    matches?: string[]
    acceptsTlsChannelId?: boolean
  } | null
}

function asStringArray(val: unknown): string[] {
  if (!Array.isArray(val)) return []
  return val.filter((v): v is string => typeof v === 'string')
}

export function parseManifest(manifest: Record<string, unknown>): ParsedManifest {
  const manifestVersion = typeof manifest.manifest_version === 'number' ? manifest.manifest_version : 2
  const name = typeof manifest.name === 'string' ? manifest.name : 'Unknown'
  const version = typeof manifest.version === 'string' ? manifest.version : '0.0.0'

  // Permissions — separate host permissions from API permissions in MV2
  const rawPermissions = asStringArray(manifest.permissions)
  const isUrlPattern = (p: string) => /^(<all_urls>|(\*|https?|ftp|file):\/\/)/.test(p)

  let permissions: string[]
  let hostPermissions: string[]
  if (manifestVersion >= 3) {
    permissions = rawPermissions
    hostPermissions = asStringArray(manifest.host_permissions)
  } else {
    permissions = rawPermissions.filter((p) => !isUrlPattern(p))
    hostPermissions = rawPermissions.filter((p) => isUrlPattern(p))
  }

  const optionalPermissions = asStringArray(manifest.optional_permissions)
  const optionalHostPermissions = asStringArray(manifest.optional_host_permissions)

  // Content scripts
  const contentScripts: ContentScriptEntry[] = []
  const rawCS = manifest.content_scripts
  if (Array.isArray(rawCS)) {
    for (const cs of rawCS) {
      if (cs && typeof cs === 'object') {
        const entry = cs as Record<string, unknown>
        contentScripts.push({
          matches: asStringArray(entry.matches),
          js: asStringArray(entry.js),
        })
      }
    }
  }

  // Background
  let backgroundScripts: string[] = []
  let serviceWorker: string | null = null
  const bg = manifest.background as Record<string, unknown> | undefined
  if (bg && typeof bg === 'object') {
    backgroundScripts = asStringArray(bg.scripts)
    if (typeof bg.service_worker === 'string') {
      serviceWorker = bg.service_worker
    }
  }

  // Web-accessible resources — normalize MV2 (string[]) and MV3 (object[]) formats
  const webAccessibleResources: string[] = []
  const war = manifest.web_accessible_resources
  if (Array.isArray(war)) {
    for (const entry of war) {
      if (typeof entry === 'string') {
        // MV2 format
        webAccessibleResources.push(entry)
      } else if (entry && typeof entry === 'object') {
        // MV3 format: { resources: string[], matches: string[] }
        const obj = entry as Record<string, unknown>
        webAccessibleResources.push(...asStringArray(obj.resources))
      }
    }
  }

  // CSP
  let csp: string | null = null
  const rawCSP = manifest.content_security_policy
  if (typeof rawCSP === 'string') {
    csp = rawCSP
  } else if (rawCSP && typeof rawCSP === 'object') {
    const cspObj = rawCSP as Record<string, unknown>
    if (typeof cspObj.extension_pages === 'string') {
      csp = cspObj.extension_pages
    }
  }

  // Externally connectable
  let externallyConnectable: ParsedManifest['externallyConnectable'] = null
  const ec = manifest.externally_connectable as Record<string, unknown> | undefined
  if (ec && typeof ec === 'object') {
    externallyConnectable = {
      ids: ec.ids ? asStringArray(ec.ids) : undefined,
      matches: ec.matches ? asStringArray(ec.matches) : undefined,
      acceptsTlsChannelId:
        typeof ec.accepts_tls_channel_id === 'boolean' ? ec.accepts_tls_channel_id : undefined,
    }
  }

  return {
    manifestVersion,
    name,
    version,
    permissions,
    optionalPermissions,
    hostPermissions,
    optionalHostPermissions,
    contentScripts,
    backgroundScripts,
    serviceWorker,
    webAccessibleResources,
    csp,
    externallyConnectable,
  }
}
