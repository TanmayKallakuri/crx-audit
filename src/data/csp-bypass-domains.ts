/**
 * Known CSP bypass domains.
 *
 * When an extension's Content Security Policy whitelists any of these domains,
 * an attacker who can inject content into the extension page can load scripts
 * from these domains to bypass the CSP.
 *
 * Primary source: Tarnish research by Matthew Bryant (2019)
 * Also: Google's CSP Evaluator project, Sebastian Lekies' CSP bypass research
 */
export interface CSPBypassDomain {
  domain: string
  technique: string
  description: string
}

export const cspBypassDomains: CSPBypassDomain[] = [
  {
    domain: 'accounts.google.com',
    technique: 'JSONP endpoint',
    description:
      'The /o/oauth2/revoke endpoint accepts a "callback" parameter that wraps the response in an arbitrary function call. Whitelisting accounts.google.com in script-src allows loading this JSONP endpoint to execute arbitrary JavaScript via the callback parameter.',
  },
  {
    domain: 'ajax.googleapis.com',
    technique: 'Script library hosting with eval gadgets',
    description:
      'Hosts JavaScript libraries (Angular, jQuery, etc.) that include templating engines with expression evaluation. An attacker can load AngularJS 1.x and use ng-app + template injection ({{constructor.constructor(\'alert(1)\')()}}) to execute arbitrary code.',
  },
  {
    domain: 'cdn.jsdelivr.net',
    technique: 'Arbitrary npm package hosting',
    description:
      'Serves any npm package as a script. An attacker can publish a malicious npm package and load it directly via cdn.jsdelivr.net/npm/malicious-package, executing arbitrary code within the CSP-protected context.',
  },
  {
    domain: 'cdnjs.cloudflare.com',
    technique: 'Script library with eval capabilities',
    description:
      'Hosts JavaScript libraries including AngularJS versions with known template injection vulnerabilities. Loading AngularJS 1.x from cdnjs allows sandbox escape and arbitrary code execution via Angular expressions.',
  },
  {
    domain: 'unpkg.com',
    technique: 'Arbitrary npm package hosting',
    description:
      'Serves any file from any npm package. Like jsdelivr, an attacker can publish and load a malicious package, or leverage existing packages with eval-like capabilities.',
  },
  {
    domain: 'www.google.com',
    technique: 'JSONP callback on multiple endpoints',
    description:
      'Multiple Google endpoints support JSONP callbacks (/complete/search, /maps/api/js). Whitelisting www.google.com allows using these JSONP endpoints to execute arbitrary JavaScript via the callback parameter.',
  },
  {
    domain: 'www.googleapis.com',
    technique: 'JSONP endpoints in multiple APIs',
    description:
      'Google API endpoints support JSONP callbacks. For example, /customsearch/v1 and /youtube/v3 endpoints accept callback parameters that wrap responses in arbitrary function calls.',
  },
  {
    domain: 'maps.googleapis.com',
    technique: 'JSONP callback in Maps API',
    description:
      'Google Maps JavaScript API endpoints accept callback parameters. The /maps/api/js endpoint wraps its response in the specified callback function, enabling arbitrary code execution.',
  },
  {
    domain: 'translate.googleapis.com',
    technique: 'JSONP callback in Translate API',
    description:
      'Google Translate API endpoints support JSONP-style callbacks that can be used to execute arbitrary JavaScript when the domain is whitelisted in script-src.',
  },
  {
    domain: 'content.googleapis.com',
    technique: 'JSONP callback in content APIs',
    description:
      'Various Google content API endpoints support JSONP callbacks, allowing script execution via the callback parameter when this domain is in the CSP.',
  },
  {
    domain: 'clients1.google.com',
    technique: 'JSONP endpoint',
    description:
      'Google client-side service endpoints that support callback parameters, enabling JSONP-based code execution when whitelisted in CSP.',
  },
  {
    domain: 'apis.google.com',
    technique: 'Google API loader with callback',
    description:
      'The Google API client loader (gapi) accepts callback functions. Loading /js/api.js with a callback parameter executes the specified function, enabling arbitrary code execution.',
  },
  {
    domain: 'storage.googleapis.com',
    technique: 'User-uploaded content serving',
    description:
      'Google Cloud Storage serves arbitrary user-uploaded files with any content type. An attacker can upload a .js file to their own GCS bucket and load it as a script when this domain is whitelisted.',
  },
  {
    domain: 'firebasestorage.googleapis.com',
    technique: 'User-uploaded content serving',
    description:
      'Firebase Storage serves arbitrary user-uploaded files. An attacker can upload malicious JavaScript to their Firebase project and load it as a script within the CSP-protected context.',
  },
  {
    domain: 'raw.githubusercontent.com',
    technique: 'Arbitrary file hosting',
    description:
      'Serves raw files from any public GitHub repository with the correct content type. An attacker can host malicious JavaScript in any repo and load it when this domain is whitelisted.',
  },
  {
    domain: 'cdn.rawgit.com',
    technique: 'GitHub content with proper MIME types',
    description:
      'Serves GitHub-hosted files with correct MIME types for script execution. Any public GitHub repository can host malicious scripts loadable through this CDN.',
  },
  {
    domain: 'gist.githubusercontent.com',
    technique: 'Arbitrary script via GitHub Gists',
    description:
      'Serves raw content from GitHub Gists. An attacker can create a Gist containing malicious JavaScript and load it as a script when this domain is in the CSP.',
  },
  {
    domain: '*.googleusercontent.com',
    technique: 'User-controlled content domains',
    description:
      'Various Google services serve user-uploaded content from *.googleusercontent.com subdomains (Blogger, Google Sites, etc.). Whitelisting this wildcard allows loading attacker-controlled JavaScript from any Google user content service.',
  },
  {
    domain: '*.appspot.com',
    technique: 'Attacker-hosted App Engine applications',
    description:
      'Google App Engine hosts arbitrary web applications at *.appspot.com. An attacker can deploy a malicious App Engine app that serves JavaScript, bypassing the CSP when this wildcard is allowed.',
  },
  {
    domain: '*.cloudfunctions.net',
    technique: 'Attacker-hosted Cloud Functions',
    description:
      'Google Cloud Functions are served from *.cloudfunctions.net. An attacker can deploy a function that returns malicious JavaScript with the correct Content-Type, bypassing CSP restrictions.',
  },
  {
    domain: '*.run.app',
    technique: 'Attacker-hosted Cloud Run services',
    description:
      'Google Cloud Run services are served from *.run.app. An attacker can deploy a Cloud Run service returning malicious JavaScript, bypassing CSP when this domain pattern is allowed.',
  },
  {
    domain: '*.firebase.com',
    technique: 'Attacker-hosted Firebase apps',
    description:
      'Firebase Hosting serves web applications from *.firebase.com and *.web.app. An attacker can deploy a Firebase app serving malicious scripts that bypass the CSP.',
  },
  {
    domain: '*.firebaseapp.com',
    technique: 'Attacker-hosted Firebase apps (legacy domain)',
    description:
      'Legacy Firebase Hosting domain. An attacker can deploy a Firebase project that serves JavaScript from *.firebaseapp.com, bypassing CSP when this pattern is whitelisted.',
  },
  {
    domain: '*.herokuapp.com',
    technique: 'Attacker-hosted Heroku apps',
    description:
      'Heroku serves arbitrary web applications from *.herokuapp.com. An attacker can deploy an app that serves malicious JavaScript, usable when this domain pattern is in the CSP.',
  },
  {
    domain: '*.netlify.app',
    technique: 'Attacker-hosted Netlify sites',
    description:
      'Netlify hosts arbitrary static sites and serverless functions at *.netlify.app. An attacker can deploy a site serving malicious JavaScript when this wildcard is whitelisted.',
  },
  {
    domain: '*.vercel.app',
    technique: 'Attacker-hosted Vercel deployments',
    description:
      'Vercel hosts arbitrary web applications at *.vercel.app. An attacker can deploy a serverless function or static file returning malicious JavaScript.',
  },
  {
    domain: '*.pages.dev',
    technique: 'Attacker-hosted Cloudflare Pages sites',
    description:
      'Cloudflare Pages hosts arbitrary static sites at *.pages.dev. An attacker can deploy a site with malicious JavaScript when this domain pattern is in the CSP.',
  },
  {
    domain: '*.workers.dev',
    technique: 'Attacker-hosted Cloudflare Workers',
    description:
      'Cloudflare Workers execute at *.workers.dev and can return arbitrary JavaScript responses. An attacker can deploy a worker serving malicious scripts.',
  },
]

/**
 * Check if a CSP source value matches a known bypass domain.
 */
export function isBypassDomain(source: string): CSPBypassDomain | null {
  const normalizedSource = source.toLowerCase().replace(/^https?:\/\//, '')
  for (const entry of cspBypassDomains) {
    if (entry.domain.startsWith('*.')) {
      const suffix = entry.domain.slice(1) // e.g., ".googleusercontent.com"
      if (
        normalizedSource.endsWith(suffix) ||
        normalizedSource.startsWith(entry.domain.slice(2))
      ) {
        return entry
      }
    } else if (
      normalizedSource === entry.domain ||
      normalizedSource.startsWith(entry.domain + '/')
    ) {
      return entry
    }
  }
  return null
}
