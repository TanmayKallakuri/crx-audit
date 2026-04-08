/**
 * Cloudflare Worker — CRX download proxy.
 *
 * Accepts a Chrome extension ID, validates it,
 * fetches the CRX from Google's update endpoint,
 * and returns it with CORS headers.
 *
 * This is NOT an open proxy. It only forwards to
 * one hardcoded Google endpoint and only accepts
 * valid 32-char extension IDs (a-p).
 */

const CRX_ENDPOINT = 'https://clients2.google.com/service/update2/crx'
const ID_PATTERN = /^[a-p]{32}$/

export default {
  async fetch(request: Request): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() })
    }

    if (request.method !== 'GET') {
      return error(405, 'GET only')
    }

    const url = new URL(request.url)
    const id = url.searchParams.get('id')

    if (!id || !ID_PATTERN.test(id)) {
      return error(400, 'Invalid extension ID. Must be 32 lowercase a-p characters.')
    }

    const crxUrl = `${CRX_ENDPOINT}?response=redirect&acceptformat=crx2,crx3&prodversion=131.0&x=id%3D${id}%26installsource%3Dondemand%26uc`

    const upstream = await fetch(crxUrl, { redirect: 'follow' })

    if (!upstream.ok) {
      return error(upstream.status, `Google returned ${upstream.status}`)
    }

    return new Response(upstream.body, {
      status: 200,
      headers: {
        ...corsHeaders(),
        'content-type': 'application/x-chrome-extension',
        'cache-control': 'public, max-age=3600',
      },
    })
  },
}

function corsHeaders(): Record<string, string> {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-max-age': '86400',
  }
}

function error(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders(), 'content-type': 'application/json' },
  })
}
