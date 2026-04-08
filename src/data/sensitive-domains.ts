import type { RiskLevel } from '../types'

export interface SensitiveDomain {
  pattern: string
  risk: RiskLevel
  description: string
}

export const sensitiveDomains: SensitiveDomain[] = [
  {
    pattern: '*.google.com',
    risk: 'high',
    description: 'Access to Google services including Gmail, Drive, and account management',
  },
  {
    pattern: 'mail.google.com',
    risk: 'critical',
    description: 'Access to Gmail — can read, send, and delete emails',
  },
  {
    pattern: 'accounts.google.com',
    risk: 'critical',
    description: 'Access to Google account management — can compromise account security',
  },
  {
    pattern: '*.facebook.com',
    risk: 'high',
    description: 'Access to Facebook — can read messages, posts, and personal data',
  },
  {
    pattern: '*.twitter.com',
    risk: 'high',
    description: 'Access to Twitter/X — can read and post on behalf of the user',
  },
  {
    pattern: '*.x.com',
    risk: 'high',
    description: 'Access to X (Twitter) — can read and post on behalf of the user',
  },
  {
    pattern: '*.github.com',
    risk: 'high',
    description: 'Access to GitHub — can read source code, tokens, and private repos',
  },
  {
    pattern: '*.banking.*',
    risk: 'critical',
    description: 'Potential access to banking sites — can read financial data',
  },
  {
    pattern: '*.paypal.com',
    risk: 'critical',
    description: 'Access to PayPal — can read financial data and initiate transactions',
  },
  {
    pattern: '*.stripe.com',
    risk: 'critical',
    description: 'Access to Stripe — can read payment and business data',
  },
  {
    pattern: '*.amazonaws.com',
    risk: 'high',
    description: 'Access to AWS services — can read cloud infrastructure data',
  },
  {
    pattern: '*.azure.com',
    risk: 'high',
    description: 'Access to Azure services — can read cloud infrastructure data',
  },
  {
    pattern: '*.slack.com',
    risk: 'high',
    description: 'Access to Slack — can read messages and workspace data',
  },
  {
    pattern: '*.linkedin.com',
    risk: 'medium',
    description: 'Access to LinkedIn — can read professional data and connections',
  },
  {
    pattern: 'chrome.google.com',
    risk: 'high',
    description: 'Access to Chrome Web Store — can interact with extension management',
  },
]

export function matchesSensitiveDomain(urlPattern: string): SensitiveDomain | null {
  // Extract the host from a URL pattern like *://*.google.com/*
  const hostMatch = urlPattern.match(/^(?:\*|https?):\/\/([^/]+)/)
  if (!hostMatch) return null
  const host = hostMatch[1].replace(/^\*\./, '')

  for (const entry of sensitiveDomains) {
    const entryHost = entry.pattern.replace(/^\*\./, '')
    if (host === entryHost || host.endsWith('.' + entryHost)) {
      return entry
    }
  }
  return null
}
