// functions/api/dns.js — server-side DNS-over-HTTPS resolver.
//
// The browser can't always reach a public DoH endpoint: corporate proxies and
// captive networks routinely block cloudflare-dns.com / dns.google, which used
// to break every DNS-backed tool in the app even though the page itself loaded
// fine. Doing the lookup from the Cloudflare edge means the only host the
// browser talks to is our own origin (same-origin `/api/dns`), so if the page
// loaded, DNS works.
//
// Returns the upstream DoH JSON verbatim so callers keep the { Answer, Status }
// shape they already parse. No user input is logged (see PRIVACY.md), and we do
// not forward the client IP upstream.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extraHeaders },
  });
}

// Public resolvers that expose a JSON DoH API. Keyed so the propagation tool can
// ask a specific one; everything else uses the default (Cloudflare).
export const RESOLVERS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
  dnssb: 'https://doh.sb/dns-query',
};

// Record types we're willing to proxy. Keeps this from becoming an open relay
// for arbitrary/abusive query types.
export const TYPES = new Set([
  'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'PTR',
  'SOA', 'CAA', 'DS', 'DNSKEY', 'SRV', 'SPF', 'NAPTR', 'TLSA',
]);

// Hostnames, DKIM/DMARC labels (_dmarc, selector._domainkey) and reverse-DNS
// names (…​.in-addr.arpa / …​.ip6.arpa) — letters, digits, dot, hyphen, underscore.
export const NAME_RE = /^[a-zA-Z0-9._-]{1,253}$/;

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const params = new URL(request.url).searchParams;
  const name = (params.get('name') || '').trim();
  const type = (params.get('type') || 'A').trim().toUpperCase();
  const resolverKey = (params.get('resolver') || 'cloudflare').trim().toLowerCase();

  if (!NAME_RE.test(name)) return json({ error: 'Provide a valid domain name.' }, 400);
  if (!TYPES.has(type)) return json({ error: `Unsupported record type: ${type}` }, 400);
  const base = RESOLVERS[resolverKey];
  if (!base) return json({ error: `Unknown resolver: ${resolverKey}` }, 400);

  const sep = base.includes('?') ? '&' : '?';
  const url = `${base}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;

  try {
    const res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!res.ok) {
      // Log only the upstream status — never the query itself.
      return json({ error: `Upstream DNS query failed (${res.status})` }, 502, { 'Cache-Control': 'no-store' });
    }
    const data = await res.json();
    // Cache successful answers briefly at the edge; DNS TTLs are short and stale
    // results here are misleading.
    return json(data, 200, { 'Cache-Control': 'public, max-age=60' });
  } catch (e) {
    return json({ error: 'Upstream DNS query failed.' }, 502, { 'Cache-Control': 'no-store' });
  }
}
