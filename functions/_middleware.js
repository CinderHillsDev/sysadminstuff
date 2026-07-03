// functions/_middleware.js — cheap, stateless hardening that runs before every
// API handler. Several endpoints proxy third-party services (crt.sh, bgpview,
// Spamhaus, Microsoft), so we don't want people driving them directly with curl
// or scripts and getting our IP rate-limited or banned. This shrinks the abuse
// surface; volume abuse still needs a Cloudflare Rate Limiting rule (see README).
//
// No user input is logged.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const MAX_URL_LENGTH = 2048;
// Browser fetches from our own pages set this; curl / other sites / direct
// navigation do not. Accept only same-origin (and same-site for subdomains).
const ALLOWED_FETCH_SITE = new Set(['same-origin', 'same-site']);

// Edge-cache successful GET responses per endpoint, so repeated lookups of the
// same domain/IP are served from Cloudflare's cache and never re-hit the
// upstream (crt.sh, bgpview, RDAP, Microsoft, …). Seconds. 0/absent = no cache.
const CACHE_TTL = {
  '/api/crtsh': 3600,
  '/api/asn': 3600,
  '/api/whois': 3600,
  '/api/tenant': 3600,
  '/api/rbl': 600,
  '/api/tls': 600,
  '/api/headers': 300,
};

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  // Only police the API surface; static assets pass straight through.
  if (!url.pathname.startsWith('/api/')) return next();

  if (url.href.length > MAX_URL_LENGTH) {
    return json({ error: 'Request URI too long.' }, 414);
  }
  if (!ALLOWED_METHODS.has(request.method)) {
    return json({ error: `Method ${request.method} not allowed.` }, 405);
  }
  // Require a same-origin browser fetch (blocks curl/scripts/other origins). The
  // preflight (OPTIONS) is exempt so CORS still works.
  if (request.method !== 'OPTIONS') {
    const site = request.headers.get('Sec-Fetch-Site');
    if (!ALLOWED_FETCH_SITE.has(site)) {
      return json({ error: 'This API is only available from the sysadminstuff.net web app.' }, 403);
    }
  }

  const ttl = CACHE_TTL[url.pathname];
  if (request.method !== 'GET' || !ttl) return next();

  // Cache keyed by URL only (so all users share it); auth headers are irrelevant.
  const cache = caches.default;
  const cacheKey = new Request(url.toString(), { method: 'GET' });
  const hit = await cache.match(cacheKey);
  if (hit) {
    const headers = new Headers(hit.headers);
    headers.set('X-Cache', 'HIT');
    return new Response(hit.body, { status: hit.status, headers });
  }

  const res = await next();
  // Don't cache responses the handler marked no-store (e.g. degraded/partial
  // results from a transient upstream failure — see rbl.js / tls.js).
  if (res.status === 200 && !/no-store/i.test(res.headers.get('Cache-Control') || '')) {
    const body = await res.arrayBuffer();
    const headers = new Headers(res.headers);
    headers.set('Cache-Control', `public, max-age=${ttl}`);
    headers.set('X-Cache', 'MISS');
    const out = new Response(body, { status: 200, headers });
    context.waitUntil(cache.put(cacheKey, out.clone()));
    return out;
  }
  return res; // never cache errors (4xx/5xx)
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
