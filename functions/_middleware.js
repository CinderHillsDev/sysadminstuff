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
  return next();
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
