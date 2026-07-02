// functions/_middleware.js — cheap, stateless hardening that runs before every
// API handler. This is NOT a rate limiter (that needs shared state — configure a
// Cloudflare Rate Limiting rule on /api/* in the dashboard; see README). It just
// shrinks the abuse surface: only read methods on the API, and reject absurd URLs.
//
// No user input is logged.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const MAX_URL_LENGTH = 2048;

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
  return next();
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
