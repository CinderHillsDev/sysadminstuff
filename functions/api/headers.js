// functions/api/headers.js — fetch a URL server-side, follow redirects hop by hop.
// No user input is logged. The user's IP is never forwarded upstream.

import { isBlockedHost } from '../../lib/parse.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

const MAX_HOPS = 10;

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  let target = (new URL(request.url).searchParams.get('url') || '').trim();
  if (!target) return json({ error: 'Missing url parameter.' }, 400);
  if (!/^https?:\/\//i.test(target)) target = `https://${target}`;

  let url;
  try { url = new URL(target); } catch (e) { return json({ error: 'Invalid URL.' }, 400); }
  if (!['http:', 'https:'].includes(url.protocol)) return json({ error: 'Only http and https are supported.' }, 400);
  // Block requests to internal/loopback hosts (SSRF guard).
  if (isBlockedHost(url.hostname)) return json({ error: 'Refusing to fetch internal or reserved addresses.' }, 400);

  const chain = [];
  let current = url.toString();

  try {
    for (let i = 0; i < MAX_HOPS; i++) {
      const res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': 'sysadminstuff.net header inspector' },
      });
      const headers = {};
      for (const [k, v] of res.headers.entries()) headers[k] = v;

      chain.push({ url: current, status: res.status, headers });

      const isRedirect = res.status >= 300 && res.status < 400 && headers.location;
      if (!isRedirect) break;

      let next;
      try { next = new URL(headers.location, current).toString(); } catch (e) { break; }
      if (isBlockedHost(new URL(next).hostname)) break;
      current = next;
    }
    return json(chain);
  } catch (e) {
    console.error('Header fetch failed.');
    return json({ error: 'Could not fetch the target URL. It may be unreachable or blocking requests.' }, 502);
  }
}
