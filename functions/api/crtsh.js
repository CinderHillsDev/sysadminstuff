// functions/api/crtsh.js — proxy crt.sh certificate-transparency search.
// crt.sh sends no CORS headers, so a browser can't call it directly. No user
// input is logged.

import { isBlockedHost } from '../../lib/parse.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const q = (new URL(request.url).searchParams.get('q') || '').trim();
  if (!q) return json({ error: 'Missing query parameter q.' }, 400);
  if (!/^[a-zA-Z0-9.*_-]+$/.test(q) || isBlockedHost(q)) return json({ error: 'Enter a valid domain.' }, 400);

  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json`, {
      headers: { Accept: 'application/json', 'User-Agent': 'sysadminstuff.net cert search' },
    });
    if (!res.ok) {
      console.error('crt.sh returned:', res.status);
      return json({ error: `crt.sh returned ${res.status}. It is often slow or rate-limited — try again shortly.` }, 502);
    }
    const text = await res.text();
    // crt.sh returns 200 with an empty body when a domain has zero certs.
    if (!text.trim()) return json([]);
    let data;
    try { data = JSON.parse(text); } catch (e) { return json({ error: 'crt.sh returned an unexpected response. Try again shortly.' }, 502); }
    return json(data);
  } catch (e) {
    console.error('crt.sh request failed.');
    return json({ error: 'Could not reach crt.sh. Try again in a moment.' }, 502);
  }
}
