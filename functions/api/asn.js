// functions/api/asn.js — ASN / IP details via bgpview.io. No user input is logged.

import { shapeAsn, shapeAsnFromIp, isBlockedHost } from '../../lib/parse.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  let q = (new URL(request.url).searchParams.get('q') || '').trim();
  if (!q) return json({ error: 'Missing query parameter q.' }, 400);

  const isIP = IPV4.test(q) || q.includes(':');
  if (isIP && isBlockedHost(q)) return json({ error: 'Private or reserved addresses (RFC1918) have no public ASN.' }, 400);
  const asnMatch = /^(as)?(\d{1,10})$/i.exec(q);

  try {
    if (isIP) {
      const res = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(q)}`);
      if (!res.ok) { console.error('bgpview ip failed:', res.status); return json({ error: `bgpview.io returned ${res.status}.` }, 502); }
      const d = await res.json();
      return json(shapeAsnFromIp(d, q));
    }
    if (asnMatch) {
      const num = asnMatch[2];
      const [infoRes, prefRes] = await Promise.all([
        fetch(`https://api.bgpview.io/asn/${num}`),
        fetch(`https://api.bgpview.io/asn/${num}/prefixes`),
      ]);
      if (!infoRes.ok) { console.error('bgpview asn failed:', infoRes.status); return json({ error: `bgpview.io returned ${infoRes.status}.` }, 502); }
      const infoData = await infoRes.json();
      const prefData = prefRes.ok ? await prefRes.json() : null;
      return json(shapeAsn(infoData, prefData, num));
    }
    return json({ error: 'Provide an ASN (AS13335 or 13335) or an IP address.' }, 400);
  } catch (e) {
    console.error('bgpview request error.');
    return json({ error: 'Could not reach bgpview.io. Try again shortly.' }, 502);
  }
}
