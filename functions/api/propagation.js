// functions/api/propagation.js — query one DNS record across several diverse
// public resolvers, server-side. Browsers can't do this directly: most resolvers
// don't support the JSON DoH API or don't send CORS headers. Server-side, neither
// limitation applies, so we get real operator diversity.
//
// No user input is logged.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

// All of these speak the Google-style JSON API (name/type query params,
// { Answer: [{ name, type, TTL, data }] } response). CORS is irrelevant here.
const RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
  { name: 'Quad9', url: 'https://dns.quad9.net:5053/dns-query' },
  { name: 'DNS.SB', url: 'https://doh.sb/dns-query' },
  { name: 'AliDNS', url: 'https://dns.alidns.com/resolve' },
  { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query' },
];

const TYPE_NUM = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV' };
const ALLOWED_TYPES = new Set(['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'PTR', 'SOA', 'SRV']);

async function queryResolver(resolver, name, type) {
  const sep = resolver.url.includes('?') ? '&' : '?';
  const url = `${resolver.url}${sep}name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: controller.signal });
    if (!res.ok) return { resolver: resolver.name, ok: false, answers: [], ttl: '' };
    const data = await res.json();
    const rows = (data.Answer || []).filter((a) => (TYPE_NUM[a.type] || String(a.type)) === type);
    return {
      resolver: resolver.name,
      ok: true,
      answers: rows.map((a) => String(a.data)).sort(),
      ttl: rows[0] ? rows[0].TTL : '',
    };
  } catch (e) {
    return { resolver: resolver.name, ok: false, answers: [], ttl: '' };
  } finally {
    clearTimeout(timer);
  }
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const params = new URL(request.url).searchParams;
  const name = (params.get('name') || '').trim();
  const type = (params.get('type') || 'A').trim().toUpperCase();
  if (!name) return json({ error: 'Missing name parameter.' }, 400);
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) return json({ error: 'Invalid name.' }, 400);
  if (!ALLOWED_TYPES.has(type)) return json({ error: `Unsupported record type ${type}.` }, 400);

  const results = await Promise.all(RESOLVERS.map((r) => queryResolver(r, name, type)));

  // Consistency: do all reachable resolvers that returned something agree?
  const signatures = results.filter((r) => r.ok && r.answers.length).map((r) => r.answers.join(', '));
  const distinct = new Set(signatures);
  const consistent = signatures.length > 0 && distinct.size === 1
    && results.filter((r) => r.ok).every((r) => r.answers.join(', ') === signatures[0]);

  return json({ name, type, consistent, resolvers: results });
}
