// functions/api/rbl.js — DNS blacklist checks across 15 zones. No user input is logged.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

const ZONES = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'dnsbl.sorbs.net',
  'spam.dnsbl.sorbs.net',
  'cbl.abuseat.org',
  'dnsbl-1.uceprotect.net',
  'dnsbl-2.uceprotect.net',
  'bl.mailspike.net',
  'hostkarma.junkemailfilter.com',
  'noptr.spamrats.com',
  'spam.spamrats.com',
  'dyna.spamrats.com',
  'ix.dnsbl.manitu.net',
  'db.wpbl.info',
];

import { isBlockedHost } from '../../lib/parse.mjs';

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

async function dohA(name) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`;
  const res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const ip = (new URL(request.url).searchParams.get('ip') || '').trim();
  const m = IPV4.exec(ip);
  if (!m) return json({ error: 'Provide a valid IPv4 address as ip.' }, 400);
  if (m.slice(1).some((o) => Number(o) > 255)) return json({ error: 'Invalid IPv4 address.' }, 400);
  if (isBlockedHost(ip)) return json({ error: 'Private or reserved addresses (RFC1918) are not tracked by blacklists.' }, 400);

  const reversed = ip.split('.').reverse().join('.');

  const results = await Promise.all(ZONES.map(async (zone) => {
    const query = `${reversed}.${zone}`;
    try {
      const data = await dohA(query);
      const answers = (data.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
      const listed = answers.length > 0;
      return { list: zone, listed, response: listed ? answers.join(', ') : '' };
    } catch (e) {
      return { list: zone, listed: false, response: 'lookup error' };
    }
  }));

  // If any zone lookup failed transiently, don't let the edge cache freeze a
  // partial result for the full TTL.
  const degraded = results.some((r) => r.response === 'lookup error');
  const res = json({ ip, checked: ZONES.length, listedCount: results.filter((r) => r.listed).length, results });
  if (degraded) res.headers.set('Cache-Control', 'no-store');
  return res;
}
