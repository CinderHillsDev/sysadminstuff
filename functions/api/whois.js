// functions/api/whois.js — RDAP proxy (avoids CORS). No user input is ever logged.

import { parseRdapDomain, parseRdapIP, isBlockedHost } from '../../lib/parse.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const q = (new URL(request.url).searchParams.get('q') || '').trim();
  if (!q) return json({ error: 'Missing query parameter q.' }, 400);

  const isIP = IPV4.test(q) || q.includes(':');
  if (isIP && isBlockedHost(q)) return json({ error: 'Private or reserved addresses (RFC1918) are not publicly registered.' }, 400);
  const target = isIP
    ? `https://rdap.org/ip/${encodeURIComponent(q)}`
    : `https://rdap.org/domain/${encodeURIComponent(q)}`;

  try {
    const res = await fetch(target, {
      redirect: 'follow',
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'sysadminstuff.net RDAP client',
      },
    });
    if (!res.ok) {
      // No user data in log.
      console.error('RDAP fetch failed:', res.status);
      return json({ error: `Registry returned ${res.status}. Some registries limit RDAP access.` }, 502);
    }
    const data = await res.json();
    return json(isIP ? parseRdapIP(data) : parseRdapDomain(data));
  } catch (e) {
    console.error('RDAP request error.');
    return json({ error: 'Could not reach the RDAP registry. Try again shortly.' }, 502);
  }
}
