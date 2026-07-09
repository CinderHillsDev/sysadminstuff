// functions/api/whois.js — RDAP proxy (avoids CORS). No user input is ever logged.
//
// Lookup order for domains:
//   1. RDAP via rdap.org (plus a few registries missing from the IANA
//      bootstrap — see RDAP_BOOTSTRAP_OVERRIDES in lib/parse.mjs).
//   2. If the TLD has no RDAP at all, classic whois over TCP 43: ask
//      whois.iana.org for the TLD's referral server, then query it and
//      return the raw text.

import { connect } from 'cloudflare:sockets';
import { parseRdapDomain, parseRdapIP, isBlockedHost, rdapTarget, rdapFailure, parseWhoisReferral } from '../../lib/parse.mjs';

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
// Strict enough to be safe to write into a TCP whois query verbatim.
const WHOIS_SAFE = /^[a-z0-9.-]{1,253}$/i;
const WHOIS_MAX_BYTES = 65536;

async function whoisQuery(server, query, timeoutMs = 10000) {
  const socket = connect({ hostname: server, port: 43 });
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('whois timeout')), timeoutMs);
  });
  const work = (async () => {
    const writer = socket.writable.getWriter();
    await writer.write(new TextEncoder().encode(query + '\r\n'));
    // Don't close the writable side — workerd tears down the whole socket on
    // FIN. Whois servers reply after CRLF and close the connection themselves.
    writer.releaseLock();
    const reader = socket.readable.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total >= WHOIS_MAX_BYTES) break;
    }
    const buf = new Uint8Array(Math.min(total, WHOIS_MAX_BYTES));
    let off = 0;
    for (const c of chunks) {
      const n = Math.min(c.length, buf.length - off);
      buf.set(c.subarray(0, n), off);
      off += n;
      if (off >= buf.length) break;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(buf);
  })();
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    try { socket.close(); } catch (e) { /* already closed */ }
  }
}

// Classic whois for TLDs with no RDAP. Returns { raw, source } or null.
async function whoisFallback(q) {
  if (!WHOIS_SAFE.test(q)) return null;
  const tld = q.toLowerCase().replace(/\.$/, '').split('.').pop();
  try {
    const server = parseWhoisReferral(await whoisQuery('whois.iana.org', tld));
    if (!server) return null;
    const raw = (await whoisQuery(server, q)).trim();
    if (!raw) return null;
    return { raw, source: server };
  } catch (e) {
    // No user data in log.
    console.error('whois fallback failed.');
    return null;
  }
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const q = (new URL(request.url).searchParams.get('q') || '').trim();
  if (!q) return json({ error: 'Missing query parameter q.' }, 400);

  const m4 = IPV4.exec(q);
  const isIP = (m4 && m4.slice(1).every((o) => Number(o) <= 255)) || q.includes(':');
  if (isIP && isBlockedHost(q)) return json({ error: 'Private or reserved addresses (RFC1918) are not publicly registered.' }, 400);

  try {
    const res = await fetch(rdapTarget(q, isIP), {
      redirect: 'follow',
      headers: {
        Accept: 'application/rdap+json, application/json',
        'User-Agent': 'sysadminstuff.net RDAP client',
      },
    });
    if (!res.ok) {
      // No user data in log.
      console.error('RDAP fetch failed:', res.status);
      // 404 straight from rdap.org (no redirect happened) means the TLD has
      // no RDAP service in the IANA bootstrap — try classic whois instead.
      let bootstrapMiss = false;
      try { bootstrapMiss = new URL(res.url).hostname === 'rdap.org'; } catch (e) { /* ignore */ }
      if (!isIP && res.status === 404 && bootstrapMiss) {
        const fallback = await whoisFallback(q);
        if (fallback) return json(fallback);
      }
      const fail = rdapFailure(res.status, res.url, q, isIP);
      return json({ error: fail.error }, fail.status);
    }
    const data = await res.json();
    return json(isIP ? parseRdapIP(data) : parseRdapDomain(data));
  } catch (e) {
    console.error('RDAP request error.');
    // 424, not 502 — Cloudflare swallows 502/504 bodies (see rdapFailure).
    return json({ error: 'Could not reach the RDAP registry. Try again shortly.' }, 424);
  }
}
