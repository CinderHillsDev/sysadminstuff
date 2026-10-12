// functions/api/trace.js — `dig +trace` from the Cloudflare edge.
//
// Walks the delegation chain iteratively (root → TLD → … → authoritative) over
// TCP/53 using the Workers connect() API, recording which server answered at
// every hop. Browsers can't speak raw DNS, so this has to run server-side.
//
// SSRF hardening: delegations are attacker-influenced (glue can name any IP), so
// every server address is checked with isBlockedHost() before connecting, and the
// destination port is always 53. No user input is logged (see PRIVACY.md).

import { connect } from 'cloudflare:sockets';
import { isBlockedHost } from '../../lib/parse.mjs';
import { TYPE_CODES, buildQuery, parseMessage, inZone, typeName } from '../../lib/dnswire.mjs';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS },
  });
}

const NAME_RE = /^[a-zA-Z0-9._-]{1,253}$/;
const ROOTS = [
  ['a.root-servers.net.', '198.41.0.4'], ['b.root-servers.net.', '170.247.170.2'],
  ['c.root-servers.net.', '192.33.4.12'], ['d.root-servers.net.', '199.7.91.13'],
  ['e.root-servers.net.', '192.203.230.10'], ['f.root-servers.net.', '192.5.5.241'],
  ['g.root-servers.net.', '192.112.36.4'], ['h.root-servers.net.', '198.97.190.53'],
  ['i.root-servers.net.', '192.36.148.17'], ['j.root-servers.net.', '192.58.128.30'],
  ['k.root-servers.net.', '193.0.14.129'], ['l.root-servers.net.', '199.7.83.42'],
  ['m.root-servers.net.', '202.12.27.33'],
].map(([name, ip]) => ({ name, ip }));

const MAX_HOPS = 12;
const MAX_CNAME_RESTARTS = 4;
const TRIES_PER_HOP = 3;
const TIMEOUT_MS = 4000;

function shuffle(a) {
  const r = [...a];
  for (let i = r.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [r[i], r[j]] = [r[j], r[i]];
  }
  return r;
}

// One non-recursive query over TCP; resolves { msg, bytes, ms }.
async function queryServer(ip, name, type) {
  const start = Date.now();
  const socket = connect({ hostname: ip, port: 53 });
  let timer;
  const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), TIMEOUT_MS); });
  const work = (async () => {
    const writer = socket.writable.getWriter();
    await writer.write(buildQuery(name, type));
    writer.releaseLock();
    const reader = socket.readable.getReader();
    let buf = new Uint8Array(0);
    for (;;) {
      if (buf.length >= 2 && buf.length >= 2 + ((buf[0] << 8) | buf[1])) break;
      const { value, done } = await reader.read();
      if (done) throw new Error('connection closed');
      const next = new Uint8Array(buf.length + value.length);
      next.set(buf); next.set(value, buf.length);
      buf = next;
      if (buf.length > 65537) throw new Error('response too large');
    }
    const len = (buf[0] << 8) | buf[1];
    return { msg: parseMessage(buf.subarray(2, 2 + len)), bytes: len, ms: Date.now() - start };
  })();
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    try { socket.close(); } catch (e) { /* ignore */ }
  }
}

// Resolve a nameserver hostname (no glue available) via public DoH.
async function resolveNsAddr(host) {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(3500),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const a = (data.Answer || []).find((x) => x.type === 1);
    return a ? a.data : null;
  } catch (e) {
    return null;
  }
}

// Last resort when no server for a zone can be queried directly from the edge
// (some operators' anycast ranges are unreachable from Workers): ask a public
// recursive resolver for the final answer and label the hop clearly as such.
async function dohFallback(name, type) {
  try {
    const t0 = Date.now();
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (typeof data.Status !== 'number') return null;
    return {
      ms: Date.now() - t0,
      rcode: data.Status,
      answers: (data.Answer || []).map((a) => ({ name: a.name, type: typeName(a.type), ttl: a.TTL, data: a.data })),
    };
  } catch (e) {
    return null;
  }
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const params = new URL(request.url).searchParams;
  const start = (params.get('name') || '').trim().replace(/\.$/, '');
  const type = (params.get('type') || 'A').trim().toUpperCase();
  if (!NAME_RE.test(start)) return json({ error: 'Provide a valid domain name.' }, 400);
  if (!TYPE_CODES[type]) return json({ error: `Unsupported record type: ${type}` }, 400);

  const hops = [];
  let qname = start;
  let candidates = shuffle(ROOTS);
  let zone = '.';
  let cnameRestarts = 0;
  let done = false;
  let error = null;

  while (!done && hops.length < MAX_HOPS) {
    let result = null;
    let server = null;
    const failures = [];
    for (const s of candidates.slice(0, TRIES_PER_HOP)) {
      let ip = s.ip;
      if (!ip) ip = await resolveNsAddr(s.name);
      if (!ip) { failures.push(`${s.name}: could not resolve`); continue; }
      if (isBlockedHost(ip)) { failures.push(`${s.name}: refused (internal address)`); continue; }
      try {
        result = await queryServer(ip, qname, type);
        server = { name: s.name, ip };
        if (result.msg.tc || result.msg.rcode === 2 || result.msg.rcode === 5) {
          failures.push(`${s.name} (${ip}): ${result.msg.tc ? 'truncated' : result.msg.rcode === 2 ? 'SERVFAIL' : 'REFUSED'}`);
          result = null;
          continue;
        }
        break;
      } catch (e) {
        failures.push(`${s.name} (${ip}): ${String((e && e.message) || e)}`);
      }
    }
    if (!result) {
      const doh = await dohFallback(qname, type);
      if (!doh) {
        error = `No server for ${zone} answered (${failures.join('; ') || 'no usable servers'}).`;
        break;
      }
      hops.push({
        zone, qname, server: { name: 'dns.google (public resolver)', ip: '' }, via: 'resolver',
        ms: doh.ms, bytes: 0, rcode: doh.rcode, aa: false,
        answers: doh.answers, authority: [], skipped: failures,
        note: `The ${zone} nameservers could not be queried directly from our edge, so the remaining delegation was resolved by a public resolver instead.`,
      });
      done = true;
      break;
    }

    const { msg } = result;
    const hop = {
      zone, qname, server, ms: result.ms, bytes: result.bytes,
      rcode: msg.rcode, aa: msg.aa,
      answers: msg.answers, authority: msg.authority,
      skipped: failures,
    };
    hops.push(hop);

    if (msg.rcode === 3) { done = true; break; }

    const hasAnswer = msg.answers.some((r) => r.type === type);
    if (hasAnswer) { done = true; break; }

    const cname = msg.answers.find((r) => r.type === 'CNAME' && r.name.toLowerCase() === qname.toLowerCase() + '.');
    if (cname) {
      if (type === 'CNAME' || ++cnameRestarts > MAX_CNAME_RESTARTS) { done = true; break; }
      qname = cname.data.replace(/\.$/, '');
      if (!NAME_RE.test(qname)) { error = 'CNAME target is not a valid name.'; break; }
      candidates = shuffle(ROOTS);
      zone = '.';
      hop.restart = qname;
      continue;
    }

    const ns = msg.authority.filter((r) => r.type === 'NS');
    if (!ns.length) { done = true; break; } // NODATA (SOA in authority) or empty answer
    const newZone = ns[0].name;
    if (!inZone(qname, newZone) || newZone.length <= zone.length) {
      error = 'Delegation did not make progress (lame or looping referral).';
      break;
    }
    const glue = new Map();
    for (const r of msg.additional) if (r.type === 'A') glue.set(r.name.toLowerCase(), r.data);
    candidates = shuffle(ns.map((r) => ({ name: r.data, ip: glue.get(r.data.toLowerCase()) || null })));
    // Prefer servers whose address we already have; resolving the rest costs a round trip.
    candidates.sort((a, b) => (b.ip ? 1 : 0) - (a.ip ? 1 : 0));
    zone = newZone;
  }
  if (!done && !error) error = `Gave up after ${MAX_HOPS} hops.`;

  const last = hops[hops.length - 1];
  return json({
    name: start,
    type,
    hops,
    final: last && done ? {
      server: last.server, rcode: last.rcode, aa: last.aa,
      answers: last.answers.filter((r) => r.type === type || r.type === 'CNAME'),
    } : null,
    error,
  });
}
