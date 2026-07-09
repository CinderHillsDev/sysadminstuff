// functions/api/dig.js — query a caller-chosen nameserver over DNS/TCP :53
// (like `dig @ns`), which browsers can't do themselves. No user input is
// ever logged. Returns the same JSON shape as DoH: { Status, Answer: [...] }.

import { connect } from 'cloudflare:sockets';
import { isBlockedHost } from '../../lib/parse.mjs';
import { TYPE_NUMS, RCODES, encodeQuery, parseResponse } from '../../lib/dnswire.mjs';

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

// Query names may contain underscores (_dmarc, _sip._tls) and arpa labels.
const NAME_RE = /^[a-z0-9._-]{1,253}$/i;
// Nameserver: hostname or IP literal (IPv6 allowed bare or bracketed).
const NS_RE = /^\[?[a-z0-9:.-]{1,253}\]?$/i;
const MAX_MSG = 65535;

async function dnsTcpQuery(ns, name, typeNum, timeoutMs = 8000) {
  const socket = connect({ hostname: ns.replace(/^\[|\]$/g, ''), port: 53 });
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
  });
  const work = (async () => {
    const id = Math.floor(Math.random() * 0x10000);
    const msg = encodeQuery(name, typeNum, id);
    // TCP framing: 2-byte big-endian length prefix.
    const framed = new Uint8Array(2 + msg.length);
    framed[0] = msg.length >> 8;
    framed[1] = msg.length & 0xff;
    framed.set(msg, 2);
    const writer = socket.writable.getWriter();
    await writer.write(framed);
    writer.releaseLock();

    const reader = socket.readable.getReader();
    const chunks = [];
    let total = 0;
    let expect = -1;
    for (;;) {
      if (expect < 0 && total >= 2) {
        const head = chunks[0].length >= 2 ? chunks[0] : concat(chunks, total);
        expect = (head[0] << 8) | head[1];
        if (expect > MAX_MSG) throw new Error('oversized');
      }
      if (expect >= 0 && total >= expect + 2) break;
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > MAX_MSG + 2) throw new Error('oversized');
    }
    const all = concat(chunks, total);
    if (expect < 0 || total < expect + 2) throw new Error('short read');
    const body = all.subarray(2, 2 + expect);
    const parsed = parseResponse(body);
    if (parsed.id !== id) throw new Error('id mismatch');
    return parsed;
  })();
  try {
    return await Promise.race([work, timeout]);
  } finally {
    clearTimeout(timer);
    try { socket.close(); } catch (e) { /* already closed */ }
  }
}

function concat(chunks, total) {
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf;
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

  const params = new URL(request.url).searchParams;
  const name = (params.get('name') || '').trim();
  const type = (params.get('type') || 'A').trim().toUpperCase();
  const ns = (params.get('ns') || '').trim();

  if (!name || !NAME_RE.test(name)) return json({ error: 'Missing or invalid name.' }, 400);
  const typeNum = TYPE_NUMS[type];
  if (!typeNum) return json({ error: `Unsupported record type ${type}.` }, 400);
  if (!ns || !NS_RE.test(ns)) return json({ error: 'Missing or invalid nameserver.' }, 400);
  if (isBlockedHost(ns)) return json({ error: 'That nameserver is a private or reserved address.' }, 400);

  try {
    const parsed = await dnsTcpQuery(ns, name, typeNum);
    return json({
      Status: parsed.rcode,
      StatusName: parsed.rcodeName,
      Server: ns,
      Answer: parsed.answers,
    });
  } catch (e) {
    // No user data in log.
    console.error('dig query failed.');
    return json({ error: 'Could not get an answer from that nameserver (unreachable, refused, or timed out).' }, 424);
  }
}
