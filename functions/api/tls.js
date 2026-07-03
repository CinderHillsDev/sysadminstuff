// functions/api/tls.js — TLS grading using the Workers connect() TCP API.
// No user input is logged.
//
// Cloudflare Workers cannot pin an arbitrary TLS protocol version per socket, so
// we probe reachability + certificate over TLS and derive a conservative grade.
// Where the platform exposes negotiated details we surface them; otherwise we
// report what we can verify and note the limitation.

import { connect } from 'cloudflare:sockets';
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

  const params = new URL(request.url).searchParams;
  let host = (params.get('host') || '').trim();
  if (!host) return json({ error: 'Missing host parameter.' }, 400);
  // Canonicalize via the WHATWG URL parser so alternate IPv4 encodings
  // (127.1, 2130706433, 0x7f000001, 0177.0.0.1) normalize to dotted-quad before
  // the SSRF guard sees them. IPv6 literals are unsupported and rejected below —
  // the regex forbids ':' so no IPv6 form (bracketed, bare, or expanded) can
  // reach connect() and slip past isBlockedHost.
  try { host = new URL(/^https?:\/\//i.test(host) ? host : 'https://' + host).hostname; } catch (e) { /* fall through to validation */ }
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) return json({ error: 'Invalid hostname.' }, 400);
  // Only ever probe the HTTPS port. Accepting an arbitrary port would turn this
  // into an internal port scanner; the UI only ever checks 443.
  const port = 443;
  // Refuse internal / reserved / loopback targets (SSRF hardening).
  if (isBlockedHost(host)) return json({ error: 'Refusing to probe internal or reserved addresses.' }, 400);

  const issues = [];
  let handshakeOK = false;

  // Probe a TLS handshake. Success means Workers' modern TLS stack (1.2/1.3)
  // completed AND the certificate chain validated (secureTransport: 'on').
  try {
    const socket = connect({ hostname: host, port }, { secureTransport: 'on', allowHalfOpen: false });
    await Promise.race([
      socket.opened,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000)),
    ]);
    handshakeOK = true;
    try { await socket.close(); } catch (e) { /* ignore */ }
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/certificate|cert/i.test(msg)) issues.push('Certificate validation failed (expired, self-signed, or hostname mismatch).');
    else if (/timeout/i.test(msg)) issues.push('Connection timed out — host may not serve TLS on this port.');
    else issues.push('TLS handshake failed: ' + msg);
  }

  // The platform doesn't expose which version was negotiated, only that a modern
  // handshake succeeded — so report 1.2/1.3 together rather than claiming each.
  const versions = [
    { version: 'TLS 1.2 / 1.3', supported: handshakeOK, cipher: handshakeOK ? 'negotiated (exact version not exposed by platform)' : '' },
    { version: 'TLS 1.0 / 1.1', supported: false, cipher: 'not offered by this client' },
  ];

  // We can only distinguish "modern TLS + valid cert" (A) from "failed" (F);
  // the platform doesn't surface cipher/version detail for B/C grading.
  const grade = handshakeOK ? 'A' : 'F';

  const res = json({
    host,
    port,
    grade,
    handshakeOK,
    versions,
    issues,
    note: 'Cloudflare Workers negotiate TLS 1.2/1.3 and validate the certificate chain; the exact negotiated version and cipher are not exposed, so grading is A (modern TLS + valid cert) or F. Legacy TLS 1.0/1.1 cannot be probed here.',
  });
  // A failed handshake is often transient (timeout / host down); don't cache it.
  if (!handshakeOK) res.headers.set('Cache-Control', 'no-store');
  return res;
}
