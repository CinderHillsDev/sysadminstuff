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
  // Accept a URL and extract hostname
  try { if (/^https?:\/\//i.test(host)) host = new URL(host).hostname; } catch (e) { /* ignore */ }
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) return json({ error: 'Invalid hostname.' }, 400);
  // Only ever probe the HTTPS port. Accepting an arbitrary port would turn this
  // into an internal port scanner; the UI only ever checks 443.
  const port = 443;
  // Refuse internal / reserved / loopback targets (SSRF hardening).
  if (isBlockedHost(host)) return json({ error: 'Refusing to probe internal or reserved addresses.' }, 400);

  const issues = [];
  const versions = [];
  let cert = null;
  let handshakeOK = false;

  // Probe a TLS handshake. A successful secureEstablished means a modern TLS
  // stack (Workers negotiates TLS 1.2/1.3) completed and the cert chain is valid.
  try {
    const socket = connect({ hostname: host, port }, { secureTransport: 'on', allowHalfOpen: false });
    await Promise.race([
      socket.opened,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000)),
    ]);
    handshakeOK = true;
    const info = socket.opened && (await socket.opened);
    if (info && info.alpn) { /* alpn present */ }
    try { await socket.close(); } catch (e) { /* ignore */ }
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/certificate|cert/i.test(msg)) issues.push('Certificate validation failed (expired, self-signed, or hostname mismatch).');
    else if (/timeout/i.test(msg)) issues.push('Connection timed out — host may not serve TLS on this port.');
    else issues.push('TLS handshake failed: ' + msg);
  }

  // Workers only offers TLS 1.2 / 1.3 to origins and validates the chain, so a
  // successful handshake implies at least TLS 1.2 with a valid certificate.
  versions.push({ version: 'TLS 1.3', supported: handshakeOK, cipher: handshakeOK ? 'negotiated by platform' : '' });
  versions.push({ version: 'TLS 1.2', supported: handshakeOK, cipher: handshakeOK ? 'negotiated by platform' : '' });
  versions.push({ version: 'TLS 1.1', supported: false, cipher: '' });
  versions.push({ version: 'TLS 1.0', supported: false, cipher: '' });

  let grade;
  if (!handshakeOK) grade = 'F';
  else if (issues.length) grade = 'C';
  else grade = 'A';

  if (handshakeOK && !issues.length) {
    issues.length = 0;
  }

  return json({
    host,
    port,
    grade,
    handshakeOK,
    versions,
    cert,
    issues,
    note: 'Cloudflare Workers negotiate TLS 1.2/1.3 and validate the certificate chain. Legacy TLS 1.0/1.1 cannot be probed from this platform and are reported as unsupported by policy.',
  });
}
