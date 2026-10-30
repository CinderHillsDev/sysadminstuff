// mailcheck-probe — a throwaway diagnostic Worker, not part of the site.
//
// Purpose: settle, with one real message, what an Email Routing Worker actually
// gets to work with — because the docs do not say whether the connecting IP or
// any Authentication-Results header survives to the email() handler. The answer
// decides how much of a "send us an email and we check it" feature can be
// honest rather than guessy.
//
// It stores *headers and hashes only* — never the body, never an attachment —
// in your own account's KV, with a 24 h TTL, behind a secret key. See
// mailcheck-probe/README.md for the ten-minute setup and how to read the output.

import { summarizeHeaders, probeConclusions } from '../parse.mjs';

// Anything bigger is not worth hashing inside a 10 ms CPU budget; the probe
// records that it skipped rather than silently failing.
const MAX_HASH_BYTES = 2 * 1024 * 1024;
const RECORD_TTL = 86400; // 24 h — long enough to look, short enough to not matter

async function sha256Hex(buf) {
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function localPart(address) {
  const s = String(address || '');
  const at = s.lastIndexOf('@');
  return (at >= 0 ? s.slice(0, at) : s).toLowerCase();
}

// A recipient like `a1b2c3d4@mailcheck.example.net` is a request for a separate
// record; anything else just overwrites `p:latest`.
function tokenOf(address) {
  const lp = localPart(address).replace(/^(check|probe|test)\+/, '');
  return /^[0-9a-f]{8,32}$/.test(lp) ? lp : '';
}

export default {
  async email(message, env) {
    // Never throw from an email handler: an exception turns into an SMTP failure
    // the test sender sees as a bounce. Anything unexpected is recorded instead.
    const record = {
      at: new Date().toISOString(),
      recipient: message.to,
      envelopeFrom: message.from,
      rawSize: message.rawSize,
      canBeForwarded: message.canBeForwarded,
      headers: {},
      body: null,
      error: '',
    };

    try {
      message.headers.forEach((value, name) => {
        // Repeated headers (Received, DKIM-Signature) arrive as one comma-ish
        // string from Headers.get, so accumulate per name to keep the chain.
        const key = name.toLowerCase();
        if (record.headers[key] === undefined) record.headers[key] = value;
        else if (Array.isArray(record.headers[key])) record.headers[key].push(value);
        else record.headers[key] = [record.headers[key], value];
      });

      if (record.rawSize > MAX_HASH_BYTES) {
        record.body = { bytes: record.rawSize, skipped: 'over size cap' };
      } else {
        const buf = await new Response(message.raw).arrayBuffer();
        record.body = { bytes: buf.byteLength, sha256: await sha256Hex(buf) };
      }

      record.summary = summarizeHeaders(record.headers);
    } catch (e) {
      record.error = String((e && e.message) || e);
    }

    try {
      const payload = JSON.stringify(record);
      await env.PROBE.put('p:latest', payload, { expirationTtl: RECORD_TTL });
      const token = tokenOf(message.to);
      if (token) await env.PROBE.put(`p:${token}`, payload, { expirationTtl: RECORD_TTL });
    } catch (e) {
      // A KV write failure must not bounce the sender either.
      record.storeError = String((e && e.message) || e);
    }

    // Deliberately no forward() and no setReject(): the message is accepted and
    // then dropped. Nothing is delivered to anyone, and no copy is retained
    // beyond the header record above.
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/last')) {
      // Compare without leaking position via early exit; this is a diagnostic
      // endpoint, but it does front someone else's mail metadata.
      const want = String(env.PROBE_KEY || '');
      const got = String(url.searchParams.get('key') || '');
      if (!want || !equalStrings(want, got)) return text('Forbidden', 403);
      const token = tokenOf(url.searchParams.get('to') || '') || 'latest';
      const stored = await env.PROBE.get(`p:${token}`);
      if (!stored) return text(`No probe record under "${token}" yet.`, 404);
      const record = JSON.parse(stored);
      const conclusions = probeConclusions(record);
      if (url.searchParams.get('full') === '1') return json({ record, conclusions });
      // Default view: the answers, the header names, and the parsed chain —
      // enough to decide, without dumping a stranger's full headers.
      const { headers, ...rest } = record;
      return json({
        conclusions,
        record: Object.assign({}, rest, { headerCount: Object.keys(headers || {}).length, headerNames: (rest.summary || {}).headerNames || [] }),
      });
    }
    if (url.pathname === '/health') return text('probe ready');
    return text([
      'mailcheck-probe: no HTTP surface needed.',
      'Send an email to this domain, then read it back:',
      `  ${url.origin}/last?key=<PROBE_KEY>`,
      `  ${url.origin}/last?key=<PROBE_KEY>&full=1      (includes every header value)`,
      `  ${url.origin}/last?key=<PROBE_KEY>&to=<token>   (a specific test address)`,
    ].join('\n'));
  },
};

function equalStrings(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function text(body, status = 200) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), { status, headers: { 'Content-Type': 'application/json' } });
}
