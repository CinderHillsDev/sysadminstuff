// mailcheck-probe/parse.mjs — pure header forensics for the probe.
//
// No Workers APIs, no DOM, no network: this file is imported by the probe
// Worker *and* by tests/smoke.mjs, so the logic that decides the shape of the
// real "send us an email" feature is covered by unit tests from day one.

// Headers that tell us anything about how the message was authenticated.
const AUTH_HEADERS = [
  'authentication-results', 'received-spf', 'arc-authentication-results',
  'arc-seal', 'arc-message-signature', 'dkim-signature', 'return-path', 'sender',
  'list-unsubscribe', 'message-id', 'date', 'received',
];

// IPv4 or a bracketed/colon IPv6, loosely: the probe only needs to show us which
// addresses a Received chain mentions, and core.js's tested isIPv4/isIPv6 do the
// strict work later for the real feature.
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;

function uniq(list) {
  return [...new Set(list.filter(Boolean))];
}

export function ipsInText(text) {
  const s = String(text || '');
  const v4 = s.match(IPV4_RE) || [];
  const v6 = s.match(IPV6_RE) || [];
  // Received comments contain timestamps ("for <x>; Tue, 1 Jan 2024 …") and
  // version strings, so drop anything with an octet > 255 or a 4-part run that
  // is really a date fragment.
  return uniq([...v4.filter((o) => o.split('.').every((p) => Number(p) <= 255)), ...v6]);
}

// One RFC 5321 Received line into the parts we care about. Most useful for
// deciding *who really handed this message to Cloudflare*.
// Recover the individual values of a repeated header.
//
// `Headers` follows the WHATWG rule of joining repeated headers into one string
// separated by ", " — so a real 5-hop Received chain arrives as a single value
// unless it keeps its newlines. Splitting on a comma only when another line's
// keyword follows it avoids shredding the date ("; Mon, 1 Jan 2024").
export function splitList(value, startsWith) {
  if (Array.isArray(value)) {
    const flat = [];
    value.forEach((v) => flat.push(...splitList(v, startsWith)));
    return flat;
  }
  const s = String(value == null ? '' : value);
  if (!s) return [];
  if (/\r?\n/.test(s)) return s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  if (startsWith) {
    const parts = s.split(new RegExp(`,(?=\\s*(?:${startsWith})\\s*)`, 'i'));
    if (parts.length > 1) return parts.map((x) => x.trim()).filter(Boolean);
  }
  return [s.trim()].filter(Boolean);
}

export function parseReceived(line) {
  const s = String(line || '').trim();
  const hop = { raw: s, from: '', by: '', comments: [], ips: [], for: '', with: '' };
  const from = /from\s+([^by;]+)/i.exec(s);
  const by = /\bby\s+([A-Za-z0-9._-]+)/i.exec(s);
  const forM = /\bfor\s+<?([^>(;]+?)>?(\s*;|\s*$)/i.exec(s);
  const withM = /\bwith\s+([A-Za-z0-9._/-]+)/i.exec(s);
  if (from) hop.from = from[1].trim().replace(/\s*\(/g, '').replace(/\)$/, '');
  if (by) hop.by = by[1];
  if (forM) hop.for = forM[1].trim();
  if (withM) hop.with = withM[1];
  // Bracketed comments: `(mail.example.com [203.0.113.9])` — the only place a
  // sending MTA's real address usually appears.
  hop.comments = (s.match(/\([^)]*\)/g) || []).map((c) => c.slice(1, -1).trim());
  hop.ips = ipsInText(hop.comments.join(' ') + ' ' + hop.by + ' ' + hop.from);
  return hop;
}

// Parse the list-value form of DKIM/ARC-Authentication-Results into structured
// verdicts: { d, s, a, bh } per signature, and mech=result pairs per header.
export function dkimSignatures(values) {
  return (values || []).map((v) => {
    const tags = {};
    String(v).split(';').forEach((seg) => {
      const i = seg.indexOf('=');
      if (i > 0) tags[seg.slice(0, i).trim().toLowerCase()] = seg.slice(i + 1).trim();
    });
    return { d: tags.d || '', s: tags.s || '', a: tags.a || 'rsa-sha256', bh: tags.bh || '', t: tags.t || '' };
  }).filter((sig) => sig.d);
}

export function authResults(resultsText) {
  const out = {};
  String(resultsText || '').split(';').slice(1).forEach((chunk) => {
    const m = /^\s*([a-z]+)\s*=\s*([a-z]+)/i.exec(chunk);
    if (m) out[m[1].toLowerCase()] = m[2].toLowerCase();
  });
  return out;
}

// Turn a probe record's headers into the answers we deployed the probe for.
export function summarizeHeaders(headers) {
  const all = headers || {};
  const lower = {};
  Object.keys(all).forEach((k) => { lower[k.toLowerCase()] = all[k]; });
  const list = (name, startsWith) => splitList(lower[name], startsWith);

  const received = list('received', 'from|by|with|id|for').map(parseReceived);
  const authSeen = AUTH_HEADERS.filter((h) => lower[h] != null);
  const sigs = dkimSignatures(list('dkim-signature', 'v=|a=|d=|s='));
  const arcSets = new Set();
  list('arc-seal', 'i=|a=|s=|d=').forEach((v) => { const i = /\bi=(\d+)/.exec(v); if (i) arcSets.add(Number(i[1])); });

  // Which hop claims to have accepted this message from the outside world, i.e.
  // whether an MX we do not control wrote a Received line that names the
  // connecting host. Cloudflare's MX hostnames look like mx*.cloudflare.net or
  // route*.mx.cloudflare.net.
  const cloudflareHop = received.find((h) => /cloudflare\.net|mx\.cloudflare/i.test(h.by + ' ' + h.comments.join(' ')));
  const externalIps = uniq(received.flatMap((h) => h.ips));

  return {
    headerNames: Object.keys(all).map((k) => String(k).toLowerCase()).sort(),
    authHeadersSeen: authSeen,
    // True when repeated headers had to be reconstructed from one joined value:
    // informative, because it means per-hop detail is inferred, not observed.
    foldedFromSingleValue: typeof lower.received === 'string' && received.length > 1,
    receivedHops: received.map((h) => ({ by: h.by, from: h.from, for: h.for, with: h.with, comments: h.comments, ips: h.ips })),
    dkimSignatures: sigs,
    arcSealSets: [...arcSets].sort((a, b) => a - b),
    authenticationResults: authResults(lower['authentication-results'] || ''),
    receivedSpf: list('received-spf').join(' | '),
    envelopeHints: { returnPath: lower['return-path'] || '', sender: lower.sender || '' },
    externalIps,
    cloudflareHopSeen: !!cloudflareHop,
    hopCount: received.length,
  };
}

// The decision this probe exists to make, stated as data rather than prose:
// what the real feature can honestly compute.
export function probeConclusions(record) {
  const s = (record && record.summary) || {};
  const body = (record && record.body) || {};
  const out = [];
  const push = (key, ok, ifYes, ifNo) => out.push({ key, ok: !!ok, text: ok ? ifYes : ifNo });

  push('connectingIp', (s.receivedHops || []).some((h) => (h.ips || []).length),
    `A connecting address is visible in the Received chain (${(s.externalIps || []).slice(0, 3).join(', ')}) — the feature can blacklist-check the real sending IP.`,
    'No IP appears in any Received line — the feature cannot name the sending host, so IP reputation checks would have to be skipped or clearly marked unknown.');

  push('cloudflareHop', s.cloudflareHopSeen,
    'Cloudflare\'s own MX wrote a Received line for this hop, so the last hop is authoritative rather than self-reported.',
    'No Cloudflare-authored Received line — any address you see is whatever the sender claimed about itself.');

  push('authResultsHeader', (s.authHeadersSeen || []).includes('authentication-results') || (s.authHeadersSeen || []).includes('arc-authentication-results'),
    'An Authentication-Results header is present, so a downstream verdict can be surfaced (still verify DKIM ourselves).',
    'No Authentication-Results header arrived — the feature must compute DKIM itself and can only report SPF from the published record.');

  push('dkimSigned', (s.dkimSignatures || []).length > 0,
    `The message carries ${s.dkimSignatures.length} DKIM signature(s) — a real verify is possible.`,
    'The message has no DKIM-Signature header at all.');

  push('bodyAccessible', typeof body.sha256 === 'string' && body.sha256.length === 64,
    `message.raw was readable and hashed (${body.bytes} bytes) — body canonicalisation fits in one invocation.`,
    body.error ? `Reading message.raw failed: ${body.error}` : 'message.raw was not hashed (over the size cap or skipped) — check CPU limits before relying on it.');

  return out;
}
