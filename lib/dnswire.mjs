// lib/dnswire.mjs — minimal DNS wire-format encode/decode (RFC 1035) used by
// /api/trace to talk to authoritative servers directly over TCP. Pure logic, no
// I/O, so it's unit-tested in tests/smoke.mjs.

export const TYPE_CODES = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  DS: 43, DNSKEY: 48, CAA: 257,
};
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPE_CODES).map(([k, v]) => [v, k]));
export const typeName = (n) => TYPE_NAMES[n] || `TYPE${n}`;

export const RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];

export function encodeName(name) {
  const labels = name.replace(/\.$/, '').split('.').filter(Boolean);
  const out = [];
  for (const l of labels) {
    if (l.length > 63) throw new Error('label too long');
    out.push(l.length);
    for (let i = 0; i < l.length; i++) out.push(l.charCodeAt(i) & 0xff);
  }
  out.push(0);
  if (out.length > 255) throw new Error('name too long');
  return out;
}

// Non-recursive (RD=0) single-question query, framed for TCP (2-byte length prefix).
export function buildQuery(name, type, id = 0x1234) {
  const q = [
    id >> 8, id & 0xff, 0x00, 0x00, // id, flags (RD=0: we walk the tree ourselves)
    0, 1, 0, 0, 0, 0, 0, 0,         // qd=1
    ...encodeName(name),
    TYPE_CODES[type] >> 8, TYPE_CODES[type] & 0xff, 0, 1, // type, class IN
  ];
  return Uint8Array.from([q.length >> 8, q.length & 0xff, ...q]);
}

function readName(buf, off) {
  const labels = [];
  let next = -1;
  let jumps = 0;
  for (;;) {
    if (off >= buf.length) throw new Error('truncated name');
    const len = buf[off];
    if (len === 0) { off++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length) throw new Error('truncated pointer');
      if (next < 0) next = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      if (++jumps > 20) throw new Error('compression loop');
      continue;
    }
    if (len > 63) throw new Error('bad label');
    labels.push(String.fromCharCode(...buf.subarray(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  return { name: labels.join('.') + '.', end: next >= 0 ? next : off };
}

export function formatIPv6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push((b[i] << 8) | b[i + 1]);
  let best = { s: -1, l: 0 };
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > best.l) best = { s: i, l: j - i };
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best.l < 2) return hex.join(':');
  return `${hex.slice(0, best.s).join(':')}::${hex.slice(best.s + best.l).join(':')}`;
}

function readRdata(buf, off, len, type) {
  const end = off + len;
  const u16 = (o) => (buf[o] << 8) | buf[o + 1];
  switch (type) {
  case 1: return Array.from(buf.subarray(off, off + 4)).join('.');
  case 28: return formatIPv6(buf.subarray(off, off + 16));
  case 2: case 5: case 12: return readName(buf, off).name;
  case 15: return `${u16(off)} ${readName(buf, off + 2).name}`;
  case 6: {
    const m = readName(buf, off);
    const r = readName(buf, m.end);
    const n = [0, 4, 8, 12, 16].map((i) => ((buf[r.end + i] << 24) | (buf[r.end + i + 1] << 16) | (buf[r.end + i + 2] << 8) | buf[r.end + i + 3]) >>> 0);
    return `${m.name} ${r.name} ${n.join(' ')}`;
  }
  case 33: return `${u16(off)} ${u16(off + 2)} ${u16(off + 4)} ${readName(buf, off + 6).name}`;
  case 16: {
    const parts = [];
    for (let o = off; o < end;) {
      const l = buf[o];
      parts.push(`"${String.fromCharCode(...buf.subarray(o + 1, o + 1 + l)).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
      o += 1 + l;
    }
    return parts.join(' ');
  }
  case 257: {
    const tl = buf[off + 1];
    const tag = String.fromCharCode(...buf.subarray(off + 2, off + 2 + tl));
    const val = String.fromCharCode(...buf.subarray(off + 2 + tl, end));
    return `${buf[off]} ${tag} "${val}"`;
  }
  default:
    return `\\# ${len} ${Array.from(buf.subarray(off, end)).map((x) => x.toString(16).padStart(2, '0')).join('')}`;
  }
}

// Parse a DNS message (without the TCP length prefix).
export function parseMessage(buf) {
  if (buf.length < 12) throw new Error('short message');
  const u16 = (o) => (buf[o] << 8) | buf[o + 1];
  const flags = u16(2);
  const counts = [u16(4), u16(6), u16(8), u16(10)];
  let off = 12;
  for (let i = 0; i < counts[0]; i++) off = readName(buf, off).end + 4;
  const sections = [[], [], []];
  for (let s = 0; s < 3; s++) {
    for (let i = 0; i < counts[s + 1]; i++) {
      const n = readName(buf, off);
      off = n.end;
      if (off + 10 > buf.length) throw new Error('truncated record');
      const type = u16(off);
      const ttl = ((buf[off + 4] << 24) | (buf[off + 5] << 16) | (buf[off + 6] << 8) | buf[off + 7]) >>> 0;
      const rdlen = u16(off + 8);
      off += 10;
      if (off + rdlen > buf.length) throw new Error('truncated rdata');
      sections[s].push({ name: n.name, type: typeName(type), ttl, data: readRdata(buf, off, rdlen, type) });
      off += rdlen;
    }
  }
  return {
    id: u16(0),
    rcode: flags & 0xf,
    aa: !!(flags & 0x0400),
    tc: !!(flags & 0x0200),
    answers: sections[0],
    authority: sections[1],
    additional: sections[2],
  };
}

// True when `name` equals `zone` or sits beneath it (both FQDN-ish, case-insensitive).
export function inZone(name, zone) {
  const n = name.toLowerCase().replace(/\.$/, '');
  const z = zone.toLowerCase().replace(/\.$/, '');
  return z === '' || n === z || n.endsWith('.' + z);
}
