// lib/dnswire.mjs — minimal DNS wire-format codec for the /api/dig function.
// Pure logic (no I/O) so the smoke tests can exercise it directly.
//
// Only what a "dig @ns" lookup needs: encode one question, decode a response's
// answer/authority records into the same JSON shape DoH returns
// ({ name, type, TTL, data }), with name-compression support.

export const TYPE_NUMS = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257,
};

// Build a single-question query message (no TCP length prefix).
export function encodeQuery(name, typeNum, id = 0) {
  const labels = String(name).replace(/\.$/, '').split('.');
  const parts = [];
  for (const label of labels) {
    if (!label.length || label.length > 63) throw new Error('Invalid name.');
    parts.push(label.length);
    for (let i = 0; i < label.length; i++) parts.push(label.charCodeAt(i) & 0xff);
  }
  parts.push(0);
  const buf = new Uint8Array(12 + parts.length + 4);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, id & 0xffff);
  dv.setUint16(2, 0x0100); // RD
  dv.setUint16(4, 1);      // QDCOUNT
  buf.set(parts, 12);
  dv.setUint16(12 + parts.length, typeNum);
  dv.setUint16(12 + parts.length + 2, 1); // IN
  return buf;
}

// Decode a (possibly compressed) name starting at `off`.
// Returns { name, next } where next is the offset after the name in place.
function decodeName(buf, off) {
  const labels = [];
  let next = -1;
  let jumps = 0;
  while (true) {
    if (off >= buf.length) throw new Error('Truncated name.');
    const len = buf[off];
    if (len === 0) { if (next < 0) next = off + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length) throw new Error('Truncated pointer.');
      if (next < 0) next = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      if (++jumps > 64) throw new Error('Compression loop.');
      continue;
    }
    if (len > 63 || off + 1 + len > buf.length) throw new Error('Bad label.');
    let s = '';
    for (let i = off + 1; i <= off + len; i++) {
      const c = buf[i];
      s += (c >= 33 && c <= 126 && c !== 46) ? String.fromCharCode(c) : `\\${String(c).padStart(3, '0')}`;
    }
    labels.push(s);
    off += 1 + len;
    if (labels.length > 128) throw new Error('Name too long.');
  }
  return { name: labels.join('.'), next };
}

// DNS character-strings (TXT): <len><bytes>..., rendered dig-style in quotes.
function decodeStrings(buf, off, end) {
  const out = [];
  while (off < end) {
    const len = buf[off];
    if (off + 1 + len > end) throw new Error('Bad character-string.');
    let s = '';
    for (let i = off + 1; i <= off + len; i++) {
      const c = buf[i];
      s += (c >= 32 && c <= 126) ? (c === 34 || c === 92 ? '\\' + String.fromCharCode(c) : String.fromCharCode(c)) : `\\${String(c).padStart(3, '0')}`;
    }
    out.push(`"${s}"`);
    off += 1 + len;
  }
  return out.join(' ');
}

function ipv4(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function ipv6(buf, off) {
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(((buf[off + i * 2] << 8) | buf[off + i * 2 + 1]).toString(16));
  // Compress the longest run of zero groups, RFC 5952 style.
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] !== '0') continue;
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return groups.join(':');
  const head = groups.slice(0, best).join(':');
  const tail = groups.slice(best + bestLen).join(':');
  return `${head}::${tail}`;
}

function decodeRdata(typeNum, buf, off, len) {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  const end = off + len;
  switch (typeNum) {
    case 1: // A
      if (len !== 4) throw new Error('Bad A rdata.');
      return ipv4(buf, off);
    case 28: // AAAA
      if (len !== 16) throw new Error('Bad AAAA rdata.');
      return ipv6(buf, off);
    case 2: case 5: case 12: // NS, CNAME, PTR
      return decodeName(buf, off).name + '.';
    case 15: { // MX
      const pref = dv.getUint16(off);
      return `${pref} ${decodeName(buf, off + 2).name}.`;
    }
    case 6: { // SOA
      const m = decodeName(buf, off);
      const r = decodeName(buf, m.next);
      const nums = [];
      for (let i = 0; i < 5; i++) nums.push(dv.getUint32(r.next + i * 4));
      return `${m.name}. ${r.name}. ${nums.join(' ')}`;
    }
    case 16: // TXT
      return decodeStrings(buf, off, end);
    case 33: { // SRV
      const pri = dv.getUint16(off), wt = dv.getUint16(off + 2), port = dv.getUint16(off + 4);
      return `${pri} ${wt} ${port} ${decodeName(buf, off + 6).name}.`;
    }
    case 257: { // CAA
      const flags = buf[off];
      const tagLen = buf[off + 1];
      let tag = '';
      for (let i = 0; i < tagLen; i++) tag += String.fromCharCode(buf[off + 2 + i]);
      let value = '';
      for (let i = off + 2 + tagLen; i < end; i++) value += String.fromCharCode(buf[i]);
      return `${flags} ${tag} "${value}"`;
    }
    default: { // unknown → hex
      let hex = '';
      for (let i = off; i < end; i++) hex += buf[i].toString(16).padStart(2, '0');
      return hex;
    }
  }
}

export const RCODES = {
  0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED',
};

// Parse a full response message (no TCP length prefix).
// Returns { id, rcode, rcodeName, answers: [{name, type, TTL, data}] }.
export function parseResponse(buf) {
  if (buf.length < 12) throw new Error('Truncated header.');
  const dv = new DataView(buf.buffer, buf.byteOffset);
  const id = dv.getUint16(0);
  const flags = dv.getUint16(2);
  if (!(flags & 0x8000)) throw new Error('Not a response.');
  const rcode = flags & 0x0f;
  const qd = dv.getUint16(4);
  const an = dv.getUint16(6);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = decodeName(buf, off).next + 4;
  }
  const answers = [];
  for (let i = 0; i < an; i++) {
    const n = decodeName(buf, off);
    if (n.next + 10 > buf.length) throw new Error('Truncated record.');
    const typeNum = dv.getUint16(n.next);
    const ttl = dv.getUint32(n.next + 4);
    const rdLen = dv.getUint16(n.next + 8);
    const rdOff = n.next + 10;
    if (rdOff + rdLen > buf.length) throw new Error('Truncated rdata.');
    answers.push({ name: n.name, type: typeNum, TTL: ttl, data: decodeRdata(typeNum, buf, rdOff, rdLen) });
    off = rdOff + rdLen;
  }
  return { id, rcode, rcodeName: RCODES[rcode] || String(rcode), answers };
}
