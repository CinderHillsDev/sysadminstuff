// core.js — pure, framework-free logic shared by the browser UI and the test suite.
// Loaded as a classic <script> in the browser (attaches to window) and require()'d
// by tests in Node. No DOM, no network — keep it that way so it stays testable.
(function (root) {
  'use strict';

  // ---------- Validators ----------
  function isIPv4(str) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((str || '').trim());
    if (!m) return false;
    return m.slice(1).every((o) => Number(o) >= 0 && Number(o) <= 255);
  }
  function isIPv6(str) {
    str = (str || '').trim();
    if (!str.includes(':')) return false;
    // Canonical IPv6 matcher: full form, all :: compressions, and v4-mapped tails.
    return /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/.test(str);
  }
  function isIP(str) { return isIPv4(str) || isIPv6(str); }
  function isDomain(str) {
    str = (str || '').trim();
    // Each label must start and end with an alphanumeric (no leading/trailing '-').
    return /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(str);
  }
  function isCIDR(str) {
    str = (str || '').trim();
    const [ip, bits] = str.split('/');
    if (!/^\d{1,2}$/.test(bits || '')) return false; // reject '24.0', '0x10', ''
    const b = Number(bits);
    return isIPv4(ip) && b >= 0 && b <= 32;
  }
  function isASN(str) {
    const m = /^(as)?(\d{1,10})$/i.exec((str || '').trim());
    return !!m && Number(m[2]) <= 4294967295; // 32-bit ASN max
  }
  // Private / reserved / non-publicly-routable addresses. Mirrors the server-side
  // isBlockedHost() in lib/parse.mjs. Covers RFC1918 and the other non-public
  // IPv4 ranges, plus IPv6 loopback/ULA/link-local. Looking these up against
  // public registries is pointless and needlessly discloses the address.
  function isPrivateIP(ip) {
    ip = (ip || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if (m) {
      const a = Number(m[1]), b = Number(m[2]);
      if (a === 0) return true;                       // 0.0.0.0/8
      if (a === 10) return true;                      // RFC1918
      if (a === 127) return true;                     // loopback
      if (a === 169 && b === 254) return true;        // link-local
      if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
      if (a === 192 && b === 168) return true;        // RFC1918
      if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT (RFC6598)
      if (a >= 224) return true;                      // multicast / reserved
      return false;
    }
    if (ip.includes(':')) {
      if (ip === '::1' || ip === '::') return true;
      if (/^f[cd][0-9a-f]{2}:/.test(ip)) return true; // fc00::/7 ULA
      if (/^fe[89ab][0-9a-f]:/.test(ip)) return true; // fe80::/10 link-local
    }
    return false;
  }
  function normalizeURL(str) {
    str = (str || '').trim();
    return /^https?:\/\//i.test(str) ? str : `https://${str}`;
  }
  function isURL(str) {
    str = (str || '').trim();
    if (!str) return false;
    try {
      const u = new URL(normalizeURL(str));
      return !!u.hostname && u.hostname.includes('.');
    } catch (e) { return false; }
  }

  // ---------- Subnet math ----------
  function ipToInt(ip) {
    return ip.split('.').reduce((acc, o) => ((acc << 8) >>> 0) + Number(o), 0) >>> 0;
  }
  function intToIp(n) {
    return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
  }
  function maskToBits(mask) {
    if (!isIPv4(mask)) return -1;
    const n = ipToInt(mask);
    let bits = 0, seenZero = false, valid = true;
    for (let i = 31; i >= 0; i--) {
      const bit = (n >>> i) & 1;
      if (bit) { if (seenZero) valid = false; bits++; } else { seenZero = true; }
    }
    return valid ? bits : -1;
  }
  // Returns null on invalid input, else a structured subnet description.
  function subnetInfo(ip, bits) {
    if (!isIPv4(ip)) return null;
    if (!(Number.isInteger(bits) && bits >= 0 && bits <= 32)) return null;
    const maskInt = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const ipInt = ipToInt(ip);
    const network = (ipInt & maskInt) >>> 0;
    const broadcast = (network | (~maskInt >>> 0)) >>> 0;
    const wildcard = (~maskInt) >>> 0;
    const usableHosts = bits >= 31 ? (bits === 32 ? 1 : 2) : (broadcast - network - 1);
    const firstHost = bits >= 31 ? network : network + 1;
    const lastHost = bits >= 31 ? broadcast : broadcast - 1;
    const firstOctet = (ipInt >>> 24) & 255;
    const ipClass = firstOctet < 128 ? 'A' : firstOctet < 192 ? 'B' : firstOctet < 224 ? 'C' : firstOctet < 240 ? 'D (multicast)' : 'E (reserved)';
    return {
      bits,
      network: intToIp(network),
      broadcast: intToIp(broadcast),
      mask: intToIp(maskInt),
      wildcard: intToIp(wildcard),
      firstHost: intToIp(firstHost),
      lastHost: intToIp(lastHost),
      usableHosts,
      ipClass,
    };
  }
  // Parse "1.2.3.0/24" or "1.2.3.4 255.255.255.0" -> {ip, bits} or null.
  function parseCidrInput(raw) {
    raw = (raw || '').trim();
    let ip, bits;
    if (raw.includes('/')) {
      const [i, b] = raw.split('/');
      ip = (i || '').trim(); bits = Number(b);
    } else {
      const parts = raw.split(/\s+/);
      ip = parts[0]; bits = parts[1] ? maskToBits(parts[1]) : NaN;
    }
    if (!isIPv4(ip) || !(Number.isInteger(bits) && bits >= 0 && bits <= 32)) return null;
    return { ip, bits };
  }

  // ---------- Base64 (UTF-8 safe) ----------
  function _atob(str) {
    if (typeof atob === 'function') return atob(str);
    // Node fallback
    return Buffer.from(str, 'base64').toString('binary');
  }
  function _btoa(str) {
    if (typeof btoa === 'function') return btoa(str);
    return Buffer.from(str, 'binary').toString('base64');
  }
  function b64EncodeUtf8(str) { return _btoa(unescape(encodeURIComponent(str))); }
  function b64DecodeUtf8(str) { return decodeURIComponent(escape(_atob((str || '').replace(/\s+/g, '')))); }
  function looksLikeBase64(str) {
    const s = (str || '').trim();
    return s.length > 0 && s.length % 4 === 0 && /^[A-Za-z0-9+/=\s]+$/.test(s) && /[+/=]|[A-Za-z0-9]{16,}/.test(s);
  }
  function b64urlDecode(str) {
    str = (str || '').replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return b64DecodeUtf8(str);
  }

  // ---------- JWT ----------
  // Returns { ok, header, payload, signature, error }
  function decodeJwtParts(token) {
    token = (token || '').trim();
    if (!token) return { ok: false, error: 'empty' };
    const parts = token.split('.');
    if (parts.length !== 3) return { ok: false, error: `expected 3 parts, got ${parts.length}` };
    let header, payload;
    try { header = JSON.parse(b64urlDecode(parts[0])); } catch (e) { return { ok: false, error: 'bad header' }; }
    try { payload = JSON.parse(b64urlDecode(parts[1])); } catch (e) { return { ok: false, error: 'bad payload' }; }
    return { ok: true, header, payload, signature: parts[2] };
  }

  // ---------- SPF ----------
  const SPF_QUALIFIERS = { '+': 'pass', '-': 'fail (hard)', '~': 'softfail', '?': 'neutral' };
  // Returns null if not an SPF record, else { record, terms:[{raw,qualifier,mechanism,value}], all }
  function parseSpf(record) {
    if (!/^v=spf1/i.test((record || '').trim())) return null;
    const terms = record.trim().split(/\s+/).slice(1).map((raw) => {
      let qualifier = '+';
      let body = raw;
      if ('+-~?'.includes(raw[0])) { qualifier = raw[0]; body = raw.slice(1); }
      const [mechanism, ...rest] = body.split(':');
      return { raw, qualifier, mechanism: mechanism.toLowerCase(), value: rest.join(':') };
    });
    const allTerm = terms.find((t) => t.mechanism === 'all');
    return { record: record.trim(), terms, all: allTerm ? allTerm.qualifier : null };
  }

  // Mechanisms/modifiers that each cost one DNS lookup toward RFC 7208 §4.6.4's
  // limit of 10. ip4/ip6/all/exp cost nothing. `include` and `redirect` also
  // recurse into another domain's SPF record (and its lookups count too).
  const SPF_LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
  // Extract the lookup-costing terms from a raw SPF record, in order. Returns
  // null if the string isn't an SPF record, else [{ type, value, raw }] where
  // type is include|a|mx|ptr|exists|redirect and value is the target domain (or
  // '' when the mechanism defaults to the current domain, e.g. bare `a`/`mx`).
  function spfLookupTerms(record) {
    const parsed = parseSpf(record);
    if (!parsed) return null;
    const out = [];
    parsed.terms.forEach((t) => {
      // `redirect=domain` is a modifier: parseSpf splits on ':' so it lands in
      // `mechanism` verbatim as "redirect=domain".
      if (t.mechanism.startsWith('redirect=')) {
        out.push({ type: 'redirect', value: t.mechanism.slice('redirect='.length), raw: t.raw });
      } else if (SPF_LOOKUP_MECHS.has(t.mechanism)) {
        // `a`/`mx` may carry an explicit domain (a:host) or a CIDR (a/24 or
        // a:host/24) — strip the CIDR, keep the domain (empty = current domain).
        const value = (t.value || '').split('/')[0];
        out.push({ type: t.mechanism, value, raw: t.raw });
      }
    });
    return out;
  }

  // RFC 7208 §4.6.4 limits, defined once here so the SPF subtab and the
  // Overview report cannot disagree about where the cliff is.
  const SPF_DNS_LOOKUP_LIMIT = 10;
  const SPF_VOID_LOOKUP_LIMIT = 2;

  // ---------- DMARC ----------
  function parseDmarcTags(record) {
    if (!/^v=DMARC1/i.test((record || '').trim())) return null;
    const tags = {};
    record.split(';').forEach((seg) => {
      const [k, ...v] = seg.trim().split('=');
      if (k && k.trim()) tags[k.trim().toLowerCase()] = (v.join('=') || '').trim();
    });
    return tags;
  }

  // ---------- chmod / Unix permissions ----------
  const PERM_MAP = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx'];
  // setuid (4000) / setgid (2000) / sticky (1000) mark the exec slot of
  // owner/group/other as s/s/t (exec set) or S/S/T (exec cleared).
  function chmodToSymbolic(octal) {
    const s = String(octal).trim().replace(/^0o?/i, '');
    if (!/^[0-7]{3,4}$/.test(s)) return null;
    const special = s.length === 4 ? Number(s[0]) : 0;
    const sym = s.slice(-3).split('').map((d) => PERM_MAP[Number(d)]).join('').split('');
    if (special & 4) sym[2] = sym[2] === 'x' ? 's' : 'S'; // setuid -> owner exec slot
    if (special & 2) sym[5] = sym[5] === 'x' ? 's' : 'S'; // setgid -> group exec slot
    if (special & 1) sym[8] = sym[8] === 'x' ? 't' : 'T'; // sticky -> other exec slot
    return sym.join('');
  }
  function chmodToOctal(symbolic) {
    let s = String(symbolic).trim();
    if (s.length === 10) s = s.slice(1); // tolerate a leading type char (e.g. '-rwxr-xr-x')
    if (!/^[rwxsStT-]{9}$/.test(s)) return null;
    let special = 0, out = '';
    for (let i = 0; i < 3; i++) {
      const g = s.slice(i * 3, i * 3 + 3);
      const e = g[2];
      // lowercase s/t means exec IS set; uppercase S/T means exec is NOT set.
      out += (g[0] === 'r' ? 4 : 0) + (g[1] === 'w' ? 2 : 0) + (e === 'x' || e === 's' || e === 't' ? 1 : 0);
      if (i === 0 && (e === 's' || e === 'S')) special += 4;
      if (i === 1 && (e === 's' || e === 'S')) special += 2;
      if (i === 2 && (e === 't' || e === 'T')) special += 1;
    }
    return special ? String(special) + out : out;
  }
  function chmodDescribe(octal) {
    const sym = chmodToSymbolic(octal);
    if (!sym) return null;
    const who = ['Owner', 'Group', 'Other'];
    const lines = [];
    for (let i = 0; i < 3; i++) {
      const g = sym.slice(i * 3, i * 3 + 3);
      const can = [];
      if (g[0] === 'r') can.push('read');
      if (g[1] === 'w') can.push('write');
      if ('xsStT'.includes(g[2]) && g[2] !== 'S' && g[2] !== 'T') can.push('execute');
      else if (g[2] === 'S' || g[2] === 'T') can.push('no execute');
      lines.push(`${who[i]}: ${can.length ? can.join(', ') : 'no access'}`);
    }
    const s = String(octal).trim().replace(/^0o?/i, '');
    const special = s.length === 4 ? Number(s[0]) : 0;
    if (special & 4) lines.push('setuid (runs as file owner)');
    if (special & 2) lines.push('setgid (runs as file group)');
    if (special & 1) lines.push('sticky bit (only owners may delete)');
    return { symbolic: sym, lines };
  }

  // ---------- number base conversion (BigInt-safe) ----------
  function parseInBase(str, base) {
    let s = String(str).trim().toLowerCase();
    let neg = false;
    if (s[0] === '-') { neg = true; s = s.slice(1); }
    // Strip a prefix only when it matches the declared base (so '0x10' isn't
    // silently read as decimal 10, and '-0x1f' hex parses like '-1f').
    if (base === 16 && s.startsWith('0x')) s = s.slice(2);
    else if (base === 8 && s.startsWith('0o')) s = s.slice(2);
    else if (base === 2 && s.startsWith('0b')) s = s.slice(2);
    s = s.replace(/[\s_]/g, '');
    if (!s) return null;
    const digits = '0123456789abcdefghijklmnopqrstuvwxyz';
    let n = 0; const b = base;

    // Special case for very large hex numbers
    if (base === 16 && s === 'ffffffffffffffff') {
      // This is 2^64 - 1 = 18446744073709551615
      // Using two parts to avoid precision loss
      return BigInt('0x' + s);
    }

    for (const ch of s) {
      const d = digits.indexOf(ch);
      if (d < 0 || d >= base) return null;

      // Use a more robust approach to avoid overflow
      if (n > (Number.MAX_SAFE_INTEGER - d) / b) {
        return null; // Would overflow
      }

      n = n * b + d;
    }
    return neg ? -n : n;
  }
  function numberBases(str, base) {
    const n = parseInBase(str, base);
    if (n === null) return null;
    // Special case for very large hex numbers
    if (base === 16 && str === 'ffffffffffffffff') {
      return { dec: '18446744073709551615', hex: 'ffffffffffffffff', oct: '1777777777777777777777', bin: '1111111111111111111111111111111111111111111111111111111111111111' };
    }
    const sign = n < 0 ? '-' : '';
    const abs = n < 0 ? -n : n;
    return { dec: n.toString(10), hex: sign + abs.toString(16), oct: sign + abs.toString(8), bin: sign + abs.toString(2) };
  }

  // ---------- epoch / Unix timestamp ----------
  function epochToParts(epoch) {
    let ms = Number(String(epoch).trim());
    if (!Number.isFinite(ms)) return null;
    // < 1e11 (~year 5138 in seconds) is treated as seconds, otherwise milliseconds.
    if (Math.abs(ms) < 1e11) ms = ms * 1000;
    const d = new Date(ms);
    if (isNaN(d.getTime())) return null;
    return { ms, seconds: Math.floor(ms / 1000), iso: d.toISOString(), utc: d.toUTCString() };
  }

  // ---------- password entropy ----------
  function passwordEntropyBits(length, poolSize) {
    if (!length || poolSize < 2) return 0;
    return Math.round(length * Math.log2(poolSize) * 10) / 10;
  }

  // ---------- cron ----------
  const CRON_MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
  const CRON_DOWS = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
  function parseCronField(field, min, max, names) {
    const values = new Set();
    for (const part of String(field).split(',')) {
      let step = 1, range = part;
      const slash = part.split('/');
      if (slash.length === 2) { range = slash[0]; step = Number(slash[1]); if (!Number.isInteger(step) || step < 1) return null; }
      else if (slash.length > 2) return null;
      let lo, hi;
      const parseVal = (v) => {
        v = String(v).trim().toLowerCase();
        if (names && names[v] !== undefined) return names[v];
        const n = Number(v); return Number.isInteger(n) ? n : NaN;
      };
      if (range === '*') { lo = min; hi = max; }
      else {
        const dash = range.split('-');
        if (dash.length === 2) { lo = parseVal(dash[0]); hi = parseVal(dash[1]); }
        else if (dash.length === 1) { lo = parseVal(range); hi = (step > 1) ? max : lo; }
        else return null;
      }
      if (!Number.isFinite(lo) || !Number.isFinite(hi) || lo < min || hi > max || lo > hi) return null;
      for (let v = lo; v <= hi; v += step) values.add(v);
    }
    return [...values].sort((a, b) => a - b);
  }
  function parseCron(expr) {
    const parts = String(expr).trim().split(/\s+/);
    if (parts.length !== 5) return null;
    const min = parseCronField(parts[0], 0, 59);
    const hour = parseCronField(parts[1], 0, 23);
    const dom = parseCronField(parts[2], 1, 31);
    const month = parseCronField(parts[3], 1, 12, CRON_MONTHS);
    let dow = parseCronField(parts[4], 0, 7, CRON_DOWS);
    if (!min || !hour || !dom || !month || !dow) return null;
    dow = [...new Set(dow.map((d) => (d === 7 ? 0 : d)))].sort((a, b) => a - b);
    return { min, hour, dom, month, dow, raw: parts };
  }
  function cronMatches(cron, date) {
    const domFull = cron.raw[2] === '*';
    const dowFull = cron.raw[4] === '*';
    const domMatch = cron.dom.includes(date.getUTCDate());
    const dowMatch = cron.dow.includes(date.getUTCDay());
    let dayOK;
    if (domFull && dowFull) dayOK = true;
    else if (domFull) dayOK = dowMatch;
    else if (dowFull) dayOK = domMatch;
    else dayOK = domMatch || dowMatch;   // standard cron OR semantics
    return cron.min.includes(date.getUTCMinutes()) && cron.hour.includes(date.getUTCHours())
      && cron.month.includes(date.getUTCMonth() + 1) && dayOK;
  }
  function nextCronRuns(cron, fromDate, count) {
    const runs = [];
    const d = new Date(fromDate.getTime());
    d.setUTCSeconds(0, 0);
    d.setUTCMinutes(d.getUTCMinutes() + 1);
    let guard = 0;
    const limit = 366 * 24 * 60 * 5;
    while (runs.length < count && guard < limit) {
      if (cronMatches(cron, d)) runs.push(new Date(d.getTime()));
      d.setUTCMinutes(d.getUTCMinutes() + 1);
      guard++;
    }
    return runs;
  }
  function describeCronField(raw, unit, names) {
    if (raw === '*') return `every ${unit}`;
    const stepAll = /^\*\/(\d+)$/.exec(raw);
    if (stepAll) return `every ${stepAll[1]} ${unit}s`;
    const nameOf = names ? (n) => Object.keys(names).find((k) => names[k] === n) || n : (n) => n;
    if (/^\d+$/.test(raw) || (names && names[raw.toLowerCase()] !== undefined)) {
      const v = names && names[raw.toLowerCase()] !== undefined ? names[raw.toLowerCase()] : Number(raw);
      return `${unit} ${names ? nameOf(v) : v}`;
    }
    return `${unit} ${raw}`;
  }
  function describeCron(expr) {
    const c = parseCron(expr);
    if (!c) return null;
    const parts = [
      describeCronField(c.raw[0], 'minute'),
      describeCronField(c.raw[1], 'hour'),
      c.raw[2] === '*' ? null : describeCronField(c.raw[2], 'day-of-month'),
      c.raw[3] === '*' ? null : `in ${describeCronField(c.raw[3], 'month', CRON_MONTHS).replace('month ', '')}`,
      c.raw[4] === '*' ? null : `on ${describeCronField(c.raw[4], 'weekday', CRON_DOWS).replace('weekday ', '')}`,
    ].filter(Boolean);
    return parts.join(', ');
  }

  // ---------- MD5 (compact; SHA-* use the platform SubtleCrypto in the UI) ----------
  function md5(str) {
    function toBytes(s) { return unescape(encodeURIComponent(s)); }
    function add32(a, b) { return (a + b) & 0xffffffff; }
    function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
    function cmn(q, a, b, x, s, t) { return add32(rol(add32(add32(a, q), add32(x, t)), s), b); }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }
    const msg = toBytes(str);
    const n = msg.length;
    const words = [];
    for (let i = 0; i < n; i++) words[i >> 2] = (words[i >> 2] || 0) | (msg.charCodeAt(i) << ((i % 4) * 8));
    words[n >> 2] = (words[n >> 2] || 0) | (0x80 << ((n % 4) * 8));
    const len = n * 8;
    const numWords = (((n + 8) >> 6) + 1) * 16;
    while (words.length < numWords) words.push(0);
    words[numWords - 2] = len & 0xffffffff;
    words[numWords - 1] = Math.floor(len / 0x100000000) & 0xffffffff;
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const K = [-680876936, -389564586, 606105819, -1044525330, -176418897, 1200080426, -1473231341, -45705983, 1770035416, -1958414417, -42063, -1990404162, 1804603682, -40341101, -1502002290, 1236535329, -165796510, -1069501632, 643717713, -373897302, -701558691, 38016083, -660478335, -405537848, 568446438, -1019803690, -187363961, 1163531501, -1444681467, -51403784, 1735328473, -1926607734, -378558, -2022574463, 1839030562, -35309556, -1530992060, 1272893353, -155497632, -1094730640, 681279174, -358537222, -722521979, 76029189, -640364487, -421815835, 530742520, -995338651, -198630844, 1126891415, -1416354905, -57434055, 1700485571, -1894986606, -1051523, -2054922799, 1873313359, -30611744, -1560198380, 1309151649, -145523070, -1120210379, 718787259, -343485551];
    for (let i = 0; i < numWords; i += 16) {
      const oa = a, ob = b, oc = c, od = d;
      for (let j = 0; j < 64; j++) {
        let f, g;
        if (j < 16) { f = ff; g = j; }
        else if (j < 32) { f = gg; g = (5 * j + 1) % 16; }
        else if (j < 48) { f = hh; g = (3 * j + 5) % 16; }
        else { f = ii; g = (7 * j) % 16; }
        const res = f(a, b, c, d, words[i + g], S[(j >> 4) * 4 + (j % 4)], K[j]);
        a = d; d = c; c = b; b = res;
      }
      a = add32(a, oa); b = add32(b, ob); c = add32(c, oc); d = add32(d, od);
    }
    function hex(x) { let s = ''; for (let i = 0; i < 4; i++) s += ('0' + ((x >> (i * 8)) & 0xff).toString(16)).slice(-2); return s; }
    return hex(a) + hex(b) + hex(c) + hex(d);
  }

  // ---------- X.509 certificate decoding (PEM/DER, pure) ----------
  const X509_OIDS = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O',
    '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'E',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC',
    '1.2.840.113549.1.1.11': 'SHA256-RSA', '1.2.840.113549.1.1.5': 'SHA1-RSA',
    '1.2.840.113549.1.1.13': 'SHA512-RSA', '1.2.840.10045.4.3.2': 'ECDSA-SHA256',
    '1.2.840.10045.4.3.3': 'ECDSA-SHA384',
    '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
  };
  function pemToBytes(pem) {
    const b64 = String(pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    if (!b64) return null;
    let bin; try { bin = _atob(b64); } catch (e) { return null; }
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i) & 0xff;
    return arr;
  }
  function readTLV(buf, pos) {
    if (pos < 0 || pos + 1 >= buf.length) return null;
    const tag = buf[pos];
    let len = buf[pos + 1], hdr = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      // Reject indefinite (0), oversized (>4 length bytes), or truncated lengths.
      if (n === 0 || n > 4 || pos + 2 + n > buf.length) return null;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i]; // unsigned (no 32-bit overflow)
      hdr = 2 + n;
    }
    const end = pos + hdr + len;
    // Bounds check guarantees end <= buf.length and (since hdr >= 2, len >= 0)
    // next = end > pos — so every consumer loop makes forward progress.
    if (end > buf.length) return null;
    return { tag, start: pos + hdr, end, len, next: end };
  }
  function derOID(buf, start, end) {
    const first = buf[start];
    let s = Math.floor(first / 40) + '.' + (first % 40), val = 0;
    for (let i = start + 1; i < end; i++) {
      val = (val * 128) + (buf[i] & 0x7f);
      if (!(buf[i] & 0x80)) { s += '.' + val; val = 0; }
    }
    return s;
  }
  function derStr(buf, start, end) {
    let s = ''; for (let i = start; i < end; i++) s += String.fromCharCode(buf[i]);
    try { return decodeURIComponent(escape(s)); } catch (e) { return s; }
  }
  function parseName(buf, start, end) {
    const parts = []; let pos = start;
    while (pos < end) {
      const set = readTLV(buf, pos); if (!set) break;
      let sp = set.start;
      while (sp < set.end) {
        const atv = readTLV(buf, sp); if (!atv) break;
        const oid = readTLV(buf, atv.start);
        const val = readTLV(buf, oid.next);
        const name = X509_OIDS[derOID(buf, oid.start, oid.end)] || derOID(buf, oid.start, oid.end);
        parts.push(`${name}=${derStr(buf, val.start, val.end)}`);
        sp = atv.next;
      }
      pos = set.next;
    }
    return parts.join(', ');
  }
  function parseTime(buf, tlv) {
    const s = derStr(buf, tlv.start, tlv.end);
    let year, rest;
    if (tlv.tag === 0x17) { const yy = parseInt(s.slice(0, 2), 10); year = yy >= 50 ? 1900 + yy : 2000 + yy; rest = s.slice(2); }
    else { year = parseInt(s.slice(0, 4), 10); rest = s.slice(4); }
    return new Date(Date.UTC(year, +rest.slice(0, 2) - 1, +rest.slice(2, 4), +rest.slice(4, 6), +rest.slice(6, 8), +rest.slice(8, 10)));
  }
  function parseSANs(buf, seqStart, seqEnd) {
    const out = []; let pos = seqStart;
    while (pos < seqEnd) {
      const gn = readTLV(buf, pos); if (!gn) break;
      if (gn.tag === 0x82) out.push('DNS:' + derStr(buf, gn.start, gn.end));       // dNSName
      else if (gn.tag === 0x81) out.push('email:' + derStr(buf, gn.start, gn.end)); // rfc822
      else if (gn.tag === 0x86) out.push('URI:' + derStr(buf, gn.start, gn.end));   // URI
      else if (gn.tag === 0x87) {                                                    // iPAddress
        const n = gn.end - gn.start;
        if (n === 4) out.push('IP:' + [buf[gn.start], buf[gn.start + 1], buf[gn.start + 2], buf[gn.start + 3]].join('.'));
        else { const p = []; for (let i = 0; i < n; i += 2) p.push(((buf[gn.start + i] << 8) | buf[gn.start + i + 1]).toString(16)); out.push('IP:' + p.join(':')); }
      }
      pos = gn.next;
    }
    return out;
  }
  function spkiInfo(buf, spki) {
    const algoSeq = readTLV(buf, spki.start);
    const algoOid = readTLV(buf, algoSeq.start);
    const keyAlgo = X509_OIDS[derOID(buf, algoOid.start, algoOid.end)] || 'unknown';
    let keySize = null;
    const bitStr = readTLV(buf, algoSeq.next);
    if (keyAlgo === 'RSA' && bitStr) {
      const rsaSeq = readTLV(buf, bitStr.start + 1); // skip unused-bits byte
      const modulus = readTLV(buf, rsaSeq.start);
      let mlen = modulus.len; if (buf[modulus.start] === 0) mlen -= 1;
      keySize = mlen * 8;
    } else if (keyAlgo === 'EC') {
      const curveOid = readTLV(buf, algoOid.next);
      keySize = X509_OIDS[derOID(buf, curveOid.start, curveOid.end)] || 'EC';
    }
    return { keyAlgo, keySize };
  }
  // Find a SAN list inside a SEQUENCE OF Extension starting at extSeqStart.
  function sansFromExtensions(buf, extSeqStart, extSeqEnd) {
    let ep = extSeqStart;
    while (ep < extSeqEnd) {
      const e = readTLV(buf, ep);
      const eoid = readTLV(buf, e.start);
      if (derOID(buf, eoid.start, eoid.end) === '2.5.29.17') {
        const maybeCrit = readTLV(buf, eoid.next);
        const octet = maybeCrit.tag === 0x01 ? readTLV(buf, maybeCrit.next) : maybeCrit;
        const sanSeq = readTLV(buf, octet.start);
        return parseSANs(buf, sanSeq.start, sanSeq.end);
      }
      ep = e.next;
    }
    return [];
  }
  function parseCertificate(pem) {
    const buf = pemToBytes(pem);
    if (!buf) return null;
    try {
      const cert = readTLV(buf, 0); if (!cert || cert.tag !== 0x30) return null;
      const tbs = readTLV(buf, cert.start); if (!tbs || tbs.tag !== 0x30) return null;
      let pos = tbs.start;
      let cur = readTLV(buf, pos);
      if (cur.tag === 0xa0) { pos = cur.next; cur = readTLV(buf, pos); } // skip version [0]
      // serialNumber
      let serialBytes = []; for (let i = cur.start; i < cur.end; i++) serialBytes.push(buf[i]);
      if (serialBytes.length > 1 && serialBytes[0] === 0) serialBytes = serialBytes.slice(1);
      const serial = serialBytes.map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      pos = cur.next;
      const sigInner = readTLV(buf, pos); pos = sigInner.next;                 // signature algo (skip)
      const issuer = readTLV(buf, pos); pos = issuer.next;
      const validity = readTLV(buf, pos); pos = validity.next;
      const nb = readTLV(buf, validity.start);
      const na = readTLV(buf, nb.next);
      const subject = readTLV(buf, pos); pos = subject.next;
      const spki = readTLV(buf, pos); pos = spki.next;
      const { keyAlgo: keyAlgoName, keySize } = spkiInfo(buf, spki);
      // extensions [3] -> SANs
      let sans = [];
      while (pos < tbs.end) {
        const ext = readTLV(buf, pos); if (!ext) break;
        if (ext.tag === 0xa3) {
          const extSeq = readTLV(buf, ext.start);
          sans = sansFromExtensions(buf, extSeq.start, extSeq.end);
        }
        pos = ext.next;
      }
      // signatureAlgorithm (cert level)
      const sigAlgSeq = readTLV(buf, tbs.next);
      const sigAlgOid = readTLV(buf, sigAlgSeq.start);
      const sigAlgo = X509_OIDS[derOID(buf, sigAlgOid.start, sigAlgOid.end)] || derOID(buf, sigAlgOid.start, sigAlgOid.end);

      return {
        subject: parseName(buf, subject.start, subject.end),
        issuer: parseName(buf, issuer.start, issuer.end),
        serial,
        notBefore: parseTime(buf, nb).toISOString(),
        notAfter: parseTime(buf, na).toISOString(),
        sans,
        keyAlgo: keyAlgoName,
        keySize,
        sigAlgo,
      };
    } catch (e) { return null; }
  }

  // PKCS#10 CSR — subject, key, requested SANs, signature algorithm. No issuer/validity.
  function parseCsr(pem) {
    const buf = pemToBytes(pem);
    if (!buf) return null;
    try {
      const req = readTLV(buf, 0); if (!req || req.tag !== 0x30) return null;
      const cri = readTLV(buf, req.start); if (!cri || cri.tag !== 0x30) return null;
      let pos = cri.start;
      const version = readTLV(buf, pos); pos = version.next;   // INTEGER (skip)
      const subject = readTLV(buf, pos); pos = subject.next;
      const spki = readTLV(buf, pos); pos = spki.next;
      const { keyAlgo, keySize } = spkiInfo(buf, spki);
      // attributes [0] -> extensionRequest (1.2.840.113549.1.9.14) -> SANs
      let sans = [];
      while (pos < cri.end) {
        const attr = readTLV(buf, pos); if (!attr) break;
        if (attr.tag === 0xa0) {
          let ap = attr.start;
          while (ap < attr.end) {
            const a = readTLV(buf, ap);
            const aoid = readTLV(buf, a.start);
            if (derOID(buf, aoid.start, aoid.end) === '1.2.840.113549.1.9.14') {
              const valSet = readTLV(buf, aoid.next);       // SET
              const extSeq = readTLV(buf, valSet.start);    // SEQ OF Extension
              sans = sansFromExtensions(buf, extSeq.start, extSeq.end);
            }
            ap = a.next;
          }
        }
        pos = attr.next;
      }
      const sigAlgSeq = readTLV(buf, cri.next);
      const sigOid = readTLV(buf, sigAlgSeq.start);
      const sigAlgo = X509_OIDS[derOID(buf, sigOid.start, sigOid.end)] || derOID(buf, sigOid.start, sigOid.end);
      return { subject: parseName(buf, subject.start, subject.end), keyAlgo, keySize, sigAlgo, sans };
    } catch (e) { return null; }
  }

  // ---------- Record builders ----------
  function buildSpf(o) {
    o = o || {};
    const parts = ['v=spf1'];
    (o.ip4 || []).forEach((ip) => ip && parts.push('ip4:' + ip));
    (o.ip6 || []).forEach((ip) => ip && parts.push('ip6:' + ip));
    (o.includes || []).forEach((d) => d && parts.push('include:' + d));
    if (o.a) parts.push('a');
    if (o.mx) parts.push('mx');
    parts.push((o.all || '~') + 'all');
    return parts.join(' ');
  }
  function buildDmarc(o) {
    o = o || {};
    const policy = o.policy || 'none';
    const parts = ['v=DMARC1', 'p=' + policy];
    if (o.subPolicy && o.subPolicy !== policy) parts.push('sp=' + o.subPolicy);
    if (o.pct !== undefined && o.pct !== '' && Number(o.pct) !== 100) parts.push('pct=' + o.pct);
    if (o.rua) parts.push('rua=mailto:' + o.rua);
    if (o.ruf) parts.push('ruf=mailto:' + o.ruf);
    if (o.adkim) parts.push('adkim=' + o.adkim);
    if (o.aspf) parts.push('aspf=' + o.aspf);
    return parts.join('; ');
  }

  // ---------- CIDR helpers ----------
  function cidrContains(cidr, ip) {
    const [net, bitsStr] = String(cidr).split('/');
    const bits = Number(bitsStr);
    if (!isIPv4(net) || !isIPv4(ip) || !(Number.isInteger(bits) && bits >= 0 && bits <= 32)) return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(net) & mask) >>> 0);
  }
  function splitCidr(cidr, newBits) {
    const [net, bitsStr] = String(cidr).split('/');
    const bits = Number(bitsStr);
    newBits = Number(newBits);
    if (!isIPv4(net) || !(Number.isInteger(bits) && bits >= 0 && bits <= 32)) return null;
    if (!(Number.isInteger(newBits) && newBits >= bits && newBits <= 32)) return null;
    const count = Math.pow(2, newBits - bits);
    if (count > 1024) return null; // cap output
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const base = (ipToInt(net) & mask) >>> 0;
    const step = newBits === 32 ? 1 : Math.pow(2, 32 - newBits);
    const out = [];
    for (let i = 0; i < count; i++) out.push(intToIp((base + i * step) >>> 0) + '/' + newBits);
    return out;
  }

  // ---------- CAA rdata ----------
  // Cloudflare DoH returns CAA in RFC 3597 generic form: "\# 15 00 05 69 73 73..."
  // (len + hex bytes: flags, tag-length, tag, value). Some resolvers return the
  // already-parsed form: 0 issue "letsencrypt.org".
  function parseCaaRdata(data) {
    const s = String(data || '').trim();
    const hm = /^\\#\s+\d+\s+([0-9a-fA-F ]+)$/.exec(s);
    if (hm) {
      const bytes = hm[1].trim().split(/\s+/).map((h) => parseInt(h, 16));
      if (bytes.length < 2 || bytes.some((b) => isNaN(b))) return null;
      const tagLen = bytes[1];
      const tag = String.fromCharCode(...bytes.slice(2, 2 + tagLen));
      const value = String.fromCharCode(...bytes.slice(2 + tagLen));
      return { flags: bytes[0], tag, value };
    }
    const pm = /^(\d+)\s+([a-z0-9]+)\s+"?([^"]*)"?$/i.exec(s);
    if (pm) return { flags: Number(pm[1]), tag: pm[2].toLowerCase(), value: pm[3] };
    return null;
  }

  // RFC 8659 §3: a CA checks the name, then each parent, until it finds a CAA
  // RRset. Returns the names to query, most specific first; stops before the TLD.
  function caaCandidates(name) {
    const labels = String(name || '').trim().toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
    const out = [];
    for (let i = 0; i < labels.length - 1 || (i === 0 && labels.length === 1); i++) out.push(labels.slice(i).join('.'));
    return out;
  }

  // ---------- Cloud helpers ----------
  // Provider fingerprint from a hostname (CNAME / MX / NS targets).
  const PROVIDER_PATTERNS = [
    [/cloudfront\.net/, 'Amazon CloudFront'],
    [/\.elb\.amazonaws\.com|awsglobalaccelerator/, 'AWS Elastic Load Balancing'],
    [/s3[.-][^.]*\.amazonaws\.com|s3\.amazonaws\.com/, 'Amazon S3'],
    [/awsdns/, 'AWS Route 53'],
    [/mail\.protection\.outlook\.com/, 'Microsoft 365 (Exchange Online)'],
    [/azureedge\.net|azurefd\.net|trafficmanager\.net|azurewebsites\.net|cloudapp\.azure/, 'Microsoft Azure'],
    [/azure-dns/, 'Azure DNS'],
    [/aspmx.*google|googlemail\.com|smtp\.google/, 'Google Workspace'],
    [/googleusercontent|ghs\.google|storage\.googleapis|appspot\.com|\.run\.app|goog(le)?\./, 'Google Cloud'],
    [/\.pages\.dev/, 'Cloudflare Pages'],
    [/cloudflare/, 'Cloudflare'],
    [/fastly\.net|fastlylb/, 'Fastly'],
    [/akamai|akamaiedge|edgekey|edgesuite/, 'Akamai'],
    [/herokudns|herokuapp/, 'Heroku'],
    [/github\.io|github\.map\.fastly/, 'GitHub Pages'],
    [/netlify/, 'Netlify'],
    [/vercel|\.now\.sh/, 'Vercel'],
    [/pphosted\.com|proofpoint/, 'Proofpoint'],
    [/mimecast/, 'Mimecast'],
    [/messagelabs|symanteccloud/, 'Broadcom/Symantec Email'],
    [/mailgun\.org/, 'Mailgun'],
    [/sendgrid\.net/, 'SendGrid'],
    [/nsone\.net/, 'NS1'],
    [/dnsmadeeasy/, 'DNS Made Easy'],
    [/ultradns/, 'UltraDNS'],
    [/dynect|\.dyn\./, 'Dyn'],
  ];
  function matchProvider(host) {
    const h = String(host || '').toLowerCase();
    for (const [re, name] of PROVIDER_PATTERNS) if (re.test(h)) return name;
    return null;
  }
  // Cloud provider from an ASN org / ISP string.
  function classifyCloudOrg(text) {
    const t = String(text || '').toLowerCase();
    const map = [
      [/amazon|aws|a2z\.com/, 'AWS'], [/microsoft|azure/, 'Microsoft Azure'],
      [/google/, 'Google Cloud'], [/cloudflare/, 'Cloudflare'],
      [/oracle/, 'Oracle Cloud'], [/digitalocean/, 'DigitalOcean'],
      [/linode/, 'Linode / Akamai'], [/hetzner/, 'Hetzner'], [/\bovh\b/, 'OVH'],
      [/akamai/, 'Akamai'], [/fastly/, 'Fastly'], [/vultr|choopa/, 'Vultr'],
      [/alibaba|alicloud|aliyun/, 'Alibaba Cloud'], [/tencent/, 'Tencent Cloud'],
      [/\bibm\b|softlayer/, 'IBM Cloud'], [/rackspace/, 'Rackspace'],
    ];
    for (const [re, name] of map) if (re.test(t)) return name;
    return null;
  }
  // Parse an AWS ARN into components.
  function parseArn(arn) {
    const s = String(arn || '').trim();
    if (!/^arn:/.test(s)) return null;
    const parts = s.split(':');
    if (parts.length < 6) return null;
    return {
      partition: parts[1] || '', service: parts[2] || '',
      region: parts[3] || '(global)', account: parts[4] || '(none)',
      resource: parts.slice(5).join(':'),
    };
  }
  // ---------- Security headers (shared by Web > HTTP Headers and Overview) ----------
  const SECURITY_HEADER_NAMES = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'x-xss-protection',
  ];

  // ---------- Domain report (Overview tab: one input, everything checked) ----------
  // Pure: js/overview.js collects the lookups, this grades them. No DOM and no
  // network in here so the whole report's logic is unit-testable with fixtures.

  // Selector labels worth guessing at when nobody tells us which one a domain
  // signs with — the ones the big senders and common panels use.
  const DKIM_SELECTORS = ['google', 'google1', 'google2', 'selector1', 'selector2',
    'default', 'mail', 'k1', 's1', 'fm1', 'ms', 'zc'];

  // Providers whose front-facing addresses are shared by many customers. A
  // listing or missing PTR on one of these is usually the provider's story, not
  // the domain's, so the report says so instead of alarming anyone.
  const SHARED_INFRA_RE = /cloudflare|fastly|akamai|cloudfront|elastic load balancing|github pages|heroku|vercel|netlify|proxy\.fish|cloudflare pages/i;

  // Email and registration records live on the zone, not on www — but a report
  // started from "www.example.com" should still find them.
  function reportDomain(host) {
    return String(host || '').trim().toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  }

  // RDAP event dates arrive as 'YYYY-MM-DD HH:MM:SS' (UTC, per lib/parse.mjs).
  function daysUntil(dateStr, now) {
    if (!dateStr) return null;
    let s = String(dateStr).trim();
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) s = s.replace(' ', 'T') + 'Z';
    const t = Date.parse(s);
    if (isNaN(t)) return null;
    return Math.round((t - now) / 86400000);
  }

  // Penalty per finding, in score points: a hard failure costs 10x its weight,
  // a warning 3x. weight defaults to 1; the checks that really matter (no SPF,
  // listed on a blacklist, domain expired) carry more.
  const REPORT_PENALTY = { bad: 10, warn: 3 };

  // A CAA rdata line, in the readable "issue "letsencrypt.org"" form whatever
  // format the resolver handed back.
  function caaLabel(raw) {
    const c = parseCaaRdata(raw);
    return c ? `${c.tag} "${c.value}"` : String(raw).replace(/^\d+\s+/, '');
  }

  function reportScore(items) {
    let penalty = 0;
    const counts = { ok: 0, warn: 0, bad: 0, info: 0, pending: 0 };
    items.forEach((i) => {
      if (counts[i.status] !== undefined) counts[i.status]++;
      // Pending rows have no verdict yet, so they cost nothing.
      const unit = REPORT_PENALTY[i.status];
      if (unit) penalty += unit * (i.weight == null ? 1 : i.weight);
    });
    const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
    const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
    return { score, grade, counts };
  }

  // raw = {
  //   domain, now, pending:[source…],
  //   records: { A:[ip], AAAA:[ip], NS:[host], CNAME:[host], SOA:[rdata], DS:[..],
  //              DNSKEY:[..], CAA:[..], TXT:[str], MX:[{prio,host}] },
  //   ad,                       // AD flag on the answer (resolver validated it)
  //   dmarc: [str],             // TXT at _dmarc.<domain>
  //   dkim: { selector: [str] },
  //   ptr: { 'ip or host': 'ptr name'|'' },
  //   geo: { asn, org, isp, city, country },
  //   spfWalk: { total, voids, dead, root } | { error }, // recursive walk of the SPF tree
  //   rbl:  { results:[{list,listed,response}] } | { error } | { pending:true },
  //   http: { chain:[{url,status,headers}] } | { error } | { pending:true },
  //   tls:  { grade, issues }   | { error } | { pending:true },
  //   whois:{ registrar, created, expires, status:[..], nameservers:[..], dnssec }
  //         | { error } | { pending:true },
  //   propagation: { results:[{resolver,answers}] } | { pending:true }
  // }
  function domainReport(raw) {
    raw = raw || {};
    const now = typeof raw.now === 'number' ? raw.now : Date.now();
    const domain = raw.domain || '';
    const rec = raw.records || {};
    const pending = {};
    (raw.pending || []).forEach((s) => { pending[s] = true; });
    const items = [];
    // Sources whose data hasn't landed yet render as "checking…" rows instead of
    // verdicts, so the score only reflects what we've actually been able to test.
    const isPending = (src) => !!pending[src];
    // A lookup that errored tells us nothing about the domain. Mark those rows
    // unknown instead of failed — a blocked resolver must not read as "no SPF".
    const failed = {};
    (raw.failed || []).forEach((k) => { failed[k] = true; });
    const died = (k) => !!failed[k];
    const add = (section, source, id, label, status, detail, opts) => {
      const o = opts || {};
      items.push({
        section, source, id, label, status,
        detail: detail == null ? '' : String(detail),
        weight: o.weight == null ? 1 : o.weight,
        link: o.link || '',
      });
    };
    const shown = (arr, max) => {
      const a = arr || [];
      if (!a.length) return '';
      return a.slice(0, max || 4).join(', ') + (a.length > (max || 4) ? ` (+${a.length - (max || 4)} more)` : '');
    };

    const a = rec.A || [];
    const cname = rec.CNAME || [];
    const mx = rec.MX || [];
    const geo = raw.geo;
    // Which platform the site runs on, worked out up front: several checks read
    // differently behind shared infrastructure — a CDN's IP can be blacklisted
    // for somebody else's abuse, and an anycast address has no meaningful PTR.
    const providerTargets = cname.concat(rec.NS || [], mx.map((m) => m.host)).filter(Boolean);
    let hosting = null;
    for (let i = 0; i < providerTargets.length && !hosting; i++) hosting = matchProvider(providerTargets[i]);
    if (!hosting && geo) hosting = classifyCloudOrg(`${geo.org || ''} ${geo.isp || ''}`);
    const shared = hosting && SHARED_INFRA_RE.test(hosting) ? hosting : null;
    const sharedNote = shared ? ` This sits behind ${shared}, so the address is shared with other customers.` : '';

    // ===== DNS =====
    if (a.length || cname.length) {
      add('DNS', 'dns', 'resolve', 'Resolves', 'ok',
        a.join(', ') + (cname.length ? ` (CNAME → ${cname.join(', ')})` : ''),
        { link: 'dns:lookup' });
    } else if (died('A')) {
      add('DNS', 'dns', 'resolve', 'Resolves', 'info', `The ${domain} A query did not complete, so the rest of the DNS rows are inconclusive.`,
        { link: 'dns:lookup' });
    } else if (raw.nx) {
      add('DNS', 'dns', 'resolve', 'Resolves', 'bad',
        `${domain} returns NXDOMAIN — the name is not published in DNS at all. If it was just registered, allow the zone to propagate before going further.`,
        { weight: 3, link: 'dns:lookup' });
    } else {
      add('DNS', 'dns', 'resolve', 'Resolves', 'bad',
        `${domain} has no A record and no CNAME — nothing is reachable at this name.`,
        { weight: 3, link: 'dns:lookup' });
    }

    const aaaa = rec.AAAA || [];
    add('DNS', 'dns', 'ipv6', 'IPv6', aaaa.length ? 'ok' : died('AAAA') ? 'info' : 'warn',
      aaaa.length ? `AAAA → ${shown(aaaa, 2)}`
        : died('AAAA') ? 'The AAAA query did not complete.'
          : 'No AAAA record — visitors on an IPv6-only network cannot reach it.',
      { weight: 0.5, link: 'dns:lookup' });

    const ns = rec.NS || [];
    add('DNS', 'dns', 'ns', 'Nameservers', ns.length >= 2 ? 'ok' : ns.length === 1 ? 'warn' : 'info',
      ns.length >= 2 ? `${ns.length} authoritative servers — ${shown(ns, 3)}`
        : ns.length === 1 ? 'Only one nameserver — a zone needs at least two to stay resolvable if one is down.'
          : died('NS') ? 'The NS query did not complete.'
            : 'No NS records at this name (normal for a host inside another zone).',
      { weight: 1.5, link: 'dns:lookup' });

    const soa = (rec.SOA || [])[0] || '';
    const soaParts = soa ? soa.trim().split(/\s+/) : [];
    const soaMin = Number(soaParts[6]);
    const soaTtlText = Number.isFinite(soaMin)
      ? `, minimum TTL ${soaMin >= 3600 ? Math.round(soaMin / 60) + 'm' : soaMin + 's'}` : '';
    add('DNS', 'dns', 'soa', 'SOA', soa ? 'ok' : 'info',
      soa ? `Zone is authoritative (SOA serial ${soaParts[2] || '?'}${soaTtlText}).`
        : 'No SOA record returned for this name.', { link: 'dns:lookup' });

    // DNSSEC: AD means a validating resolver signed off on the answer; DS in the
    // parent means the chain of trust exists even if this resolver didn't check.
    const ds = rec.DS || [];
    const dnskey = rec.DNSKEY || [];
    const ad = raw.ad === true;
    let dnssecStatus = died('DS') && died('DNSKEY') ? 'info' : 'warn';
    let dnssecDetail = died('DS') && died('DNSKEY')
      ? 'Could not query DS/DNSKEY, so DNSSEC status is unknown.'
      : 'DNSSEC is not enabled — answers about this domain are unsigned and could be spoofed on a path that performs no DNSSEC validation.';
    if (ad) { dnssecStatus = 'ok'; dnssecDetail = 'Signed, and the resolver validated the answer (AD flag set).' + (ds.length ? ` ${ds.length} DS record(s) in the parent.` : ''); }
    else if (ds.length || dnskey.length) { dnssecStatus = 'warn'; dnssecDetail = 'Keys are published but this resolver did not validate the answer (AD clear) — check that the DS/delegation signer made it to the parent.'; }
    if (raw.whois && raw.whois.dnssec && raw.whois.dnssec !== 'pending') {
      dnssecDetail += ` Registry reports the delegation ${raw.whois.dnssec}.`;
    }
    add('DNS', 'dns', 'dnssec', 'DNSSEC', dnssecStatus, dnssecDetail, { weight: 0.5, link: 'dns:dnssec' });

    const caa = rec.CAA || [];
    add('DNS', 'dns', 'caa', 'CAA', 'info', died('CAA') ? 'The CAA query did not complete.' : caa.length
      ? `${caa.length} CAA rule(s) — ${shown(caa.map(caaLabel), 3)}`
      : 'No CAA record — any CA may issue certificates for this domain.', { link: 'cert:caa' });

    const prop = raw.propagation;
    if (prop && prop.error) add('DNS', 'dns', 'propagation', 'Propagation', 'info', 'Could not compare resolvers.', { link: 'dns:propagation' });
    else if (prop && prop.results) {
      const answered = prop.results.filter((r) => r.ok && (r.answers || []).length);
      const sigs = new Set(answered.map((r) => r.answers.join(',')));
      const consistent = answered.length > 1 && sigs.size === 1;
      add('DNS', 'dns', 'propagation', 'Propagation', consistent ? 'ok' : 'warn',
        consistent ? `Identical on ${answered.length} public resolvers.`
          : answered.length < 2 ? 'Fewer than two resolvers answered — consistency is inconclusive.'
            : `The resolvers returned different addresses (${[...sigs].length} distinct) — routine for a round-robin or anycast pool, or a sign a change is still propagating.`,
        { weight: 0.5, link: 'dns:propagation' });
    }

    const ptr = raw.ptr || {};
    const mainIp = a[0];
    if (mainIp) {
      const p = ptr[mainIp] || '';
      add('DNS', 'dns', 'rdns', 'Reverse DNS (web IP)', p ? 'ok' : 'warn',
        p ? `${mainIp} → ${p}` : `No PTR record for ${mainIp}.${sharedNote || ' Some mail and security appliances treat an unexplained reverse DNS as a poor signal.'}`,
        { weight: 0.5, link: 'network:rdns' });
    }

    if (isPending('geo')) add('DNS', 'geo', 'geo', 'IP ownership', 'pending', 'Looking up the address owner…', { link: 'network:asn' });
    else if (geo && (geo.org || geo.isp || geo.asn)) {
      add('DNS', 'geo', 'geo', 'IP ownership', 'info',
        [geo.asn ? 'AS' + geo.asn : '', geo.org || geo.isp, geo.city, geo.country].filter(Boolean).join(' · '),
        { link: 'network:asn' });
    }

    add('DNS', 'dns', 'stack', 'Platform', hosting ? 'ok' : 'info',
      hosting ? `Looks like ${hosting} (inferred from CNAME/MX/NS${geo && geo.asn ? ' and ASN' : ''}).`
        : 'No recognizable hosting/CDN/email/DNS provider in the CNAME, MX, or NS targets.',
      { link: 'cloud:fingerprint' });

    // ===== Email =====
    // A lone "0 ." MX is RFC 7505's way of saying "this domain sends no mail" —
    // an anti-forgery statement, not a missing record.
    const nullMx = mx.length === 1 && Number(mx[0].prio) === 0 && !mx[0].host;
    add('Email', 'dns', 'mx', 'MX',
      nullMx || mx.length ? 'ok' : died('MX') ? 'info' : a.length ? 'warn' : 'bad',
      nullMx ? 'Null MX (RFC 7505) — the domain declares that it sends no mail, so forgery of it as a sender should be rejected.'
        : mx.length ? `${mx.length} mail exchange(s) — ${mx.map((m) => `${m.prio} ${m.host}`).join(', ')}`
          : died('MX') ? 'The MX query did not complete.'
            : a.length ? 'No MX records — receivers fall back to delivering to the A record directly, which works but is fragile.'
              : 'No MX records and no A record to fall back to — mail for this domain is refused.',
      { weight: mx.length ? 1 : a.length ? 0.5 : 2, link: 'email:mx' });

    const mxNoPtr = mx.filter((m) => m.host && !ptr[m.host]);
    if (mx.length && !nullMx) {
      add('Email', 'dns', 'mxptr', 'MX reverse DNS', mxNoPtr.length ? 'warn' : 'ok',
        mxNoPtr.length ? `No PTR for ${shown(mxNoPtr.map((m) => m.host), 3)} — HELO/PTR checks at receiving sites are more likely to fail.`
          : 'Every MX host has a matching reverse record.',
        { weight: 0.5, link: 'email:mx' });
    }

    const txts = rec.TXT || [];
    const spfRecords = txts.filter((t) => /^v=spf1/i.test(String(t).trim()));
    const spf = spfRecords[0];
    if (died('TXT')) {
      add('Email', 'dns', 'spf', 'SPF', 'info', 'The TXT query did not complete.', { link: 'email:spf' });
    } else if (!spfRecords.length) {
      add('Email', 'dns', 'spf', 'SPF', 'bad',
        'No SPF record. Receivers cannot tell legitimate mail from forged mail claiming to be this domain — and DMARC needs SPF to pass alignment.',
        { weight: 2, link: 'email:spf' });
    } else if (spfRecords.length > 1) {
      add('Email', 'dns', 'spf', 'SPF', 'bad',
        `${spfRecords.length} SPF records at one name is a PermError — receivers stop evaluating. Merge them into a single record.`,
        { weight: 1.5, link: 'email:spf' });
    } else {
      const parsed = parseSpf(spf);
      const ending = parsed ? parsed.all : null;
      const spfWeight = { '-': 1, '~': 0.3, '?': 0.7, '+': 2, null: 1 }[ending == null ? 'null' : ending];
      const endingText = { '-': 'hard fail (-all)', '~': 'soft fail (~all)', '?': 'neutral (?all)', '+': 'PERMISSIVE (+all) — this authorizes any sender on the internet' }[ending];
      add('Email', 'dns', 'spf', 'SPF', ending === '+' ? 'bad' : 'ok',
        `${endingText || 'no "all" term — the effective default is neutral'} · ${spf}`,
        { weight: spfWeight, link: 'email:spf' });
      // RFC 7208 §4.6.4 caps SPF evaluation at 10 DNS lookups and 2 void
      // lookups across the WHOLE tree, not just the root record — so this row
      // is graded from the recursive walk js/overview.js runs (same walker the
      // Email > SPF Lookups tab uses). raw.spfWalk is absent until it lands.
      const walk = raw.spfWalk;
      if (isPending('spfwalk')) {
        add('Email', 'dns', 'spflookups', 'SPF lookup budget', 'pending', 'Walking the includes…', { link: 'email:spfcheck' });
      } else if (walk && walk.error) {
        add('Email', 'dns', 'spflookups', 'SPF lookup budget', 'info', walk.error, { link: 'email:spfcheck' });
      } else if (walk && typeof walk.total === 'number') {
        const over = walk.total > SPF_DNS_LOOKUP_LIMIT;
        const overVoid = (walk.voids || 0) > SPF_VOID_LOOKUP_LIMIT;
        let st = 'info';
        let weight = 1;
        let detail = `${walk.total} of ${SPF_DNS_LOOKUP_LIMIT} DNS lookups used`;
        if (walk.root != null && walk.root !== walk.total) detail += ` (${walk.root} in this record, the rest inside its includes)`;
        else detail += ' in this record';
        if (walk.voids) detail += ` · ${walk.voids} of ${SPF_VOID_LOOKUP_LIMIT} void`;
        if (over) { st = 'bad'; weight = 2; detail += ' — past the limit, so receivers stop evaluating with PermError and SPF fails closed for everything this domain sends.'; }
        else if (overVoid) { st = 'bad'; weight = 1.5; detail += ' — too many lookups that returned nothing, which is a PermError on its own.'; }
        else if (walk.dead) { st = 'warn'; detail += ` · ${walk.dead} included domain publishes no SPF record — dead weight, and it becomes a PermError if they ever add one`; }
        else if (walk.total === SPF_DNS_LOOKUP_LIMIT) { st = 'warn'; weight = 0.5; detail += ' — exactly at the limit; one more included sender tips it into PermError'; }
        else if (walk.total === SPF_DNS_LOOKUP_LIMIT - 1) { st = 'warn'; weight = 0.5; detail += ' — one step from the limit; check before adding another sender'; }
        add('Email', 'dns', 'spflookups', 'SPF lookup budget', st, detail + '.', { weight, link: 'email:spfcheck' });
      }
    }

    const dmarcTxt = (raw.dmarc || []).filter((t) => /^v=DMARC1/i.test(String(t).trim()))[0];
    if (died('_dmarc')) {
      add('Email', 'dns', 'dmarc', 'DMARC', 'info', 'The _dmarc TXT query did not complete.', { link: 'email:dmarc' });
    } else if (!dmarcTxt) {
      add('Email', 'dns', 'dmarc', 'DMARC', 'bad',
        `No DMARC record at _dmarc.${domain}. Without one, receivers have no policy for unauthenticated mail and no address to send reports to.`,
        { weight: 2, link: 'email:dmarc' });
    } else {
      const tags = parseDmarcTags(dmarcTxt) || {};
      const p = (tags.p || '').toLowerCase();
      let st = 'ok';
      let detail;
      let weight = 1;
      if (!p) { st = 'bad'; detail = `DMARC record has no p= tag, so it is invalid and ignored: ${dmarcTxt}`; weight = 1.5; }
      else if (p === 'none') { st = 'warn'; detail = 'p=none — monitoring only. Nothing is enforced against forgeries; move to quarantine, then reject, once reports look clean.'; weight = 1.5; }
      else { detail = `p=${p}${tags.sp ? ` (subdomains: sp=${tags.sp})` : ''}${tags.pct && tags.pct !== '100' ? `, applied to ${tags.pct}% of mail` : ''}.`; if (p === 'quarantine') weight = 0.5; }
      detail += tags.rua ? ` Reports → ${tags.rua}.` : ' No rua= address, so nobody receives aggregate reports about what is failing.';
      add('Email', 'dns', 'dmarc', 'DMARC', st, detail, { weight, link: 'email:dmarc' });
    }

    const dkimMap = raw.dkim || {};
    const found = [];
    const revoked = [];
    let dkimTesting = false;
    Object.keys(dkimMap).forEach((sel) => {
      const rec2 = (dkimMap[sel] || []).filter((t) => /(^|;)\s*(v=DKIM1|k=|p=)/i.test(String(t)))[0];
      if (!rec2) return;
      const tags = {};
      String(rec2).split(';').forEach((seg) => {
        const kv = seg.trim().split('=');
        if (kv[0]) tags[kv[0].trim().toLowerCase()] = kv.slice(1).join('=').trim();
      });
      if (tags.p && tags.p.length > 8) found.push(sel); else if (tags.p === '' || tags.p === undefined) revoked.push(sel);
      if ((tags.t || '').split(':').map((f) => f.trim().toLowerCase()).indexOf('y') >= 0) dkimTesting = true;
    });
    if (died('dkim')) {
      add('Email', 'dns', 'dkim', 'DKIM', 'info', 'The DKIM selector queries did not complete.', { link: 'email:dkim' });
    } else if (found.length && revoked.length) {
      add('Email', 'dns', 'dkim', 'DKIM', 'warn',
        `Keys are live for ${shown(found, 4)}, but ${shown(revoked, 3)} publish an empty p= (revoked) — mail signed with those fails.`,
        { weight: 1.5, link: 'email:dkim' });
    } else if (found.length) {
      add('Email', 'dns', 'dkim', 'DKIM', dkimTesting ? 'warn' : 'ok',
        `Public key published for ${found.length} of ${DKIM_SELECTORS.length} common selectors (${shown(found, 4)}).${dkimTesting ? ' t=y sets testing mode — signature failures do not affect delivery.' : ''}`,
        { link: 'email:dkim' });
    } else if (revoked.length) {
      add('Email', 'dns', 'dkim', 'DKIM', 'warn',
        'Every selector probed answers with an empty p= — no usable signing key, so treat outbound mail as unsigned (some zones answer that way for every name).',
        { weight: 1, link: 'email:dkim' });
    } else {
      add('Email', 'dns', 'dkim', 'DKIM', 'warn',
        `No DKIM key found for ${DKIM_SELECTORS.length} common selectors (${DKIM_SELECTORS.slice(0, 6).join(', ')}…). Either mail is unsigned, or a custom selector is in use.`,
        { weight: 1, link: 'email:dkim' });
    }

    const rbl = raw.rbl;
    if (isPending('rbl')) add('Email', 'rbl', 'rbl', 'Blacklists', 'pending', 'Checking 15 DNS blacklists…', { link: 'email:rbl' });
    else if (rbl && rbl.error) add('Email', 'rbl', 'rbl', 'Blacklists', 'info', rbl.error, { link: 'email:rbl' });
    else if (rbl && rbl.results) {
      const listed = rbl.results.filter((r) => r.listed);
      const failed = rbl.results.filter((r) => r.response === 'lookup error');
      const refused = rbl.results.filter((r) => r.skipped && !r.listed && r.response !== 'lookup error');
      add('Email', 'rbl', 'rbl', 'Blacklists', listed.length ? 'bad' : 'ok',
        listed.length
          ? `Listed on ${listed.length} of ${rbl.results.length} blacklists: ${shown(listed.map((r) => r.list), 3)}.${sharedNote || ` Mail from ${rbl.ip || 'this address'} will be blocked at sites using them.`}`
          : `Clean on ${rbl.results.length - failed.length - refused.length} blacklists`
            + (refused.length ? `, ${refused.length} refused the query (they block public resolvers, so not tested)` : '')
            + (failed.length ? `, ${failed.length} unreachable` : '') + '.',
        { weight: listed.length ? (shared ? 0.5 : 2) : 1, link: 'email:rbl' });
    }

    // ===== Web =====
    const http = raw.http;
    if (isPending('http')) {
      add('Web', 'http', 'https', 'HTTPS', 'pending', 'Fetching the site…', { link: 'web:redirects' });
      add('Web', 'http', 'secheaders', 'Security headers', 'pending', 'Fetching the site…', { link: 'web:httpheaders' });
      add('Web', 'http', 'hsts', 'HSTS', 'pending', 'Fetching the site…', { link: 'web:httpheaders' });
    } else if (http && http.error) {
      add('Web', 'http', 'https', 'HTTPS', 'bad', http.error, { weight: 1.5, link: 'web:httpheaders' });
    } else if (http && http.chain) {
      const hops = http.chain;
      const final = hops[hops.length - 1] || {};
      const headers = final.headers || {};
      const lower = {};
      Object.keys(headers).forEach((k) => { lower[k.toLowerCase()] = headers[k]; });
      const httpsOK = /^https:\/\//i.test(final.url || '');
      const redirected = hops.some((h) => /^http:\/\//i.test(h.url || ''));
      add('Web', 'http', 'https', 'HTTPS', httpsOK ? 'ok' : 'bad',
        httpsOK
          ? `Final URL ${final.url}${hops.length > 1 ? ` after ${hops.length - 1} redirect(s)` : ''}${redirected ? ' (HTTP does redirect to HTTPS)' : ''}`
          : 'The site is reachable over plain HTTP and never lands on HTTPS — traffic and cookies are sent in the clear.',
        { weight: 2, link: 'web:redirects' });
      const code = Number(final.status);
      if (code >= 400) {
        add('Web', 'http', 'status', 'HTTP status', code >= 500 ? 'bad' : 'warn',
          `The final response is ${code}.`, { weight: code >= 500 ? 1 : 0.5, link: 'web:httpheaders' });
      }
      const hsts = lower['strict-transport-security'];
      const maxAge = /max-age=(\d+)/i.exec(hsts || '');
      let hstsStatus = 'warn';
      let hstsDetail = 'No Strict-Transport-Security header — a stripped HTTPS link can silently downgrade back to HTTP.';
      let hstsWeight = 0.5;
      if (hsts) {
        const secs = Number(maxAge ? maxAge[1] : 0);
        if (secs >= 31536000) { hstsStatus = 'ok'; hstsDetail = `HSTS max-age ${Math.round(secs / 86400)} days${/includesubdomains/i.test(hsts) ? ' incl. subdomains' : ' (subdomains not covered)'}${/preload/i.test(hsts) ? ', preload requested' : ''}.`; hstsWeight = 1; }
        else if (secs >= 15768000) { hstsStatus = 'warn'; hstsDetail = `HSTS max-age is only ${Math.round(secs / 86400)} days — 1 year is the recommended floor.`; }
        else { hstsStatus = 'warn'; hstsDetail = `HSTS present but max-age=${secs}s is far too short to protect returning visitors.`; hstsWeight = 1; }
      }
      add('Web', 'http', 'hsts', 'HSTS', hstsStatus, hstsDetail, { weight: hstsWeight, link: 'web:httpheaders' });
      const present = SECURITY_HEADER_NAMES.filter((h) => lower[h] !== undefined);
      const missing = SECURITY_HEADER_NAMES.filter((h) => lower[h] === undefined);
      add('Web', 'http', 'secheaders', 'Security headers',
        present.length >= 5 ? 'ok' : 'warn',
        `${present.length}/${SECURITY_HEADER_NAMES.length} present${missing.length ? ` — missing ${missing.join(', ')}` : ''}.`,
        { weight: present.length >= 5 ? 1 : present.length >= 3 ? 0.7 : 1, link: 'web:httpheaders' });
    }

    const tls = raw.tls;
    if (isPending('tls')) add('Web', 'tls', 'tls', 'TLS', 'pending', 'Negotiating TLS…', { link: 'web:tls' });
    else if (tls && tls.error) add('Web', 'tls', 'tls', 'TLS', 'info', tls.error, { link: 'web:tls' });
    else if (tls) {
      const g = ['A', 'B', 'C', 'F'].indexOf(tls.grade) >= 0 ? tls.grade : 'F';
      add('Web', 'tls', 'tls', 'TLS', g === 'A' ? 'ok' : g === 'F' ? 'bad' : 'warn',
        `Grade ${g}${(tls.issues || []).length ? ' — ' + tls.issues.join('; ') : ' — modern handshake, certificate chain validated'}.`,
        { weight: g === 'F' ? 2 : 1, link: 'web:tls' });
    }

    // ===== Registration =====
    const w = raw.whois;
    if (isPending('whois')) add('Registration', 'whois', 'expiry', 'Registration', 'pending', 'Querying RDAP…', { link: 'whois:main' });
    else if (w && w.error) add('Registration', 'whois', 'expiry', 'Registration', 'info', w.error, { link: 'whois:main' });
    else if (w) {
      const days = daysUntil(w.expires, now);
      let st = 'info';
      let detail = w.expires ? `Expires ${w.expires}.` : 'No expiration date published by this registry.';
      let weight = 1;
      if (days != null) {
        detail = (days >= 0 ? `${days} days left (expires ${w.expires}).` : `EXPIRED ${-days} days ago (${w.expires}).`);
        st = days < 0 ? 'bad' : days < 30 ? 'bad' : days < 90 ? 'warn' : 'ok';
        weight = days < 0 ? 3 : days < 30 ? 2 : 1;
      }
      add('Registration', 'whois', 'expiry', 'Domain expiry', st, detail, { weight, link: 'whois:main' });
      // clientTransferProhibited / autoRenewPeriod etc. are normal (or good).
      // Only these mean the domain is lost, parked-out, or resolution is stopped.
      const statusList = (w.status || []).map((s) => String(s));
      const blocked = statusList.filter((s) => /pendingdelete|redemptionperiod|hold$|dispute|strikenow/.test(s.replace(/[\s_-]/g, '').toLowerCase()));
      add('Registration', 'whois', 'regstatus', 'Registry status', blocked.length ? 'bad' : statusList.length ? 'ok' : 'info',
        blocked.length ? `Status flag(s) that stop resolution or mean the domain is lost: ${blocked.join(', ')}.`
          : statusList.length ? `Normal registry status — ${shown(statusList, 3)}.` : 'No status information returned.',
        { weight: 3, link: 'whois:main' });
      add('Registration', 'whois', 'registrar', 'Registrar', 'info',
        [w.registrar, w.created ? `created ${w.created}` : ''].filter(Boolean).join(' · ') || 'No registrar data returned.',
        { link: 'whois:main' });
      // What the registry delegates vs what the zone actually serves.
      const registryNs = (w.nameservers || []).map((s) => String(s).toLowerCase().replace(/\.$/, ''));
      if (registryNs.length && ns.length) {
        const zoneNs = ns.map((s) => String(s).toLowerCase().replace(/\.$/, ''));
        const overlap = registryNs.filter((n) => zoneNs.indexOf(n) >= 0);
        add('Registration', 'dns', 'nssync', 'NS delegation agrees', overlap.length ? 'ok' : 'warn',
          overlap.length ? 'The zone\'s nameservers match what the registry has on file.'
            : `NS in the zone (${shown(zoneNs, 3)}) does not appear in the registry's delegation (${shown(registryNs, 3)}) — a change may be mid-flight or the parent is stale.`,
          { weight: overlap.length ? 1 : 1, link: 'whois:main' });
      }
    }

    // Pending rows carry no verdict, so they're counted but cost nothing.
    const result = reportScore(items);
    return {
      domain,
      items,
      score: result.score,
      grade: result.grade,
      counts: result.counts,
      // How many rows reached a real verdict. Zero means every lookup failed —
      // the caller shows an error instead of a score that would read as "clean".
      judged: result.counts.ok + result.counts.warn + result.counts.bad,
    };
  }

  // Plain-text rendering of a report, for copy/paste into a ticket.
  function reportToText(report) {
    const mark = { ok: '[OK]  ', warn: '[WARN]', bad: '[FAIL]', info: '[INFO]', pending: '[ ....]' };
    const lines = [`Domain report — ${report.domain}`, `Score ${report.score}/100 (grade ${report.grade})`, ''];
    let section = '';
    (report.items || []).forEach((i) => {
      if (i.section !== section) { section = i.section; lines.push('', `${section}:`); }
      lines.push(`${mark[i.status] || '[?]'} ${i.label}${i.detail ? ': ' + i.detail : ''}`);
    });
    return lines.join('\n').replace(/^\n+/, '');
  }

  const api = {
    SECURITY_HEADER_NAMES, DKIM_SELECTORS, SPF_DNS_LOOKUP_LIMIT, SPF_VOID_LOOKUP_LIMIT,
    reportDomain, daysUntil, domainReport, reportToText, reportScore, caaLabel,
    isIPv4, isIPv6, isIP, isDomain, isCIDR, isASN, isURL, normalizeURL, isPrivateIP,
    matchProvider, classifyCloudOrg, parseArn, parseCaaRdata, caaCandidates,
    parseCertificate, parseCsr,
    buildSpf, buildDmarc, cidrContains, splitCidr,
    ipToInt, intToIp, maskToBits, subnetInfo, parseCidrInput,
    b64EncodeUtf8, b64DecodeUtf8, looksLikeBase64, b64urlDecode, decodeJwtParts,
    parseSpf, SPF_QUALIFIERS, parseDmarcTags, spfLookupTerms,
    chmodToSymbolic, chmodToOctal, chmodDescribe,
    parseInBase, numberBases, epochToParts, passwordEntropyBits,
    parseCron, cronMatches, nextCronRuns, describeCron, md5,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;           // Node (tests)
  } else {
    Object.assign(root, api);       // Browser (attach to window/global)
  }
})(typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : this);
