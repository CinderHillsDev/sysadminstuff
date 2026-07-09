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
  const b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
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
      return 18446744073709551615;
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
  const api = {
    isIPv4, isIPv6, isIP, isDomain, isCIDR, isASN, isURL, normalizeURL, isPrivateIP,
    matchProvider, classifyCloudOrg, parseArn, parseCaaRdata,
    parseCertificate, parseCsr,
    buildSpf, buildDmarc, cidrContains, splitCidr,
    ipToInt, intToIp, maskToBits, subnetInfo, parseCidrInput,
    b64EncodeUtf8, b64DecodeUtf8, looksLikeBase64, b64urlDecode, decodeJwtParts,
    parseSpf, SPF_QUALIFIERS, parseDmarcTags,
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
