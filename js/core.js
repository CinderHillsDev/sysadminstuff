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
    return /^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/.test(str);
  }
  function isCIDR(str) {
    str = (str || '').trim();
    const [ip, bits] = str.split('/');
    if (bits === undefined || bits === '') return false;
    const b = Number(bits);
    return isIPv4(ip) && Number.isInteger(b) && b >= 0 && b <= 32;
  }
  function isASN(str) { return /^(as)?\d{1,10}$/i.test((str || '').trim()); }
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
  function chmodToSymbolic(octal) {
    const s = String(octal).trim().replace(/^0o?/i, '');
    if (!/^[0-7]{3,4}$/.test(s)) return null;
    return s.slice(-3).split('').map((d) => PERM_MAP[Number(d)]).join('');
  }
  function chmodToOctal(symbolic) {
    let s = String(symbolic).trim();
    if (s.length === 10) s = s.slice(1); // tolerate a leading type char (e.g. '-rwxr-xr-x')
    if (!/^[rwxsStT-]{9}$/.test(s)) return null;
    let out = '';
    for (let i = 0; i < 9; i += 3) {
      const g = s.slice(i, i + 3);
      out += (g[0] === 'r' ? 4 : 0) + (g[1] === 'w' ? 2 : 0) + ('xsStT'.includes(g[2]) ? 1 : 0);
    }
    return out;
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
      if (g[2] === 'x') can.push('execute');
      lines.push(`${who[i]}: ${can.length ? can.join(', ') : 'no access'}`);
    }
    return { symbolic: sym, lines };
  }

  // ---------- number base conversion (BigInt-safe) ----------
  function parseInBase(str, base) {
    let s = String(str).trim().toLowerCase().replace(/^0x|^0o|^0b/, '').replace(/[\s_]/g, '');
    if (!s) return null;
    let neg = false;
    if (s[0] === '-') { neg = true; s = s.slice(1); }
    const digits = '0123456789abcdefghijklmnopqrstuvwxyz';
    let n = 0n; const b = BigInt(base);
    for (const ch of s) {
      const d = digits.indexOf(ch);
      if (d < 0 || d >= base) return null;
      n = n * b + BigInt(d);
    }
    return neg ? -n : n;
  }
  function numberBases(str, base) {
    const n = parseInBase(str, base);
    if (n === null) return null;
    const sign = n < 0n ? '-' : '';
    const abs = n < 0n ? -n : n;
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

  const api = {
    isIPv4, isIPv6, isIP, isDomain, isCIDR, isASN, isURL, normalizeURL, isPrivateIP,
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
})(typeof window !== 'undefined' ? window : globalThis);
