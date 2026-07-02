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

  const api = {
    isIPv4, isIPv6, isIP, isDomain, isCIDR, isASN, isURL, normalizeURL, isPrivateIP,
    ipToInt, intToIp, maskToBits, subnetInfo, parseCidrInput,
    b64EncodeUtf8, b64DecodeUtf8, looksLikeBase64, b64urlDecode, decodeJwtParts,
    parseSpf, SPF_QUALIFIERS, parseDmarcTags,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;           // Node (tests)
  } else {
    Object.assign(root, api);       // Browser (attach to window/global)
  }
})(typeof window !== 'undefined' ? window : globalThis);
