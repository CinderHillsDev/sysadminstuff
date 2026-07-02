// lib/parse.mjs — pure response shapers shared by Pages Functions and the test suite.
// No I/O: given an upstream JSON object, return the trimmed shape the frontend expects.

// ---------- RDAP ----------
export function eventDate(events, action) {
  const ev = (events || []).find((e) => e.eventAction === action);
  return ev ? (ev.eventDate || '').slice(0, 19).replace('T', ' ') : '';
}

export function vcardValue(entity, key) {
  const arr = entity && entity.vcardArray && entity.vcardArray[1];
  if (!arr) return '';
  const item = arr.find((x) => x[0] === key);
  return item ? (Array.isArray(item[3]) ? item[3].join(' ') : item[3]) : '';
}

export function findNestedAbuse(entities) {
  for (const e of entities || []) {
    if ((e.roles || []).includes('abuse')) return e;
    if (e.entities) { const nested = findNestedAbuse(e.entities); if (nested) return nested; }
  }
  return null;
}

export function parseRdapDomain(d) {
  const registrarEntity = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
  const registrar = registrarEntity ? (vcardValue(registrarEntity, 'fn') || registrarEntity.handle || '') : '';
  const nameservers = (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean);
  return {
    domain: d.ldhName || '',
    registrar,
    status: d.status || [],
    created: eventDate(d.events, 'registration'),
    updated: eventDate(d.events, 'last changed'),
    expires: eventDate(d.events, 'expiration'),
    nameservers,
    dnssec: d.secureDNS && d.secureDNS.delegationSigned ? 'signed' : 'unsigned',
  };
}

export function parseRdapIP(d) {
  const orgEntity = (d.entities || []).find((e) => (e.roles || []).some((r) => ['registrant', 'administrative'].includes(r)));
  const abuseEntity = (d.entities || []).find((e) => (e.roles || []).includes('abuse')) || findNestedAbuse(d.entities || []);
  return {
    name: d.name || '',
    handle: d.handle || '',
    cidr: (d.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ')
      || (d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : ''),
    country: d.country || '',
    org: orgEntity ? (vcardValue(orgEntity, 'fn') || orgEntity.handle) : '',
    abuse: abuseEntity ? (vcardValue(abuseEntity, 'email') || vcardValue(abuseEntity, 'fn')) : '',
    registered: eventDate(d.events, 'registration'),
    updated: eventDate(d.events, 'last changed'),
  };
}

// ---------- bgpview.io ----------
export function shapeAsnFromIp(bgpData, fallbackQuery) {
  const data = (bgpData && bgpData.data) || {};
  const pref = (data.prefixes || [])[0] || {};
  const asn = pref.asn || {};
  return {
    ip: data.ip || fallbackQuery,
    asn: asn.asn || '',
    name: asn.name || '',
    description: asn.description || '',
    country: asn.country_code || (data.rir_allocation && data.rir_allocation.country_code) || '',
    prefixes: (data.prefixes || []).map((p) => ({ prefix: p.prefix, description: p.name || (p.asn && p.asn.description) || '' })),
  };
}

export function shapeAsn(infoData, prefData, fallbackNum) {
  const info = (infoData && infoData.data) || {};
  const pd = (prefData && prefData.data) || {};
  const prefixes = (pd.ipv4_prefixes || []).concat(pd.ipv6_prefixes || [])
    .map((p) => ({ prefix: p.prefix, description: p.name || p.description || '' }));
  return {
    asn: info.asn || fallbackNum,
    name: info.name || '',
    description: info.description_short || (info.description_full || [])[0] || '',
    country: info.country_code || '',
    prefixes,
  };
}

// ---------- RBL ----------
// Given a target IPv4, return the reversed label used to query a blacklist zone.
export function rblQuery(ip, zone) {
  const reversed = ip.split('.').reverse().join('.');
  return `${reversed}.${zone}`;
}

// ---------- security headers scorecard ----------
export const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'x-xss-protection',
];
export function securityScore(headers) {
  const keys = Object.keys(headers || {}).map((k) => k.toLowerCase());
  const present = SECURITY_HEADERS.filter((h) => keys.includes(h));
  return { present, score: present.length, total: SECURITY_HEADERS.length };
}

// ---------- Microsoft 365 / Entra tenant classification ----------
// Extract the tenant GUID from an OIDC issuer like
// https://login.microsoftonline.com/{guid}/v2.0
export function extractTenantId(issuer) {
  const m = /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(issuer || '');
  return m ? m[1].toLowerCase() : '';
}

// Determine the Microsoft cloud environment from the OIDC metadata fields.
// tenant_region_sub_scope is the reliable discriminator: GCC lives on the
// commercial cloud (login.microsoftonline.com) and only sub_scope tells it apart
// from Commercial. GCC High / DoD live on the US Gov cloud (….us).
export function classifyTenantEnvironment({ subScope, cloudInstance } = {}) {
  const sub = (subScope || '').toUpperCase();
  const cloud = (cloudInstance || '').toLowerCase();
  if (cloud === 'partner.microsoftonline.cn') return 'China (21Vianet)';
  if (cloud === 'microsoftonline.de') return 'Germany (legacy)';
  if (sub === 'DOD') return 'DoD';
  if (sub === 'DODCON') return 'GCC High';
  if (sub === 'GCC') return 'GCC';
  if (cloud === 'microsoftonline.us') return 'GCC High'; // gov cloud w/o sub_scope
  return 'Commercial';
}

// Pull <Domain>…</Domain> entries out of a GetFederationInformation SOAP response.
export function parseTenantDomains(xml, cap = 200) {
  const out = [];
  const re = /<Domain>([^<]+)<\/Domain>/gi;
  let m;
  while ((m = re.exec(xml || '')) && out.length < cap) {
    const d = m[1].trim().toLowerCase();
    if (d && !out.includes(d)) out.push(d);
  }
  return out.sort();
}

// ---------- SSRF host guard (shared with headers.js) ----------
export function isBlockedHost(host) {
  host = (host || '').toLowerCase().trim();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '0.0.0.0') return true;

  // IPv6 — strip brackets the URL parser leaves on. Block loopback, unspecified,
  // unique-local (fc00::/7), link-local (fe80::/10), and IPv4-mapped/compat forms
  // that could smuggle a private IPv4 (::ffff:a.b.c.d or ::ffff:aabb:ccdd).
  if (host.includes(':')) {
    const v6 = host.replace(/^\[|\]$/g, '');
    if (v6 === '::1' || v6 === '::') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(v6)) return true;          // fc00::/7 (ULA)
    if (/^fe[89ab][0-9a-f]:/.test(v6)) return true;          // fe80::/10 (link-local)
    const mapped = /::ffff:(.+)$/.exec(v6);
    if (mapped) {
      const tail = mapped[1];
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(tail)) return isBlockedHost(tail);
      // hex form ::ffff:aabb:ccdd -> reconstruct dotted quad
      const hx = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(tail);
      if (hx) {
        const n = (parseInt(hx[1], 16) << 16) | parseInt(hx[2], 16);
        const dotted = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
        return isBlockedHost(dotted);
      }
    }
    return false;
  }

  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (m) {
    const a = Number(m[1]), b = Number(m[2]);
    if (a === 0) return true;                                // 0.0.0.0/8
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}
