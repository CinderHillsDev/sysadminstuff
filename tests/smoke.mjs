// tests/smoke.mjs — dependency-free unit tests for the pure logic that ships in
// the browser (js/core.js) and the Pages Functions (lib/parse.mjs).
//
// Run: node tests/smoke.mjs
// Exits non-zero on any failure, so it's safe to gate CI on it.

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// core.js is a UMD-style classic script; require() picks up its module.exports.
const core = require(join(__dirname, '..', 'js', 'core.js'));
const parse = await import('../lib/parse.mjs');

// ---- tiny test harness ----
let passed = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { passed++; }
  else { failures.push(`${name}${detail ? ' — ' + detail : ''}`); }
}
function eq(name, actual, expected) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  check(name, a === e, `got ${a}, expected ${e}`);
}

// ================= core.js: validators =================
check('isIPv4 valid', core.isIPv4('192.168.0.1'));
check('isIPv4 rejects >255', !core.isIPv4('999.1.1.1'));
check('isIPv4 rejects short', !core.isIPv4('1.2.3'));
check('isIPv6 valid', core.isIPv6('2001:db8::1'));
check('isIP accepts v4', core.isIP('8.8.8.8'));
check('isIP accepts v6', core.isIP('::1'));
check('isIP rejects garbage', !core.isIP('not-an-ip'));
check('isDomain valid', core.isDomain('example.com'));
check('isDomain sub', core.isDomain('a.b.example.co.uk'));
check('isDomain rejects space', !core.isDomain('exa mple.com'));
check('isDomain rejects bare tld', !core.isDomain('localhost'));
check('isCIDR valid', core.isCIDR('10.0.0.0/8'));
check('isCIDR rejects /33', !core.isCIDR('10.0.0.0/33'));
check('isCIDR rejects no bits', !core.isCIDR('10.0.0.0'));
// isPrivateIP — RFC1918 + other non-public ranges (client-side guard)
check('private 10/8', core.isPrivateIP('10.1.2.3'));
check('private 172.16/12 low', core.isPrivateIP('172.16.0.1'));
check('private 172.31 high', core.isPrivateIP('172.31.255.254'));
check('public 172.15 not private', !core.isPrivateIP('172.15.0.1'));
check('public 172.32 not private', !core.isPrivateIP('172.32.0.1'));
check('private 192.168/16', core.isPrivateIP('192.168.1.1'));
check('private 127 loopback', core.isPrivateIP('127.0.0.1'));
check('private 169.254 link-local', core.isPrivateIP('169.254.1.1'));
check('private 100.64 CGNAT', core.isPrivateIP('100.64.0.1'));
check('private 0.0.0.0/8', core.isPrivateIP('0.0.0.0'));
check('private multicast 224', core.isPrivateIP('224.0.0.1'));
check('public 8.8.8.8 not private', !core.isPrivateIP('8.8.8.8'));
check('public 1.1.1.1 not private', !core.isPrivateIP('1.1.1.1'));
check('private ::1 v6', core.isPrivateIP('::1'));
check('private fd00 ULA v6', core.isPrivateIP('fd00::1'));
check('public v6 not private', !core.isPrivateIP('2606:4700::1111'));

check('isASN AS-prefixed', core.isASN('AS13335'));
check('isASN bare', core.isASN('13335'));
check('isASN rejects word', !core.isASN('cloudflare'));
check('isURL bare host', core.isURL('example.com'));
check('isURL full', core.isURL('https://example.com/path'));
check('isURL rejects empty', !core.isURL(''));
eq('normalizeURL adds https', core.normalizeURL('example.com'), 'https://example.com');
eq('normalizeURL keeps http', core.normalizeURL('http://x.com'), 'http://x.com');

// ================= core.js: subnet math =================
const s24 = core.subnetInfo('192.168.1.50', 24);
eq('subnet /24 network', s24.network, '192.168.1.0');
eq('subnet /24 broadcast', s24.broadcast, '192.168.1.255');
eq('subnet /24 mask', s24.mask, '255.255.255.0');
eq('subnet /24 wildcard', s24.wildcard, '0.0.0.255');
eq('subnet /24 firstHost', s24.firstHost, '192.168.1.1');
eq('subnet /24 lastHost', s24.lastHost, '192.168.1.254');
eq('subnet /24 usableHosts', s24.usableHosts, 254);
eq('subnet /24 class', s24.ipClass, 'C');

const s30 = core.subnetInfo('10.0.0.1', 30);
eq('subnet /30 usableHosts', s30.usableHosts, 2);
eq('subnet /30 network', s30.network, '10.0.0.0');
eq('subnet /30 broadcast', s30.broadcast, '10.0.0.3');
eq('subnet /30 class', s30.ipClass, 'A');

const s31 = core.subnetInfo('10.0.0.0', 31);
eq('subnet /31 usableHosts', s31.usableHosts, 2);
const s32 = core.subnetInfo('10.0.0.5', 32);
eq('subnet /32 usableHosts', s32.usableHosts, 1);
eq('subnet /32 network', s32.network, '10.0.0.5');

const s8 = core.subnetInfo('172.16.5.4', 8);
eq('subnet /8 network', s8.network, '172.0.0.0');
eq('subnet /8 usableHosts', s8.usableHosts, 16777214);
eq('subnet /8 class B', s8.ipClass, 'B');

eq('subnetInfo rejects bad ip', core.subnetInfo('999.0.0.0', 24), null);
eq('subnetInfo rejects bad bits', core.subnetInfo('10.0.0.0', 40), null);

eq('parseCidrInput slash', core.parseCidrInput('192.168.1.0/24'), { ip: '192.168.1.0', bits: 24 });
eq('parseCidrInput mask', core.parseCidrInput('192.168.1.0 255.255.255.0'), { ip: '192.168.1.0', bits: 24 });
eq('parseCidrInput bad', core.parseCidrInput('nonsense'), null);
eq('maskToBits /24', core.maskToBits('255.255.255.0'), 24);
eq('maskToBits noncontiguous', core.maskToBits('255.0.255.0'), -1);

// ================= core.js: base64 =================
eq('b64 roundtrip', core.b64DecodeUtf8(core.b64EncodeUtf8('hello world')), 'hello world');
eq('b64 utf8', core.b64DecodeUtf8(core.b64EncodeUtf8('héllo — 世界')), 'héllo — 世界');
eq('b64 known', core.b64EncodeUtf8('sysadmin'), 'c3lzYWRtaW4=');
check('looksLikeBase64 yes', core.looksLikeBase64('c3lzYWRtaW4='));
check('looksLikeBase64 no', !core.looksLikeBase64('hello there!'));

// ================= core.js: JWT =================
// header {"alg":"HS256","typ":"JWT"} . payload {"sub":"123","exp":9999999999} . sig
const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJleHAiOjk5OTk5OTk5OTl9.abc123';
const decoded = core.decodeJwtParts(jwt);
check('jwt ok', decoded.ok);
eq('jwt alg', decoded.header.alg, 'HS256');
eq('jwt sub', decoded.payload.sub, '123');
eq('jwt sig', decoded.signature, 'abc123');
eq('jwt wrong parts', core.decodeJwtParts('a.b').ok, false);
eq('jwt bad b64', core.decodeJwtParts('!!!.###.$$$').ok, false);

// ================= core.js: SPF =================
const spf = core.parseSpf('v=spf1 include:_spf.google.com ip4:1.2.3.0/24 -all');
check('spf parsed', spf !== null);
eq('spf term count', spf.terms.length, 3);
eq('spf include mech', spf.terms[0].mechanism, 'include');
eq('spf include value', spf.terms[0].value, '_spf.google.com');
eq('spf all qualifier', spf.all, '-');
eq('spf softfail', core.parseSpf('v=spf1 ~all').all, '~');
eq('spf non-spf', core.parseSpf('v=DKIM1; k=rsa'), null);

// ================= core.js: DMARC =================
const dmarc = core.parseDmarcTags('v=DMARC1; p=reject; rua=mailto:r@x.com; pct=100');
eq('dmarc policy', dmarc.p, 'reject');
eq('dmarc rua', dmarc.rua, 'mailto:r@x.com');
eq('dmarc non-dmarc', core.parseDmarcTags('v=spf1 -all'), null);

// ================= lib/parse.mjs: RDAP =================
const rdapDomain = parse.parseRdapDomain({
  ldhName: 'example.com',
  status: ['client transfer prohibited'],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]] }],
  nameservers: [{ ldhName: 'NS1.EXAMPLE.COM' }, { ldhName: 'ns2.example.com' }],
  events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2030-08-13T04:00:00Z' }],
  secureDNS: { delegationSigned: true },
});
eq('rdap registrar', rdapDomain.registrar, 'Example Registrar');
eq('rdap nameservers lowercased', rdapDomain.nameservers, ['ns1.example.com', 'ns2.example.com']);
eq('rdap created', rdapDomain.created, '1995-08-14 04:00:00');
eq('rdap dnssec', rdapDomain.dnssec, 'signed');
eq('rdap status', rdapDomain.status, ['client transfer prohibited']);

const rdapIP = parse.parseRdapIP({
  name: 'CLOUDFLARENET',
  handle: 'NET-104-16-0-0-1',
  country: 'US',
  startAddress: '104.16.0.0', endAddress: '104.31.255.255',
  entities: [
    { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'Cloudflare, Inc.']]] },
    { roles: ['other'], entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['email', {}, 'text', 'abuse@cloudflare.com']]] }] },
  ],
  events: [{ eventAction: 'registration', eventDate: '2014-03-28T00:00:00Z' }],
});
eq('rdap ip name', rdapIP.name, 'CLOUDFLARENET');
eq('rdap ip org', rdapIP.org, 'Cloudflare, Inc.');
eq('rdap ip nested abuse', rdapIP.abuse, 'abuse@cloudflare.com');
eq('rdap ip cidr range', rdapIP.cidr, '104.16.0.0 – 104.31.255.255');

// ================= lib/parse.mjs: bgpview shaping =================
const asnFromIp = parse.shapeAsnFromIp({
  data: { ip: '1.1.1.1', prefixes: [{ prefix: '1.1.1.0/24', name: 'APNIC-LABS', asn: { asn: 13335, name: 'CLOUDFLARENET', description: 'Cloudflare', country_code: 'US' } }] },
}, '1.1.1.1');
eq('asn-from-ip asn', asnFromIp.asn, 13335);
eq('asn-from-ip name', asnFromIp.name, 'CLOUDFLARENET');
eq('asn-from-ip prefix', asnFromIp.prefixes[0].prefix, '1.1.1.0/24');

const asn = parse.shapeAsn(
  { data: { asn: 13335, name: 'CLOUDFLARENET', description_short: 'Cloudflare, Inc.', country_code: 'US' } },
  { data: { ipv4_prefixes: [{ prefix: '1.1.1.0/24', name: 'p1' }], ipv6_prefixes: [{ prefix: '2606:4700::/32', name: 'p2' }] } },
  '13335',
);
eq('asn number', asn.asn, 13335);
eq('asn description', asn.description, 'Cloudflare, Inc.');
eq('asn prefix count', asn.prefixes.length, 2);
eq('asn v6 prefix', asn.prefixes[1].prefix, '2606:4700::/32');

// ================= lib/parse.mjs: security scorecard =================
const sc = parse.securityScore({ 'Strict-Transport-Security': 'max-age=1', 'x-frame-options': 'DENY', 'content-type': 'text/html' });
eq('securityScore count', sc.score, 2);
eq('securityScore total', sc.total, 7);

// ================= lib/parse.mjs: RBL + SSRF guard =================
eq('rblQuery reverses octets', parse.rblQuery('1.2.3.4', 'zen.spamhaus.org'), '4.3.2.1.zen.spamhaus.org');
check('ssrf blocks localhost', parse.isBlockedHost('localhost'));
check('ssrf blocks 127.x', parse.isBlockedHost('127.0.0.1'));
check('ssrf blocks 10.x', parse.isBlockedHost('10.1.2.3'));
check('ssrf blocks 192.168', parse.isBlockedHost('192.168.1.1'));
check('ssrf blocks 169.254 metadata', parse.isBlockedHost('169.254.169.254'));
check('ssrf blocks 172.16', parse.isBlockedHost('172.16.0.1'));
check('ssrf blocks 0.0.0.0/8', parse.isBlockedHost('0.1.2.3'));
check('ssrf allows public', !parse.isBlockedHost('example.com'));
check('ssrf allows 8.8.8.8', !parse.isBlockedHost('8.8.8.8'));
// IPv6 coverage (finding #4)
check('ssrf blocks ::1', parse.isBlockedHost('::1'));
check('ssrf blocks [::1] bracketed', parse.isBlockedHost('[::1]'));
check('ssrf blocks unspecified ::', parse.isBlockedHost('::'));
check('ssrf blocks ULA fd00::', parse.isBlockedHost('fd00::1'));
check('ssrf blocks link-local fe80::', parse.isBlockedHost('fe80::1'));
check('ssrf blocks v4-mapped metadata', parse.isBlockedHost('[::ffff:169.254.169.254]'));
check('ssrf blocks v4-mapped private', parse.isBlockedHost('::ffff:10.0.0.1'));
check('ssrf blocks v4-mapped hex metadata', parse.isBlockedHost('::ffff:a9fe:a9fe'));
check('ssrf allows public v6', !parse.isBlockedHost('2606:4700::1111'));

// ---- report ----
const total = passed + failures.length;
if (failures.length) {
  console.error(`\n✗ ${failures.length}/${total} checks FAILED:\n`);
  failures.forEach((f) => console.error('  ✗ ' + f));
  console.error('');
  process.exit(1);
}
console.log(`✓ all ${total} smoke checks passed`);
