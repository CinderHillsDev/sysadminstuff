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
check('isDomain rejects trailing-hyphen label', !core.isDomain('ab-.com'));
check('isDomain rejects leading-hyphen label', !core.isDomain('a.-b.com'));
check('isDomain allows internal hyphen', core.isDomain('a-b.example.com'));
check('isDomain sub', core.isDomain('a.b.example.co.uk'));
check('isDomain rejects space', !core.isDomain('exa mple.com'));
check('isDomain rejects bare tld', !core.isDomain('localhost'));
check('isCIDR valid', core.isCIDR('10.0.0.0/8'));
check('isCIDR rejects 24.0 bits', !core.isCIDR('1.2.3.0/24.0'));
check('isCIDR rejects 0x10 bits', !core.isCIDR('1.2.3.0/0x10'));
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
check('isASN rejects >32bit', !core.isASN('9999999999'));
check('isASN accepts 32bit max', core.isASN('4294967295'));
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

// ================= lib/parse.mjs: RDAP target + failure shaping =================
eq('rdap target com via rdap.org', parse.rdapTarget('example.com', false), 'https://rdap.org/domain/example.com');
eq('rdap target ip', parse.rdapTarget('1.1.1.1', true), 'https://rdap.org/ip/1.1.1.1');
eq('rdap target de override', parse.rdapTarget('heise.de', false), 'https://rdap.denic.de/domain/heise.de');
eq('rdap target io override', parse.rdapTarget('github.io', false), 'https://rdap.identitydigital.services/rdap/domain/github.io');
eq('rdap target trailing dot + case', parse.rdapTarget('Heise.DE.', false), 'https://rdap.denic.de/domain/Heise.DE.');

const noRdapTld = parse.rdapFailure(404, 'https://rdap.org/domain/example.eu', 'example.eu', false);
eq('rdap failure bootstrap miss is 404', noRdapTld.status, 404);
check('rdap failure bootstrap miss names tld', noRdapTld.error.includes('.eu'), noRdapTld.error);
const notFound = parse.rdapFailure(404, 'https://rdap.verisign.com/com/v1/domain/nope.com', 'nope.com', false);
eq('rdap failure registry 404 is not-found', notFound.error, 'Domain not found — it may be unregistered.');
eq('rdap failure ip 404', parse.rdapFailure(404, 'https://rdap.arin.net/ip/x', '203.0.113.9', true).error, 'No registration found for this IP address.');
eq('rdap failure 429 passthrough', parse.rdapFailure(429, 'https://rdap.org/domain/x.com', 'x.com', false).status, 429);
// 5xx must be remapped — Cloudflare replaces 502/504 bodies with its own page.
eq('rdap failure 502 remapped to 424', parse.rdapFailure(502, 'https://rdap.org/domain/x.com', 'x.com', false).status, 424);

// ================= lib/parse.mjs: whois referral =================
eq('whois referral parsed', parse.parseWhoisReferral('% IANA WHOIS server\nrefer:        whois.eu\nwhois:        whois.eu\nstatus: ACTIVE'), 'whois.eu');
eq('whois referral case-insensitive', parse.parseWhoisReferral('WHOIS:  WHOIS.NIC.AT\n'), 'whois.nic.at');
eq('whois referral absent', parse.parseWhoisReferral('% IANA WHOIS server\nstatus: ACTIVE'), '');
eq('whois referral garbage rejected', parse.parseWhoisReferral('whois: not a host!\n'), '');
eq('whois referral empty input', parse.parseWhoisReferral(''), '');

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

// ================= lib/parse.mjs: M365 tenant classification =================
eq('env Commercial (no sub_scope)', parse.classifyTenantEnvironment({ subScope: '', cloudInstance: 'microsoftonline.com' }), 'Commercial');
eq('env GCC (sub_scope GCC)', parse.classifyTenantEnvironment({ subScope: 'GCC', cloudInstance: 'microsoftonline.com' }), 'GCC');
eq('env GCC High (DODCON)', parse.classifyTenantEnvironment({ subScope: 'DODCON', cloudInstance: 'microsoftonline.us' }), 'GCC High');
eq('env DoD', parse.classifyTenantEnvironment({ subScope: 'DOD', cloudInstance: 'microsoftonline.us' }), 'DoD');
eq('env GCC High (gov cloud, no sub)', parse.classifyTenantEnvironment({ subScope: '', cloudInstance: 'microsoftonline.us' }), 'GCC High');
eq('env China', parse.classifyTenantEnvironment({ subScope: '', cloudInstance: 'partner.microsoftonline.cn' }), 'China (21Vianet)');
eq('env default empty', parse.classifyTenantEnvironment({}), 'Commercial');
eq('extractTenantId from issuer', parse.extractTenantId('https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0'), '72f988bf-86f1-41af-91ab-2d7cd011db47');
eq('extractTenantId none', parse.extractTenantId('https://login.microsoftonline.com/contoso.com/v2.0'), '');
eq('parseTenantDomains dedups+sorts', parse.parseTenantDomains('<Domain>b.com</Domain><Domain>A.com</Domain><Domain>b.com</Domain>'), ['a.com', 'b.com']);
eq('parseTenantDomains empty', parse.parseTenantDomains('<x/>'), []);

// ================= core.js: chmod =================
eq('chmod 755 symbolic', core.chmodToSymbolic('755'), 'rwxr-xr-x');
// setuid/setgid/sticky (special bits)
eq('chmod 4755 setuid', core.chmodToSymbolic('4755'), 'rwsr-xr-x');
eq('chmod 4644 setuid no-exec', core.chmodToSymbolic('4644'), 'rwSr--r--');
eq('chmod 2755 setgid', core.chmodToSymbolic('2755'), 'rwxr-sr-x');
eq('chmod 1777 sticky', core.chmodToSymbolic('1777'), 'rwxrwxrwt');
eq('chmod rwsr-xr-x -> 4755', core.chmodToOctal('rwsr-xr-x'), '4755');
eq('chmod rwSr--r-- -> 4644', core.chmodToOctal('rwSr--r--'), '4644');
eq('chmod rwxrwxrwt -> 1777', core.chmodToOctal('rwxrwxrwt'), '1777');
eq('chmod round-trip 4755', core.chmodToOctal(core.chmodToSymbolic('4755')), '4755');
eq('chmod 644 symbolic', core.chmodToSymbolic('644'), 'rw-r--r--');
eq('chmod 0755 symbolic', core.chmodToSymbolic('0755'), 'rwxr-xr-x');
eq('chmod 777 symbolic', core.chmodToSymbolic('777'), 'rwxrwxrwx');
eq('chmod bad', core.chmodToSymbolic('999'), null);
eq('chmod rwxr-xr-x octal', core.chmodToOctal('rwxr-xr-x'), '755');
eq('chmod rw-r--r-- octal', core.chmodToOctal('rw-r--r--'), '644');
eq('chmod leading type char', core.chmodToOctal('-rwxr-xr-x'), '755');
eq('chmod describe owner', core.chmodDescribe('750').lines[0], 'Owner: read, write, execute');

// ================= core.js: number bases =================
eq('base 255 dec', core.numberBases('255', 10), { dec: '255', hex: 'ff', oct: '377', bin: '11111111' });
eq('base 0x10 in base 10 -> null', core.numberBases('0x10', 10), null);
eq('base -1f hex', core.numberBases('-1f', 16).dec, '-31');
eq('base -0x1f hex', core.numberBases('-0x1f', 16).dec, '-31');
eq('base ff hex -> 255', core.numberBases('ff', 16).dec, '255');
eq('base 0xff strips prefix', core.numberBases('0xff', 16).dec, '255');
eq('base 1010 bin -> 10', core.numberBases('1010', 2).dec, '10');
eq('base bad digit', core.numberBases('2', 2), null);
eq('base bigint safe', core.numberBases('ffffffffffffffff', 16).dec, '18446744073709551615');

// ================= core.js: epoch =================
eq('epoch 0 iso', core.epochToParts(0).iso, '1970-01-01T00:00:00.000Z');
eq('epoch seconds detect', core.epochToParts(1000000000).iso, '2001-09-09T01:46:40.000Z');
eq('epoch ms detect', core.epochToParts(1000000000000).iso, '2001-09-09T01:46:40.000Z');
eq('epoch bad', core.epochToParts('nope'), null);

// ================= core.js: password entropy =================
eq('entropy 16x94', core.passwordEntropyBits(16, 94), 104.9);
eq('entropy zero', core.passwordEntropyBits(0, 94), 0);

// ================= core.js: cron =================
const cron = core.parseCron('*/15 2 * * 1-5');
check('cron parses', cron !== null);
eq('cron minutes', cron.min, [0, 15, 30, 45]);
eq('cron hour', cron.hour, [2]);
eq('cron dow mon-fri', cron.dow, [1, 2, 3, 4, 5]);
eq('cron 5 fields required', core.parseCron('* * * *'), null);
eq('cron names', core.parseCron('0 0 * jan mon').month, [1]);
eq('cron sun=7 normalized', core.parseCron('0 0 * * 7').dow, [0]);
// next runs from a fixed UTC instant (Wed 2024-01-03 01:00:00Z) — cron runs at 02:00 Mon-Fri every 15min
const runs = core.nextCronRuns(core.parseCron('*/15 2 * * 1-5'), new Date('2024-01-03T01:00:00Z'), 2);
eq('cron next run 1', runs[0].toISOString(), '2024-01-03T02:00:00.000Z');
eq('cron next run 2', runs[1].toISOString(), '2024-01-03T02:15:00.000Z');
check('cron describe non-empty', typeof core.describeCron('*/15 2 * * 1-5') === 'string' && core.describeCron('*/15 2 * * 1-5').length > 0);

// ================= core.js: MD5 =================
eq('md5 empty', core.md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
eq('md5 abc', core.md5('abc'), '900150983cd24fb0d6963f7d28e17f72');
eq('md5 fox', core.md5('The quick brown fox jumps over the lazy dog'), '9e107d9d372bb6826bd81d3542a419d6');
eq('md5 utf8', core.md5('héllo'), core.md5('héllo')); // stable

// ================= core.js: cloud helpers =================
eq('provider cloudfront', core.matchProvider('d111.cloudfront.net'), 'Amazon CloudFront');
eq('provider m365 mx', core.matchProvider('contoso-com.mail.protection.outlook.com'), 'Microsoft 365 (Exchange Online)');
eq('provider google workspace', core.matchProvider('aspmx.l.google.com'), 'Google Workspace');
eq('provider route53 ns', core.matchProvider('ns-1234.awsdns-56.org'), 'AWS Route 53');
eq('provider azure dns', core.matchProvider('ns1-01.azure-dns.com'), 'Azure DNS');
eq('provider fastly', core.matchProvider('x.fastly.net'), 'Fastly');
eq('provider none', core.matchProvider('example.com'), null);
eq('cloud org amazon', core.classifyCloudOrg('Amazon Technologies Inc.'), 'AWS');
eq('cloud org azure', core.classifyCloudOrg('MICROSOFT-CORP-MSN-AS-BLOCK'), 'Microsoft Azure');
eq('cloud org google', core.classifyCloudOrg('Google LLC'), 'Google Cloud');
eq('cloud org none', core.classifyCloudOrg('Some Local ISP'), null);

const arn = core.parseArn('arn:aws:iam::123456789012:role/MyRole');
eq('arn partition', arn.partition, 'aws');
eq('arn service', arn.service, 'iam');
eq('arn region global', arn.region, '(global)');
eq('arn account', arn.account, '123456789012');
eq('arn resource', arn.resource, 'role/MyRole');
eq('arn s3 with colons', core.parseArn('arn:aws:s3:::my-bucket/path/to/obj').resource, 'my-bucket/path/to/obj');
eq('arn invalid', core.parseArn('not-an-arn'), null);

// CAA rdata (RFC3597 hex + parsed forms)
eq('caa hex issue', core.parseCaaRdata('\\# 15 00 05 69 73 73 75 65 70 6b 69 2e 67 6f 6f 67'), { flags: 0, tag: 'issue', value: 'pki.goog' });
eq('caa parsed form', core.parseCaaRdata('0 issue "letsencrypt.org"'), { flags: 0, tag: 'issue', value: 'letsencrypt.org' });
eq('caa bad', core.parseCaaRdata('garbage'), null);

// ================= core.js: X.509 certificate parsing =================
const TEST_CERT = `-----BEGIN CERTIFICATE-----
MIIDkzCCAnugAwIBAgIUQnrvthQu1/FlASvD3vWbtgW/J6AwDQYJKoZIhvcNAQEL
BQAwPjEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTEUMBIGA1UECgwLRXhhbXBs
ZSBPcmcxCzAJBgNVBAYTAlVTMB4XDTI2MDcwMzAxMDY1M1oXDTM2MDYzMDAxMDY1
M1owPjEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTEUMBIGA1UECgwLRXhhbXBs
ZSBPcmcxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA4idnVDh4qwPohdmEGTHXwqJxcQEvjU6DU0paUtgVh2mopbCb3AZbSw+D+lQ0
GBAHTropLGBIEmXnJg46zMSOP6O5DRSuVmlifOEaDESN1IcF2YTmC5z9CLmOlCo+
HrhTjeV1ft2RyvGFp/IOmQxyB1OSELwGFQGcutfg6jH6iv2VB1v0fgZwAj5NYgxH
x+LsGqZ7ygqoUKO9bKlPV9E/9lkNzG4NwdbwCcj6rFMUrLheMAZJ7CjVrjS3MIjl
ckYnDhdEn3x5n0G25B424Idc5cuZPq/3k6ftZg7rdc4OzHRPFI74KfAnOkE5pqPR
mDL3DK8XEmvC9djccXksxYA9hQIDAQABo4GIMIGFMB0GA1UdDgQWBBTnYixnBhez
/WX9qag8VXUDpnMTmTAfBgNVHSMEGDAWgBTnYixnBhez/WX9qag8VXUDpnMTmTAP
BgNVHRMBAf8EBTADAQH/MDIGA1UdEQQrMCmCEHRlc3QuZXhhbXBsZS5jb22CD3d3
dy5leGFtcGxlLmNvbYcECgAAATANBgkqhkiG9w0BAQsFAAOCAQEAhjOYTz/zukl6
WnWciQR3uHyW9rvRHD6xb65VHHX0FKEt/4DWdRGn5qNdA9gHnwFNrBJayKvCGY6U
O53wjwmD+xxEF0TMjmmnGVh286m5Ficqby0NsASFTUUaXrVpPzsJsxW+HxHWm3KS
vklQalJFVGVjX1vlSGP5du/qQv3xwAI7PztnS95oaBPKZhykQ80Kp01dpqxYOXaV
tjXJ91Rdcg75jwkWd3x+0qmaEnO5a613ZMORhmD29BFP1LFj/vnIrhd0zvRcmNRj
YmzW9rdc1Z42+g8YI7hrRd8p3z0d1+tLn9wfHp/ld+YQhfXQRxV/E6TwmX4j4eY3
D58MRpcPjA==
-----END CERTIFICATE-----`;
const cert1 = core.parseCertificate(TEST_CERT);
check('cert parses', cert1 !== null);
check('cert subject CN', cert1.subject.includes('CN=test.example.com'));
check('cert subject O', cert1.subject.includes('O=Example Org'));
eq('cert serial', cert1.serial, '427AEFB6142ED7F165012BC3DEF59BB605BF27A0');
eq('cert notBefore', cert1.notBefore, '2026-07-03T01:06:53.000Z');
eq('cert notAfter', cert1.notAfter, '2036-06-30T01:06:53.000Z');
eq('cert SANs', cert1.sans, ['DNS:test.example.com', 'DNS:www.example.com', 'IP:10.0.0.1']);
eq('cert keyAlgo', cert1.keyAlgo, 'RSA');
eq('cert keySize', cert1.keySize, 2048);
eq('cert sigAlgo', cert1.sigAlgo, 'SHA256-RSA');
eq('cert bad input', core.parseCertificate('not a cert'), null);
// Hostile 4-byte DER length (would overflow 32-bit signed -> infinite loop pre-fix).
// The test simply completing proves readTLV bounds-checks and never hangs.
const evilPem = '-----BEGIN CERTIFICATE-----\n' +
  Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xfa, 0x00, 0x00]).toString('base64') +
  '\n-----END CERTIFICATE-----';
eq('cert overflow length -> null (no hang)', core.parseCertificate(evilPem), null);

const TEST_CSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICvTCCAaUCAQAwOjEYMBYGA1UEAwwPY3NyLmV4YW1wbGUuY29tMREwDwYDVQQK
DAhDU1IgVGVzdDELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQD0o9EhuO/ccZMMtLFZABCzYnD4/iiH5lEdKAtBfsQYlNTyJe323pat
ZsX6STPAsHHW2oOF550V+F4qfffH/axwpgoeWvoPBVcsOSlRi7pspIYIApyid8zv
aEfsnpii3Sgzf+JGa6YWkkk8fjmhjPX9HiUtLCukjOlUzYIjYdF2/APqlKGioWZG
rlrHJ0JaLMAxlYLlBI6v5ngS3sAICAaKVt8aGcgR2lDGdJ6x6rgXl59OMX+lg/9u
8RzMKViP+L7d8PtI0zrmLOZMsqaziT1wp1t1/wA1zJY5TvZTWVNWdHuOAS+0hfmD
qso0p8jQPUqCS8CII+JB3CExwOPwcIejAgMBAAGgPjA8BgkqhkiG9w0BCQ4xLzAt
MCsGA1UdEQQkMCKCD2Nzci5leGFtcGxlLmNvbYIPYWx0LmV4YW1wbGUuY29tMA0G
CSqGSIb3DQEBCwUAA4IBAQBGUjDQpLUyfhxuEObU+jahgxAkh2yyntNetu4RxynF
ynjLg/AzMcY/ZiXN37bNYef+W6YtEJ5IibLX+D9WGUPUj7fExRg4h16HVQFvVKQI
kQv+Dd3DxK7VxEfm+6i9E+QIDH6Vncjp2yCCxFnsvGzIFc3yvX8jT6AhhekYk0qr
GQkvehYbREJpzcsI1SWC4o9HBloglmqdeagN7NhW85tNjelA6ghRWBpoWOSDgAt+
vGVpXpzs1EznQ5O9XPMqJw4HGaGLWsnOJRjfmZjX1YgRtQXJk4Ua2hQ20An1Wbqy
JwmH+bTUGnveAJMzlN9f5q8HcGL0OciDEAHlWb+ZUjVy
-----END CERTIFICATE REQUEST-----`;
const csr1 = core.parseCsr(TEST_CSR);
check('csr parses', csr1 !== null);
check('csr subject CN', csr1.subject.includes('CN=csr.example.com'));
check('csr subject O', csr1.subject.includes('O=CSR Test'));
eq('csr SANs', csr1.sans, ['DNS:csr.example.com', 'DNS:alt.example.com']);
eq('csr keyAlgo', csr1.keyAlgo, 'RSA');
eq('csr keySize', csr1.keySize, 2048);
eq('csr sigAlgo', csr1.sigAlgo, 'SHA256-RSA');
eq('csr bad', core.parseCsr('nope'), null);

// ================= core.js: record builders + CIDR =================
eq('spf build', core.buildSpf({ ip4: ['1.2.3.4'], includes: ['_spf.google.com'], mx: true, all: '-' }),
  'v=spf1 ip4:1.2.3.4 include:_spf.google.com mx -all');
eq('spf default all', core.buildSpf({}), 'v=spf1 ~all');
eq('dmarc build', core.buildDmarc({ policy: 'reject', rua: 'r@x.com' }), 'v=DMARC1; p=reject; rua=mailto:r@x.com');
eq('dmarc no redundant sp=none', core.buildDmarc({ subPolicy: 'none' }), 'v=DMARC1; p=none');
eq('dmarc pct + sp', core.buildDmarc({ policy: 'quarantine', subPolicy: 'reject', pct: 50 }), 'v=DMARC1; p=quarantine; sp=reject; pct=50');
eq('cidr contains yes', core.cidrContains('10.0.0.0/8', '10.5.6.7'), true);
eq('cidr contains no', core.cidrContains('10.0.0.0/8', '11.0.0.1'), false);
eq('cidr contains bad', core.cidrContains('nope', '1.2.3.4'), null);
eq('cidr split /24->/26', core.splitCidr('192.168.1.0/24', 26), ['192.168.1.0/26', '192.168.1.64/26', '192.168.1.128/26', '192.168.1.192/26']);
eq('cidr split too many', core.splitCidr('10.0.0.0/8', 24), null);

// ================= wordlist (passphrase generator) =================
const wordlist = require(join(__dirname, '..', 'js', 'wordlist.js'));
check('wordlist is a large array', Array.isArray(wordlist) && wordlist.length >= 1000);
check('wordlist all lowercase alpha', wordlist.every((w) => /^[a-z]+$/.test(w)));
check('wordlist deduped', new Set(wordlist).size === wordlist.length);

// ---- report ----
const total = passed + failures.length;
if (failures.length) {
  console.error(`\n✗ ${failures.length}/${total} checks FAILED:\n`);
  failures.forEach((f) => console.error('  ✗ ' + f));
  console.error('');
  process.exit(1);
}
console.log(`✓ all ${total} smoke checks passed`);
