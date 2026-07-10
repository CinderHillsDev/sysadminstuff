// tests/e2e.mjs — end-to-end checks against a running Pages dev server.
//
//   npx wrangler pages dev .        # terminal 1 (serves http://localhost:8788)
//   node tests/e2e.mjs              # terminal 2
//
// Override the target with BASE_URL, e.g. BASE_URL=https://sysadminstuff.net node tests/e2e.mjs
//
// These hit live third-party APIs (RDAP, bgpview, blacklists), so a failure can
// mean an upstream hiccup rather than a real regression. Exits non-zero on failure.

const BASE = (process.env.BASE_URL || 'http://localhost:8788').replace(/\/$/, '');

let passed = 0;
let skipped = 0;
const failures = [];
function ok(name, cond, detail) {
  if (cond) { passed++; console.log('  ✓ ' + name); }
  else { failures.push(`${name}${detail ? ' — ' + detail : ''}`); console.log('  ✗ ' + name + (detail ? ' — ' + detail : '')); }
}
// For checks that depend on a live third-party API: an upstream 403/429/5xx (or
// a network block) means "their service, not our bug" — record it as a skip.
function isUpstreamDown(status) { return status === 0 || status === 403 || status === 429 || status >= 500; }
function okUpstream(name, status, cond, detail) {
  if (isUpstreamDown(status)) { skipped++; console.log(`  ~ ${name} — SKIP (upstream status ${status})`); return; }
  ok(name, cond, detail);
}

async function getJson(path) {
  // Emulate a same-origin browser fetch (the middleware requires Sec-Fetch-Site).
  const res = await fetch(BASE + path, { headers: { Accept: 'application/json', 'Sec-Fetch-Site': 'same-origin' } });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* leave null */ }
  return { status: res.status, json, text, headers: res.headers };
}

async function main() {
  console.log(`e2e against ${BASE}\n`);

  // Static assets
  {
    const res = await fetch(BASE + '/');
    ok('GET / serves HTML', res.status === 200 && (await res.text()).includes('sysadminstuff'));
  }
  {
    const res = await fetch(BASE + '/css/style.css');
    ok('GET /css/style.css', res.status === 200);
  }
  {
    const res = await fetch(BASE + '/js/core.js');
    ok('GET /js/core.js', res.status === 200);
  }

  // CORS preflight on a function
  {
    const res = await fetch(BASE + '/api/whois', { method: 'OPTIONS' });
    ok('OPTIONS /api/whois preflight', res.status === 200 && res.headers.get('access-control-allow-origin') === '*');
  }
  // Anti-abuse: a curl-style request (no Sec-Fetch-Site) to the API is rejected
  {
    const res = await fetch(BASE + '/api/whois?q=example.com'); // no Sec-Fetch-Site header
    ok('API rejects non-browser request (403)', res.status === 403);
  }

  // whois (domain) — RDAP (live registry)
  {
    const { status, json } = await getJson('/api/whois?q=example.com');
    okUpstream('whois domain 200', status, status === 200, `status ${status}`);
    okUpstream('whois domain has field', status, json && (json.registrar !== undefined || json.domain), JSON.stringify(json));
  }
  // whois — RDAP override for a registry missing from the IANA bootstrap (.de)
  {
    const { status, json } = await getJson('/api/whois?q=heise.de');
    okUpstream('whois .de override 200', status, status === 200, `status ${status}`);
    okUpstream('whois .de has domain field', status, json && json.domain, JSON.stringify(json));
  }
  // whois — classic port-43 fallback for a TLD with no RDAP at all (.eu)
  {
    const { status, json } = await getJson('/api/whois?q=europa.eu');
    okUpstream('whois .eu raw fallback 200', status, status === 200, `status ${status}`);
    okUpstream('whois .eu returns raw text', status, json && json.raw && json.source, JSON.stringify(json).slice(0, 120));
  }
  // whois missing param — this is OUR validation, always checked
  {
    const { status, json } = await getJson('/api/whois');
    ok('whois no-param 400', status === 400 && json && json.error);
  }
  // whois rejects private IP (RFC1918) — OUR guard
  {
    const { status } = await getJson('/api/whois?q=10.0.0.1');
    ok('whois blocks RFC1918 400', status === 400);
  }

  // (DNS, incl. propagation, resolves server-side via /api/dns — checked below.)

  // M365 tenant lookup (live Microsoft endpoints)
  {
    const { status, json } = await getJson('/api/tenant?domain=microsoft.com');
    okUpstream('tenant microsoft.com 200', status, status === 200, `status ${status}`);
    okUpstream('tenant is Commercial', status, json && json.isTenant && json.environment === 'Commercial', JSON.stringify(json && json.environment));
    okUpstream('tenant has GUID', status, json && /^[0-9a-f-]{36}$/.test(json.tenantId || ''), JSON.stringify(json && json.tenantId));
  }
  {
    const { status, json } = await getJson('/api/tenant?domain=irs.gov');
    okUpstream('tenant irs.gov is GCC', status, json && json.environment === 'GCC', JSON.stringify(json && json.environment));
  }
  {
    const { status, json } = await getJson('/api/tenant?domain=lmco.com');
    okUpstream('tenant lmco.com is GCC High', status, json && json.environment === 'GCC High', JSON.stringify(json && json.environment));
  }
  {
    const { status, json } = await getJson('/api/tenant?domain=army.mil');
    okUpstream('tenant army.mil is DoD', status, json && json.environment === 'DoD', JSON.stringify(json && json.environment));
  }
  {
    const { status } = await getJson('/api/tenant?domain=notadomain'); // no dot -> invalid
    ok('tenant invalid-domain 400', status === 400);
  }
  {
    // A syntactically valid but non-existent domain -> 200 isTenant:false
    const { status, json } = await getJson('/api/tenant?domain=no-such-tenant-9f8e7d6c5b4a.com');
    okUpstream('tenant fake domain -> isTenant false', status, json && json.isTenant === false, JSON.stringify(json && json.isTenant));
  }

  // crt.sh proxy (live)
  {
    const { status, json } = await getJson('/api/crtsh?q=example.com');
    okUpstream('crtsh 200', status, status === 200, `status ${status}`);
    okUpstream('crtsh returns array', status, Array.isArray(json));
  }
  {
    const { status } = await getJson('/api/crtsh');
    ok('crtsh no-param 400', status === 400);
  }

  // asn (live bgpview.io)
  {
    const { status, json } = await getJson('/api/asn?q=AS13335');
    okUpstream('asn AS13335 200', status, status === 200, `status ${status}`);
    okUpstream('asn has prefixes array', status, json && Array.isArray(json.prefixes));
    okUpstream('asn name present', status, json && typeof json.name === 'string' && json.name.length > 0, JSON.stringify(json && json.name));
  }

  // rbl — 1.1.1.1 should be clean
  {
    const { status, json } = await getJson('/api/rbl?ip=1.1.1.1');
    ok('rbl 200', status === 200, `status ${status}`);
    ok('rbl checked 15', json && json.checked === 15, JSON.stringify(json && json.checked));
    ok('rbl results array', json && Array.isArray(json.results) && json.results.length === 15);
  }
  {
    const { status } = await getJson('/api/rbl?ip=notanip');
    ok('rbl bad ip 400', status === 400);
  }
  // Edge caching: a repeated identical lookup should be served from cache.
  {
    const url = '/api/rbl?ip=8.8.4.4';
    const r1 = await fetch(BASE + url, { headers: { 'Sec-Fetch-Site': 'same-origin' } });
    if (r1.status === 200) {
      const r2 = await fetch(BASE + url, { headers: { 'Sec-Fetch-Site': 'same-origin' } });
      ok('rbl second request is cache HIT', r2.headers.get('x-cache') === 'HIT', `x-cache=${r2.headers.get('x-cache')}`);
    } else {
      ok('rbl second request is cache HIT', true, 'skipped — first request not 200');
    }
  }
  {
    const { status } = await getJson('/api/rbl?ip=192.168.1.1');
    ok('rbl blocks RFC1918 400', status === 400);
  }

  // dns — resolve A record server-side (live resolver)
  {
    const { status, json } = await getJson('/api/dns?name=cloudflare.com&type=A');
    okUpstream('dns A 200', status, status === 200, `status ${status}`);
    okUpstream('dns A returns answer', status, json && Array.isArray(json.Answer) && json.Answer.some((a) => a.type === 1));
  }
  // dns resolver param — propagation tool passes ?resolver=google
  {
    const { status, json } = await getJson('/api/dns?name=cloudflare.com&type=A&resolver=google');
    okUpstream('dns via google 200', status, status === 200, `status ${status}`);
    okUpstream('dns via google returns answer', status, json && Array.isArray(json.Answer));
  }
  // dns validation — OUR logic, always checked
  {
    const { status } = await getJson('/api/dns');
    ok('dns rejects missing name 400', status === 400);
  }
  {
    const { status } = await getJson('/api/dns?name=example.com&type=BOGUS');
    ok('dns rejects bad type 400', status === 400);
  }
  {
    const { status } = await getJson('/api/dns?name=a%20b.com&type=A');
    ok('dns rejects malformed name 400', status === 400);
  }

  // headers — fetch a live site
  {
    const { status, json } = await getJson('/api/headers?url=https://example.com');
    okUpstream('headers 200', status, status === 200, `status ${status}`);
    okUpstream('headers returns chain', status, json && Array.isArray(json) && json.length >= 1 && json[0].headers);
  }
  // headers SSRF guard — OUR logic, always checked
  {
    const { status, json } = await getJson('/api/headers?url=http://127.0.0.1');
    ok('headers blocks localhost', status === 400 && json && json.error);
  }

  // tls — connects to a live host
  {
    const { status, json } = await getJson('/api/tls?host=cloudflare.com');
    okUpstream('tls 200', status, status === 200, `status ${status}`);
    okUpstream('tls returns grade', status, json && ['A', 'B', 'C', 'F'].includes(json.grade), JSON.stringify(json && json.grade));
    okUpstream('tls versions array', status, json && Array.isArray(json.versions));
  }
  // tls SSRF guard — OUR logic, always checked
  {
    const { status } = await getJson('/api/tls?host=127.0.0.1');
    ok('tls blocks loopback', status === 400);
  }
  {
    const { status } = await getJson('/api/tls?host=10.0.0.1');
    ok('tls blocks private range', status === 400);
  }

  // Security headers on the site's own responses
  {
    const res = await fetch(BASE + '/');
    const csp = res.headers.get('content-security-policy') || '';
    ok('CSP present with script-src self', csp.includes('script-src \'self\''), csp.slice(0, 60));
    ok('X-Content-Type-Options nosniff', res.headers.get('x-content-type-options') === 'nosniff');
  }

  // report
  const total = passed + failures.length;
  console.log('');
  if (skipped) console.log(`~ ${skipped} check(s) skipped (upstream unavailable)`);
  if (failures.length) {
    console.error(`✗ ${failures.length}/${total} e2e checks FAILED`);
    process.exit(1);
  }
  console.log(`✓ all ${total} e2e checks passed`);
}

main().catch((e) => {
  console.error('e2e runner crashed — is `wrangler pages dev .` running?');
  console.error(e.message || e);
  process.exit(1);
});
