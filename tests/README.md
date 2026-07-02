# Tests

Two dependency-free suites — plain Node, no test framework, no `npm install`.

## `smoke.mjs` — pure-logic unit tests

Exercises the exact code that ships:

- `js/core.js` — validators, subnet math, base64, JWT decode, SPF/DMARC parsing
- `lib/parse.mjs` — RDAP shaping, bgpview shaping, security-header scorecard, RBL query building, SSRF host guard

No network, fully deterministic. Exits non-zero on any failure, so CI gates on it.

```sh
node tests/smoke.mjs
```

## `e2e.mjs` — live endpoint checks

Boots nothing itself — point it at a running Pages dev server (or production):

```sh
npx wrangler pages dev .      # terminal 1
node tests/e2e.mjs            # terminal 2

# or against production:
BASE_URL=https://sysadminstuff.net node tests/e2e.mjs
```

It checks static assets, CORS preflight, and every `/api/*` endpoint (whois, asn, rbl, headers, tls) including the SSRF guard and bad-input handling. Because it calls real third-party APIs, an occasional failure can reflect an upstream hiccup rather than a regression — re-run before assuming a break.

## CI

`smoke.mjs` runs on every push/PR via `.github/workflows/ci.yml`. The e2e job boots `wrangler pages dev` and runs `e2e.mjs` as a non-blocking job (upstream flakiness shouldn't fail the build).
