# sysadminstuff.net

[![CI](https://github.com/CinderHillsDev/sysadminstuff/actions/workflows/ci.yml/badge.svg)](https://github.com/CinderHillsDev/sysadminstuff/actions/workflows/ci.yml)
[![License: Apache-2.0 + Commons Clause](https://img.shields.io/badge/license-Apache--2.0%20%2B%20Commons%20Clause-blue)](LICENSE)

Clean, ad-free sysadmin tools — DNS, email authentication, TLS, certificates, whois, network, and everyday utilities. Pure HTML/CSS/JS on the frontend with a handful of Cloudflare Pages Functions for the lookups that need a server. **No logs. No tracking. No ads.**

**Live:** https://sysadminstuff.net

---

## Features

### DNS
- **Lookup** — A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, or ALL, via Cloudflare DNS-over-HTTPS. IP input auto-switches to reverse (PTR).
- **Propagation** — the same record across Cloudflare, Google, and DNS.SB, with a consistency verdict. Runs entirely in your browser (these are the public resolvers that expose a browser-usable JSON + CORS DoH API).
- **CAA** — which CAs may issue certificates for a domain (RFC3597-parsed). 
- **DNSSEC** — signed/unsigned status from the AD flag + DS/DNSKEY presence.

### Email
- **SPF** — parsed mechanisms with plain-English explanations and a policy summary.
- **DMARC** — every tag explained, policy badge (NONE / QUARANTINE / REJECT), report addresses.
- **DKIM** — look up any selector, key type and bit length, testing-mode warning.
- **MX** — priority-ordered hosts with resolved IPs and PTR records.
- **Header Analyzer** — paste raw headers to trace the routing path, per-hop delays, and SPF/DKIM/DMARC results. Runs entirely in your browser.
- **Blacklist** — checks an IP against 15 DNS blacklists.
- **Builder** — generate SPF and DMARC TXT records from a form.

### Web
- **HTTP Headers** — all response headers plus a 7-point security-header scorecard.
- **Redirects** — the full redirect chain, hop by hop, with status codes.
- **TLS Grade** — protocol/cipher probe and an A–F grade.

### Network
- **ASN Lookup** — ASN or IP details and announced prefixes (bgpview.io).
- **Subnet Calculator** — network/broadcast/mask/range/host-count. 100% in-browser.
- **CIDR Tools** — is-IP-in-CIDR check and split a CIDR into subnets.
- **Geo** — approximate IP geolocation (ipwho.is).
- **Reverse DNS** — PTR lookup with forward-confirmation.

### Cert
- **Lookup** — certificate history via crt.sh (validity, SANs, issuer, expiry).
- **Decode PEM/CSR** — paste a certificate or CSR and see subject/issuer/SANs/validity/key/signature, parsed entirely in your browser (never uploaded).

### Whois
- RDAP-based whois for domains and IPs.

### M365
- **Microsoft 365 / Entra tenant lookup** — given a domain, resolves the tenant ID (GUID), brand name, and Managed vs. Federated (ADFS) identity, and classifies the **cloud environment: Commercial / GCC / GCC High / DoD** (via OpenID Connect metadata `tenant_region_sub_scope` + cloud instance). Also lists other domains in the tenant. Uses only public, unauthenticated Microsoft endpoints — no login required.

### Cloud
- **Cloud IP** — which cloud owns an IP, with exact AWS region/service (from AWS's published ranges) or ASN-based provider detection for the rest.
- **Fingerprint** — the hosting/CDN, email, and DNS provider behind a domain (inferred from CNAME/MX/NS). Runs in your browser via DoH.
- **ARN** — break an AWS ARN into partition/service/region/account/resource.

### Utils (all client-side, zero network)
- **Base64**, **URL Encode**, **JWT Decoder** — encode/decode/inspect locally.
- **Hash** (MD5, SHA-1/256/384/512), **Password/UUID** generator, **Epoch** converter, **Cron** explainer, **Chmod** calculator, **JSON** formatter, **Base Convert** (hex/dec/oct/bin), **Regex** tester. Nothing you type leaves your browser.

---

## Privacy

sysadminstuff.net does not log, store, or track queries. No analytics. No cookies. No ads. The utility tools (JWT decoder, Base64, URL encode, subnet calculator) run entirely in your browser and never transmit data. See [PRIVACY.md](PRIVACY.md) for full details.

The page makes **no external asset requests at all** — the IBM Plex fonts are self-hosted (`css/fonts/*.woff2`, [SIL OFL](https://opensource.org/license/ofl-1-1)) and every script/style is served from the same origin. Nothing (not even a font request) leaks to a third party on page load.

---

## APIs used (with attribution)

- [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) — DNS lookups & blacklist queries
- [crt.sh](https://crt.sh) — certificate transparency logs
- [RDAP via rdap.org](https://rdap.org) / ARIN — whois data
- [ipwho.is](https://ipwho.is) — IP geolocation
- [bgpview.io](https://bgpview.io) — ASN / prefix data
- Microsoft public endpoints (login.microsoftonline.com/.us OIDC metadata, GetUserRealm, Autodiscover) — M365/Entra tenant lookup, no auth
- DNS blacklists: Spamhaus, SpamCop, Barracuda, SORBS, UCEPROTECT, Mailspike, SpamRats, and others

---

## Run locally

The static files and the Pages Functions run together under Wrangler:

```sh
npx wrangler pages dev .
```

Then open the printed local URL. No `npm install` is required for the frontend — it is plain JS.

### Smoke tests

A dependency-free smoke-test suite lives in `tests/`:

```sh
# Pure-logic unit tests (no network, runs in plain Node):
node tests/smoke.mjs

# End-to-end checks against a running `wrangler pages dev` instance:
npx wrangler pages dev . &          # in one terminal
node tests/e2e.mjs                  # in another (defaults to http://localhost:8788)
```

`node tests/smoke.mjs` exits non-zero on any failure, so it is safe to wire into CI. See [tests/README.md](tests/README.md).

---

## Abuse protection & cost

Hosting is effectively free: static files are unlimited on Pages, and the Functions run on the Workers **free tier — a hard 100,000 requests/day cap that fails closed** (the API tools return errors past the limit; they never bill you). Stay on the free plan and there is no surprise-bill scenario.

The real concern is abuse of the API endpoints (`/api/headers` fetches URLs, `/api/tls` opens sockets, `/api/rbl` fans out). Two defenses:

1. **Code-level (already in the repo):** `functions/_middleware.js` restricts `/api/*` to read methods and rejects oversized URLs. It's stateless, so it's free and always on.
2. **Rate limiting (set this up once, free):** In the Cloudflare dashboard for the zone → **Security → WAF → Rate limiting rules → Create rule**:
   - **If incoming requests match:** `URI Path` `contains` `/api/`
   - **Rate:** `20` requests per `10` seconds, counting by client IP
   - **Action:** Block (or Managed Challenge) for `60` seconds

   The free plan includes one rate-limiting rule — this is a good use of it. Adjust the numbers to taste; 20/10s is generous for a human but stops a script hammering your quota.

## Deploy (Cloudflare Pages)

1. Push this repo to GitHub.
2. Cloudflare Pages dashboard → **Create project** → connect the GitHub repo.
3. Build settings: **no build command**, output directory `/`.
4. Add the custom domain `sysadminstuff.net` (already on Cloudflare — DNS auto-configures).
5. Functions in `functions/` deploy automatically.
6. Every push to `main` auto-deploys both the static files and the functions.

---

## Project structure

```
index.html            privacy.html         wrangler.toml
css/style.css
js/    core.js app.js dns.js email.js web.js network.js cert.js whois.js m365.js cloud.js utils.js tools.js
lib/   parse.mjs
functions/  _middleware.js  api/  whois.js rbl.js tls.js headers.js asn.js tenant.js
tests/ smoke.mjs e2e.mjs README.md
```

---

## Contributing

Issues and PRs welcome. Guidelines:

- No build step and no frontend dependencies — keep it plain HTML/CSS/JS.
- **Never log user input** in a Pages Function (query params, URLs, IPs). See the no-logging rules in [PRIVACY.md](PRIVACY.md).
- No analytics, telemetry, cookies, or third-party scripts. Fonts are self-hosted; the page loads no external assets.
- Add or update a smoke test for anything you change.

---

## License

**Apache-2.0 with the [Commons Clause](https://commonsclause.com/)** — see [LICENSE](LICENSE).

This is *source-available*, not OSI "open source". You may use, modify, and self-host it freely (including internally at a company). What you may **not** do is **Sell** it — that includes hosting it as a paid product or service, or selling support whose value derives substantially from this software. Everything else Apache-2.0 permits.
