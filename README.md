# sysadminstuff.net

[![CI](https://github.com/chrismuench/sysadminstuff/actions/workflows/ci.yml/badge.svg)](https://github.com/chrismuench/sysadminstuff/actions/workflows/ci.yml)
[![License: Apache-2.0 + Commons Clause](https://img.shields.io/badge/license-Apache--2.0%20%2B%20Commons%20Clause-blue)](LICENSE)

Clean, ad-free sysadmin tools — DNS, email authentication, TLS, certificates, whois, network, and everyday utilities. Pure HTML/CSS/JS on the frontend with a handful of Cloudflare Pages Functions for the lookups that need a server. **No logs. No tracking. No ads.**

**Live:** https://sysadminstuff.net

---

## Features

### DNS
- **Lookup** — A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, or ALL, via Cloudflare DNS-over-HTTPS. IP input auto-switches to reverse (PTR).
- **Propagation** — the same record across Cloudflare, Google, OpenDNS, Quad9, and AdGuard, with a consistency verdict.

### Email
- **SPF** — parsed mechanisms with plain-English explanations and a policy summary.
- **DMARC** — every tag explained, policy badge (NONE / QUARANTINE / REJECT), report addresses.
- **DKIM** — look up any selector, key type and bit length, testing-mode warning.
- **MX** — priority-ordered hosts with resolved IPs and PTR records.
- **Header Analyzer** — paste raw headers to trace the routing path, per-hop delays, and SPF/DKIM/DMARC results. Runs entirely in your browser.
- **Blacklist** — checks an IP against 15 DNS blacklists.

### Web
- **HTTP Headers** — all response headers plus a 7-point security-header scorecard.
- **Redirects** — the full redirect chain, hop by hop, with status codes.
- **TLS Grade** — protocol/cipher probe and an A–F grade.

### Network
- **ASN Lookup** — ASN or IP details and announced prefixes (bgpview.io).
- **Subnet Calculator** — network/broadcast/mask/range/host-count. 100% in-browser.
- **Geo** — approximate IP geolocation (ip-api.com).
- **Reverse DNS** — PTR lookup with forward-confirmation.

### Cert
- Certificate history via crt.sh — validity badge, SANs, issuer, expiry countdown.

### Whois
- RDAP-based whois for domains and IPs.

### Utils (all client-side, zero network)
- **Base64**, **URL Encode**, **JWT Decoder** — nothing you type leaves your browser.

---

## Privacy

sysadminstuff.net does not log, store, or track queries. No analytics. No cookies. No ads. The utility tools (JWT decoder, Base64, URL encode, subnet calculator) run entirely in your browser and never transmit data. See [PRIVACY.md](PRIVACY.md) for full details.

The only external asset loaded by the page is the JetBrains Mono font from Google Fonts. To eliminate even that request, download the font, drop the `.woff2` files under `css/fonts/`, replace the Google Fonts `<link>` tags in `index.html`/`privacy.html` with a local `@font-face` block in `css/style.css`, and you have a fully self-contained site.

---

## APIs used (with attribution)

- [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) — DNS lookups & blacklist queries
- [crt.sh](https://crt.sh) — certificate transparency logs
- [RDAP via rdap.org](https://rdap.org) / ARIN — whois data
- [ip-api.com](https://ip-api.com) — IP geolocation
- [bgpview.io](https://bgpview.io) — ASN / prefix data
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
js/    app.js dns.js email.js web.js network.js cert.js whois.js utils.js
functions/api/  whois.js rbl.js tls.js headers.js asn.js
tests/ smoke.mjs e2e.mjs README.md
```

---

## Contributing

Issues and PRs welcome. Guidelines:

- No build step and no frontend dependencies — keep it plain HTML/CSS/JS.
- **Never log user input** in a Pages Function (query params, URLs, IPs). See the no-logging rules in [PRIVACY.md](PRIVACY.md).
- No analytics, telemetry, cookies, or third-party scripts (beyond the optional Google Font).
- Add or update a smoke test for anything you change.

---

## License

**Apache-2.0 with the [Commons Clause](https://commonsclause.com/)** — see [LICENSE](LICENSE).

This is *source-available*, not OSI "open source". You may use, modify, and self-host it freely (including internally at a company). What you may **not** do is **Sell** it — that includes hosting it as a paid product or service, or selling support whose value derives substantially from this software. Everything else Apache-2.0 permits.
