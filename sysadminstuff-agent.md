# sysadminstuff.net — Claude Code Build Spec

A clean, ad-free sysadmin utility site hosted on Cloudflare Pages at sysadminstuff.net.
Pure HTML/CSS/JS frontend. Server-side logic runs in Cloudflare Pages Functions (JS, no Node deps).
Source lives in GitHub (`CinderHillsDev/sysadminstuff`) — Cloudflare Pages auto-deploys on every push to main.

This file is a historical build spec, kept roughly in sync with the live site so it stays useful as a reference — not a strict source of truth. When it and the code disagree, trust the code (and `CLAUDE.md`, which is the authoritative day-to-day guidance for working in this repo).

---

## Architecture

- **Frontend:** Static HTML/CSS/JS — no framework, no build step
- **Shared pure logic:** `lib/parse.mjs` (validators/parsers/shaping used by Functions, importable by Node) and `js/core.js` (same idea for the browser, also `require()`'d by `tests/smoke.mjs`) — one implementation shared between the app and its tests
- **Backend:** Cloudflare Pages Functions in `functions/api/` — auto-routed by Cloudflare. `functions/_middleware.js` gates every `/api/*` request: rejects non-GET/HEAD/OPTIONS, rejects oversized URLs, requires a same-origin `Sec-Fetch-Site` (blocks curl/scripts/other origins), and edge-caches successful GET responses per endpoint via the Cache API
- **DNS:** Domain already on Cloudflare — just point Pages to sysadminstuff.net in dashboard
- **Deploy:** Git push to main → Cloudflare auto-deploys everything (static files + functions)

---

## Project Structure

```
sysadminstuff/
├── CLAUDE.md
├── sysadminstuff-agent.md
├── README.md
├── PRIVACY.md
├── LICENSE                 # Apache-2.0 + Commons Clause (source-available, not OSI open source)
├── wrangler.toml
├── package.json
├── index.html
├── privacy.html
├── css/
│   ├── style.css
│   └── fonts/               # self-hosted IBM Plex Sans/Mono (.woff2, SIL OFL)
├── js/
│   ├── core.js               # pure validators/parsers shared with tests — no DOM, no network
│   ├── app.js                # tab routing, input handling, theme toggle, shared UI helpers
│   ├── dns.js                 # Lookup, Propagation, CAA, DNSSEC
│   ├── email.js                # SPF, SPF Lookups, DMARC, DKIM, MX, Header Analyzer, Blacklist, Builder
│   ├── web.js                   # HTTP Headers, Redirects, TLS Grade
│   ├── network.js                # ASN Lookup, Subnet Calculator, CIDR Tools, Geo, Reverse DNS
│   ├── cert.js                    # Decode PEM/CSR — 100% client-side
│   ├── whois.js                    # calls /api/whois
│   ├── myip.js                      # calls /api/myip
│   ├── m365.js                       # calls /api/tenant
│   ├── cloud.js                       # Cloud IP, Fingerprint, ARN
│   ├── utils.js                        # Base64, URL Encode, JWT Decoder
│   ├── tools.js                         # Hash, Password/Passphrase/UUID, Epoch, Cron, Chmod, JSON, Base Convert, Regex
│   └── wordlist.js                       # bundled EFF short wordlist (CC-BY) for the passphrase generator
├── lib/
│   └── parse.mjs             # pure logic shared by Functions + tests/smoke.mjs (RDAP/ASN shaping, SSRF host-blocking, tenant parsing, SPF term walking…)
├── functions/
│   ├── _middleware.js         # method/URL/origin gate + per-endpoint edge cache for all /api/*
│   └── api/
│       ├── whois.js            # RDAP proxy, falls back to classic whois:43 for TLDs with no RDAP
│       ├── rbl.js               # blacklist/RBL checks across 15 zones
│       ├── tls.js                # TLS reachability probe via Workers connect() — grade A/F
│       ├── headers.js             # fetch a URL server-side, return headers + redirect chain
│       ├── asn.js                  # ASN/IP lookup via bgpview.io
│       ├── tenant.js                # M365/Entra tenant lookup via Microsoft public endpoints
│       ├── myip.js                   # reflects caller's IP/ASN/geo/edge info from request.cf — no upstream call
│       └── dns.js                     # server-side DoH fallback for when direct browser DoH is blocked
└── tests/
    ├── smoke.mjs              # pure-logic unit tests, no network — safe for CI
    ├── e2e.mjs                 # live checks against a running `wrangler pages dev`
    └── README.md
```

There is no `functions/api/crtsh.js` — a crt.sh-backed "Certificate Lookup" tool existed at one point but was removed after crt.sh became unreliable. `js/cert.js` now only holds the client-side PEM/CSR decoder.

---

## Tab Structure

```
DNS         → Lookup | Propagation | CAA | DNSSEC
Email       → SPF | SPF Lookups | DMARC | DKIM | MX | Header Analyzer | Blacklist | Builder
Web         → HTTP Headers | Redirects | TLS Grade
Network     → ASN Lookup | Subnet Calculator | CIDR Tools | Geo | Reverse DNS
Cert        → (single tool — Decode PEM/CSR)
Whois       → (single tool)
My IP       → (single tool — reflects the caller's own address, no query needed)
M365        → (single tool)
Cloud       → Cloud IP | Fingerprint | ARN
Password    → (single tool — Password / Passphrase / UUID, all client-side)
Utils       → Base64 | URL Encode | JWT Decoder | Hash | Epoch | Cron | Chmod | JSON | Base Convert | Regex
```

This order matches the primary tab nav in `index.html` and `DEFAULT_SUBTAB` in `js/app.js`. Tabs whose only subtab is `main` (Whois, My IP, M365, Password, and Cert) render a single panel with no secondary subtab nav. The shared input bar (`js/app.js`'s `SHARED_INPUT_TABS`) is shown for DNS/Email/Web/Network/Whois/M365/Cloud and hidden for My IP/Password/Utils/Cert, since those are fully self-contained.

---

## Design — Light / Dark / System Theme

- Font: self-hosted **IBM Plex Sans** (UI — labels, headings, buttons, tabs) + **IBM Plex Mono** (data — table cells, `pre`/`code`, IDs, hashes). Both loaded from `css/fonts/*.woff2` (SIL OFL) — no Google Fonts, no external requests at all
- Three theme modes, cycled by the header toggle button: **System** (follows `prefers-color-scheme`, live-updates) → **Light** → **Dark**. Persisted in `localStorage` under `sas-theme`. An inline script in `<head>` sets `data-theme` before first paint so there's no flash
- Dark tokens (default): bg `#0b0e14`, surface `#131824`, border `#262c3a`, text `#e8ecf3`, muted `#8891a2`, green `#3fb968`, yellow `#d7a13a`, red `#f0605a`, blue `#5b9df0`, accent `#2dd4de`
- Light tokens: bg `#f5f6f8`, surface `#ffffff`, border `#d9dce2`, text `#1b1f27`, muted `#5b6270`, green `#1a7f4d`, yellow `#8a5d0a`, red `#c62828`, blue `#1868c9`, accent `#0f7a8a`
- Results rendered in monospace-for-data / sans-for-chrome, as above
- Responsive — works on mobile
- Copy buttons on data cells and result blocks (`⧉` on cells, `copy` on cards)

---

## index.html Structure

```html
<header>
  <button id="theme-toggle" class="theme-toggle" aria-label="Toggle color theme">
    <span class="icon"></span><span class="label"></span>
  </button>
  <a href="/" class="home-link">
    <h1><span class="logo-mark">&gt;_</span>sysadminstuff.net</h1>
    <p>Clean sysadmin tools. No ads, no fluff.</p>
  </a>
</header>

<main>
  <div class="input-bar" id="input-bar">
    <input id="query" type="text" placeholder="domain, hostname, or IP address" autofocus />
    <button id="run-btn">Run</button>
  </div>

  <nav class="tabs primary" id="primary-tabs">
    <button class="tab active" data-tab="dns">DNS</button>
    <button class="tab" data-tab="email">Email</button>
    <button class="tab" data-tab="web">Web</button>
    <button class="tab" data-tab="network">Network</button>
    <button class="tab" data-tab="cert">Cert</button>
    <button class="tab" data-tab="whois">Whois</button>
    <button class="tab" data-tab="myip">My IP</button>
    <button class="tab" data-tab="m365">M365</button>
    <button class="tab" data-tab="cloud">Cloud</button>
    <button class="tab" data-tab="password">Password</button>
    <button class="tab" data-tab="utils">Utils</button>
  </nav>

  <!-- DNS — representative example of a multi-subtab tab -->
  <div id="tab-dns" class="tab-panel active">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="lookup">Lookup</button>
      <button class="subtab" data-subtab="propagation">Propagation</button>
      <button class="subtab" data-subtab="caa">CAA</button>
      <button class="subtab" data-subtab="dnssec">DNSSEC</button>
    </nav>
    <div class="subpanel active" id="panel-dns-lookup"></div>
    <div class="subpanel" id="panel-dns-propagation"></div>
    <div class="subpanel" id="panel-dns-caa"></div>
    <div class="subpanel" id="panel-dns-dnssec"></div>
  </div>

  <!-- Email / Web / Network / Cloud / Utils follow the same nav+subpanel
       pattern — see Tab Structure above for the exact subtab list per tab. -->

  <!-- Single-tool tabs have no secondary nav, just one subpanel -->
  <div id="tab-cert" class="tab-panel">
    <div class="subpanel active" id="panel-cert-main"></div>
  </div>
  <div id="tab-whois" class="tab-panel">
    <div class="subpanel active" id="panel-whois-main"></div>
  </div>
  <div id="tab-myip" class="tab-panel">
    <div class="subpanel active" id="panel-myip-main"></div>
  </div>
  <div id="tab-m365" class="tab-panel">
    <div class="subpanel active" id="panel-m365-main"></div>
  </div>
  <div id="tab-password" class="tab-panel">
    <div class="subpanel active" id="panel-password-main"></div>
  </div>
</main>

<footer>
  No logs. No tracking. No ads. Queries are not stored or recorded.
  <a href="/privacy">Privacy</a> ·
  Source available · <a href="https://github.com/CinderHillsDev/sysadminstuff">GitHub</a>
</footer>
```

- Enter key triggers Run
- Switching tabs/subtabs re-runs if the query changed (`lastRan` memo per tab:sub key avoids redundant re-fetches)
- Spinner/loading state per panel
- Copy icon on all result blocks
- URL params: `?q=example.com&tab=dns&sub=propagation` — updated via `history.pushState`, restored on load and on popstate
- Small tooltip (`data-tip`) on each subtab explaining what it does
- Utils/Password/My IP/Cert tabs ignore the shared input bar — each has its own inputs or needs none

---

## Cloudflare Pages Functions

Each file in `functions/api/` exports an `onRequest` handler.
All functions return `Content-Type: application/json`, set `Access-Control-Allow-Origin: *`, and handle `OPTIONS` preflight. None of them ever log user input — see Privacy Requirements below. `functions/_middleware.js` runs in front of all of them.

### functions/api/whois.js
- Detect IP vs domain from `?q=` param
- Domains: RDAP via `rdap.org`, plus a small set of registry overrides for TLDs missing from the IANA bootstrap (`RDAP_BOOTSTRAP_OVERRIDES` in `lib/parse.mjs`)
- If a TLD has no RDAP support at all, falls back to classic whois: ask `whois.iana.org` for the TLD's referral server over TCP 43 (via `cloudflare:sockets` `connect()`), then query that server and return the raw text
- IPs: RDAP via `rdap.arin.net`
- SSRF guard (`isBlockedHost`) rejects internal/reserved targets before any upstream call

### functions/api/rbl.js
Check 15 blacklists — reverse the IP's octets, prepend to each zone, do an A lookup via Cloudflare DoH. A resolving answer means listed. All 15 run in parallel.

Zones checked:
`zen.spamhaus.org`, `bl.spamcop.net`, `b.barracudacentral.org`, `dnsbl.sorbs.net`, `spam.dnsbl.sorbs.net`, `cbl.abuseat.org`, `dnsbl-1.uceprotect.net`, `dnsbl-2.uceprotect.net`, `bl.mailspike.net`, `hostkarma.junkemailfilter.com`, `noptr.spamrats.com`, `spam.spamrats.com`, `dyna.spamrats.com`, `ix.dnsbl.manitu.net`, `db.wpbl.info`.

Return: `[{ list, listed: bool, response }]`

### functions/api/tls.js
Uses the Cloudflare Workers `connect()` TCP API to probe TLS reachability — **not** a full protocol/cipher matrix. Workers can't pin a specific TLS version per socket, so the check is:
- Attempt a handshake with `secureTransport: 'on'` (Workers negotiate modern TLS 1.2/1.3 and validate the certificate chain)
- Success → **grade A** ("modern TLS + valid cert"); the exact negotiated version/cipher isn't exposed by the platform, so it's reported as "TLS 1.2 / 1.3" together
- Failure → **grade F**, with a best-effort reason (certificate problem, timeout, other handshake failure)
- Legacy TLS 1.0/1.1 can't be probed this way (Workers won't negotiate down to them), so there is no B/C grade tier — it's binary
- Only ever probes port 443, to avoid becoming an arbitrary internal port scanner
- SSRF guard (`hostResolvesToBlocked`) resolves DNS and rejects internal/reserved targets before connecting

### functions/api/headers.js
- Accept `?url=` param
- Fetch target server-side, follow redirects manually hop by hop (capped at `MAX_HOPS`)
- Return: `[{ url, status, headers }]` for each hop in the redirect chain
- Final entry is the destination
- SSRF-guarded; the caller's IP is never forwarded upstream

### functions/api/asn.js
- Accept `?q=` param — ASN number (`AS13335` or `13335`) or IP address
- ASN → `https://api.bgpview.io/asn/{asn}`
- IP → `https://api.bgpview.io/ip/{ip}`
- Return: ASN, name, country, description, announced prefixes (shaped by `lib/parse.mjs`)

### functions/api/tenant.js
Microsoft 365 / Entra ID tenant lookup using public, unauthenticated Microsoft endpoints — no login, no API key.
- OpenID Connect metadata (`login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration`) → tenant GUID, region + sub-scope, cloud instance → classified into Commercial / GCC / GCC High / DoD
- `GetUserRealm` → brand name, Managed vs. Federated (ADFS) identity
- `GetFederationInformation` (SOAP/Autodiscover) → other domains in the same tenant, best-effort

### functions/api/myip.js
Reflects the caller's own public IP and whatever Cloudflare already knows about the request (`CF-Connecting-IP`, `request.cf`: ASN, org, city/region/country, colo, TLS version/cipher, HTTP protocol). No upstream call at all — everything comes from the edge for free, so it's never cached (the response is inherently per-request).

### functions/api/dns.js
Server-side DNS-over-HTTPS fallback. The browser queries public DoH resolvers directly first (`js/app.js`'s `dohQuery`); this endpoint exists only for networks that block direct DoH (corporate proxies, captive portals) so DNS-backed tools keep working via same-origin `/api/dns`. Not a user-facing "feature" on its own — it's plumbing behind DNS/CAA/DNSSEC/MX/SPF/RBL/etc.

---

## Frontend Modules

### js/dns.js

**Lookup subtab:**
- Record type pills: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, ALL
- Queries via `window.dohQuery` — tries the public resolver directly from the browser first, falls back to `/api/dns` if that's blocked
- ALL: runs all non-PTR types in parallel, groups results by type
- PTR: auto-reverses an IP input (`1.2.3.4` → `4.3.2.1.in-addr.arpa`)
- Display: table per type — Name | TTL | Type | Data

**Propagation subtab:**
- Queries the same record across 3 resolvers in parallel, straight from the browser (no backend hop for the common case): **Cloudflare**, **Google**, **DNS.SB**
- Table: Resolver | Answer | TTL | Status
- All agree → green "propagated consistently" summary; any differ → grey/yellow

**CAA subtab:**
- Looks up the `CAA` record type; parses flags/tag/value
- No CAA records → warns that *any* CA may issue for the domain
- Summarizes which CAs are authorized to issue (from `issue`/`issuewild` tags)

**DNSSEC subtab:**
- Queries A (for the resolver's `AD` flag), DS, and DNSKEY in parallel
- Signed if the `AD` flag is set or DS records exist in the parent zone
- Shows AD flag / DS record count / DNSKEY count, plus the raw DS records if present

---

### js/email.js

**SPF subtab:**
- TXT lookup on the bare domain via Cloudflare DoH; finds the `v=spf1` record
- Display raw record + parsed mechanisms table with plain-English explanations
- Qualifiers explained: `+` pass, `-` fail, `~` softfail, `?` neutral

**SPF Lookups subtab:**
- Walks the full `include`/`redirect` tree recursively and counts DNS lookups against **RFC 7208 §4.6.4**: at most 10 lookups, at most 2 "void" lookups (no records returned) — exceeding either is a PermError
- Flags dead includes, cycles, and void `a`/`mx` targets in the tree
- `exists` mechanisms are counted but never resolved (an NXDOMAIN there is a normal macro-driven existence test, not an error)

**DMARC subtab:**
- TXT lookup on `_dmarc.{domain}`; parses all tags (v, p, sp, pct, rua, ruf, adkim, aspf, fo, ri)
- Policy badge: NONE (grey) / QUARANTINE (yellow) / REJECT (green)
- Warns if `p=none`: monitoring mode only

**DKIM subtab:**
- Selector input; TXT lookup on `{selector}._domainkey.{domain}`
- Parses v, k, p (truncated + bit length), t; warns on `t=y` (testing mode)

**MX subtab:**
- MX lookup; for each host resolves IPs and does a PTR lookup on each
- Table: Priority | MX Host | IP(s) | PTR Record | PTR Match ✓/✗

**Header Analyzer subtab:**
- Paste raw email headers; parses the `Received:` chain in reverse with per-hop delays
- Extracts SPF/DKIM/DMARC authentication results, X-Spam headers, Message-ID, Date
- Runs entirely client-side

**Blacklist subtab:**
- Input: IP or domain (resolves domain to IP first)
- Calls `/api/rbl?ip={ip}` — table of all 15 zones, listed = red, clean = green

**Builder subtab:**
- Form-based SPF record builder (ip4 list, includes, a/mx flags, `~all`/`-all`/`?all` policy) and DMARC record builder (policy, pct, alignment mode, rua) — generates the raw TXT record text, entirely client-side

---

### js/web.js

**HTTP Headers subtab:**
- Calls `/api/headers?url={url}`; displays all response headers
- 7-point security-header scorecard: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`

**Redirects subtab:**
- Uses the same `/api/headers` endpoint; displays each hop (Step | URL | Status | Location)
- 301 = green (permanent), 302 = yellow (temporary); warns past 3 hops

**TLS Grade subtab:**
- Calls `/api/tls?host={hostname}`
- Grade badge is **A or F only** (see the `functions/api/tls.js` section above for why) — a successful modern-TLS handshake with a valid cert is A, anything else is F

---

### js/network.js

**ASN Lookup subtab:**
- Input: ASN (`AS13335` or `13335`) or IP; calls `/api/asn?q={query}`
- Displays ASN, org name, country, description, announced prefixes

**Subnet Calculator subtab:**
- Input: CIDR or IP + mask — entirely client-side, no API
- Network/broadcast address, mask + wildcard, usable host range, host count, IP class

**CIDR Tools subtab:**
- Is-IP-in-CIDR check, and splitting a CIDR into smaller subnets — entirely client-side

**Geo subtab:**
- Resolves hostname → IP via DoH first if needed
- `GET https://ipwho.is/{ip}` (HTTPS + CORS, no API key, callable directly from the browser)
- Displays IP, country + flag, region, city, ISP, org, ASN; notes geolocation is approximate

**Reverse DNS subtab:**
- PTR lookup via DoH (auto-reverses the IP), then forward-confirms by resolving the PTR hostname back and checking the match

---

### js/cert.js — Decode PEM/CSR (100% client-side)

- Paste a PEM certificate (`-----BEGIN CERTIFICATE-----`) or CSR (`-----BEGIN CERTIFICATE REQUEST-----`)
- Parsed entirely in the browser via `window.parseCertificate`/`window.parseCsr` (implemented in `js/core.js`, shared with `tests/smoke.mjs`) — nothing is ever uploaded
- Certificate view: status badge (VALID/EXPIRING SOON ≤30 days/EXPIRED), subject, issuer, SANs, serial, validity window, public key (algorithm + size), signature algorithm
- CSR view: subject, requested SANs, public key, signature algorithm
- This is the only thing left in the Cert tab. A `functions/api/crtsh.js` proxy backed a second "Lookup" subtab (certificate-transparency history from crt.sh) that was removed once crt.sh became unreliable — see the git history around the "Cert" tab if that's ever worth reviving with a different CT-log source.

---

### js/whois.js

- Detects IP vs domain, calls `/api/whois?q={query}`
- Domains: Registrar, status flags, Created, Updated, Expires, name servers (falls back to classic whois:43 text for TLDs with no RDAP — rendered as-is)
- IPs: Network name, CIDR, country, org, abuse contact
- Fallback link to `https://lookup.icann.org` if the result is empty

---

### js/myip.js

- Self-contained — needs no query, runs as soon as the tab opens
- Calls `/api/myip`; big copyable IP up top, then network (ASN/org/location/postal/timezone/coordinates) and connection (Cloudflare colo, HTTP protocol, TLS version/cipher, user agent) tables
- Cross-links into Whois / ASN / Geo / Reverse DNS / Blacklist, pre-filled with the detected IP

---

### js/m365.js

- Single query input (domain); calls `/api/tenant?domain={domain}`
- Shows tenant ID, brand name, Managed vs. Federated identity, cloud environment badge (Commercial/GCC/GCC High/DoD), and other domains in the tenant

---

### js/cloud.js

**Cloud IP subtab:**
- Resolves input to an IP, rejects private/reserved addresses
- First tries an exact match against AWS's published ranges (`ip-ranges.amazonaws.com/ip-ranges.json`) for precise region + service
- Falls back to classifying the ASN org (via `ipwho.is` connection/ISP field) for non-AWS providers

**Fingerprint subtab:**
- Infers the hosting/CDN, email, and DNS provider behind a domain from its CNAME/MX/NS records — runs in the browser via DoH

**ARN subtab:**
- Breaks an AWS ARN into partition/service/region/account/resource — entirely client-side

---

### js/utils.js — Base64, URL Encode, JWT Decoder (all client-side, no network)

- **Base64:** two textareas, encode/decode, auto-detects base64 input and defaults to decode
- **URL Encode:** two textareas, `encodeURIComponent`/`decodeURIComponent`
- **JWT Decoder:** auto-decodes on input (no button); header/payload/signature sections, `exp` shown as a human-readable date highlighted red if expired, notes that verifying the signature requires the secret/key

`b64EncodeUtf8`/`b64DecodeUtf8`/`looksLikeBase64`/`decodeJwtParts` live in `js/core.js` so the browser and `tests/smoke.mjs` share one implementation.

---

### js/tools.js — Hash, Password/Passphrase/UUID, Epoch, Cron, Chmod, JSON, Base Convert, Regex (all client-side)

- **Hash** (registered under the Utils tab): live MD5, SHA-1/256/384/512 as you type, via `crypto.subtle` (+ a bundled MD5 implementation, since SubtleCrypto doesn't support it)
- **Password / Passphrase / UUID** (its own top-level Password tab): cryptographically random password generator (length, character-set toggles, "avoid ambiguous characters" I/l/1/i/O/0/o/|) with an entropy readout; passphrase generator drawing from the bundled EFF short wordlist (`js/wordlist.js`, 1296 words) with separator/capitalize/number/symbol options and its own entropy readout; UUID v4 via `crypto.randomUUID()`
- **Epoch:** Unix timestamp ↔ human date, both directions
- **Cron:** explains a cron expression in plain English + next run times
- **Chmod:** octal ↔ symbolic permission calculator
- **JSON:** format / validate / minify
- **Base Convert:** hex/dec/oct/bin conversion
- **Regex:** test a pattern against sample text with match highlighting

All of `crypto.getRandomValues`/`crypto.subtle`/`crypto.randomUUID` — nothing here ever leaves the browser.

---

### js/app.js — Shared Utilities

```javascript
// Registry — modules call this instead of exposing window.runX directly
function registerRunner(tab, subtab, fn) { RUNNERS[`${tab}:${subtab}`] = fn; }

// URL param handling
function getParams() { ... }               // parse ?q=&tab=&sub=
function setParams(q, tab, sub) { ... }    // history.pushState

// UI helpers
function showLoading(panel, label) { ... }
function showError(panel, message) { ... }
function showResult(panel, html) { ... }
function card(title, bodyHtml, copyText) { ... }
function wireCopyButtons(root) { ... }
function copyToClipboard(text) { ... }

// Input helpers
function hostFromInput(str) { ... }        // isIP/isDomain from core.js, else URL().hostname

// Shared DNS resolution — tries public DoH straight from the browser first
// (free, no Worker invocation), falls back to /api/dns only when that's blocked
async function dohQuery(name, type, resolver = 'cloudflare') { ... }
async function resolveToIP(hostname) { ... }

// Theme (system / light / dark), persisted to localStorage as 'sas-theme'
function applyTheme(mode) { ... }
function initTheme() { ... }

// Tab/subtab activation, driven by SHARED_INPUT_TABS / NO_QUERY_SUBTABS / DEFAULT_SUBTAB
function activate(tab, sub, opts) { ... }
```

Pure validators (`isIP`, `isIPv4`, `isIPv6`, `isDomain`, `isCIDR`, `isASN`, `isURL`, `normalizeURL`) live in `js/core.js`, not `app.js` — that keeps a single implementation shared with `tests/smoke.mjs`.

---

## Error Handling

- Network errors: "Could not reach [service]. Try again shortly."
- No records found: "No [type] records found for [domain]."
- Invalid input: validated before running, inline error in the panel
- Upstream rate limits: surfaced as a plain-English error from the relevant function (e.g. bgpview.io/ipwho.is/RDAP being slow or rate-limited); the API never bills you past Cloudflare's free-tier request cap
- All errors styled red (`showError`), non-blocking — each panel fails independently, one broken API never breaks another tab

---

## wrangler.toml

```toml
name = "sysadminstuff"
pages_build_output_dir = "."
compatibility_date = "2025-07-01"
```

---

## Cloudflare Pages Setup (for README)

1. Push repo to GitHub
2. Cloudflare Pages dashboard → Create project → Connect GitHub repo
3. Build settings: no build command, output directory `/`
4. Custom domain: add `sysadminstuff.net` (already on Cloudflare — auto-configures DNS)
5. Functions deploy automatically from `functions/` folder
6. Every push to main auto-deploys both static files and functions

---

## README.md

- One paragraph description
- Live link: https://sysadminstuff.net
- Full feature list organized by tab
- APIs used with attribution: Cloudflare DoH, RDAP/ARIN, ipwho.is, bgpview.io, AWS published IP ranges, Microsoft public endpoints, DNS blacklists (Spamhaus et al) — no crt.sh
- Run locally: `npx wrangler pages dev .` (runs static files + functions together)
- Smoke/e2e test instructions
- Abuse protection & cost section (Workers free-tier cap, middleware defenses, optional Cloudflare rate-limiting rule)
- Cloudflare Pages deploy steps
- Project structure
- Contributing guide
- **License: Apache-2.0 + Commons Clause** (source-available, not MIT — see `LICENSE`)

---

## Implementation Notes for Claude Code

- No npm required for the frontend — plain JS files only; `package.json` exists only for `eslint` (devDependency) and the `npm test`/`npm run lint` scripts
- For local dev with Functions: `npx wrangler pages dev .`
- Each `js/<tab>.js` module registers its run function via `window.registerRunner(tab, subtab, fn)` — it does **not** assign `window.runX` directly
- Each `functions/api/*.js` must export `onRequest` as a named export
- All functions must set `Access-Control-Allow-Origin: *` and handle OPTIONS preflight
- Test domains: `google.com`, `github.com`, `cloudflare.com`
- Test IP: `1.1.1.1`
- Test ASN: `AS13335` (Cloudflare)
- Utils/Password/My IP tabs work with zero network — fully offline capable (My IP is the odd one: it calls `/api/myip`, but that endpoint has no upstream dependency of its own)
- Keep each js/ file and each function independently testable — add/update a `tests/smoke.mjs` check for any pure-logic change
- The shared input bar is hidden for tabs in `NO_QUERY_SUBTABS`/outside `SHARED_INPUT_TABS` (Utils, Password, My IP, Cert)

---

## Privacy Requirements — Non-Negotiable

This is a privacy-first tool. Users must be able to trust that nothing they type is stored or tracked.

### Cloudflare Pages Functions — strict no-logging rules

Every function in `functions/api/` must follow these rules:

- **Never log user input.** No `console.log`, `console.error`, or any logging of:
  - Query parameters (`q`, `url`, `ip`, `host`, or any user-supplied value)
  - Request URLs (which contain user input)
  - Client IP addresses
  - Any derived data from user input
- Logging is permitted only for internal errors with no user data attached:
  ```javascript
  // ALLOWED
  console.error('RDAP fetch failed:', response.status);

  // NEVER DO THIS
  console.error('RDAP fetch failed for query:', query);
  console.log('Request from IP:', request.headers.get('CF-Connecting-IP'));
  ```
- No third-party analytics, telemetry, or error-tracking services (no Sentry, no Datadog, nothing)
- Do not forward the user's IP to upstream APIs where avoidable. Do not include `X-Forwarded-For` headers in upstream requests from functions.

### Frontend — no tracking

- No Google Analytics, no Plausible, no Fathom, no tracking pixels, no beacon calls
- No cookies set anywhere — not even session cookies
- No localStorage or sessionStorage used for anything beyond UI state (selected theme, last selected tab)
- No external scripts or assets loaded at all — even the fonts (IBM Plex Sans/Mono) are self-hosted, so nothing leaks to a third party just from loading the page

### Client-side only tools — reinforce in UI

These tools never send data anywhere and must display a visible note saying so:

- **Cert → Decode PEM/CSR:** certificate/CSR parsing never leaves the browser
- **Password tab (Password / Passphrase / UUID):** generated with a cryptographic RNG, never transmitted
- **Network → Subnet Calculator, Network → CIDR Tools:** calculated entirely in your browser
- **Email → Header Analyzer, Email → Builder:** parsed/built entirely in your browser
- **Utils → Base64, URL Encode, JWT Decoder, Hash, Epoch, Cron, Chmod, JSON, Base Convert, Regex:** encoded/decoded/computed entirely in your browser

### Privacy notice on the page

Short privacy line in the footer, visible on every tab:

```html
<footer>
  No logs. No tracking. No ads.
  Queries are not stored or recorded.
  <a href="/privacy">Privacy</a> ·
  Source available · <a href="https://github.com/CinderHillsDev/sysadminstuff">GitHub</a>
</footer>
```

### PRIVACY.md — repo root

Plain English, no legal boilerplate. Covers:
- What data we collect: nothing. Queries are not logged or stored.
- Cloudflare: as the hosting provider, Cloudflare may collect standard infrastructure metrics (request counts, error rates) but we do not have access to query content and do not enable Cloudflare Web Analytics.
- Fonts: self-hosted, so no font request ever reaches a third party.
- Third-party APIs: queries are sent to public APIs (Cloudflare DoH, RDAP registries, ipwho.is, bgpview.io, AWS published IP ranges, Microsoft public endpoints) to perform lookups — this is inherent to how the tools work. These services have their own privacy policies. We do not forward the caller's IP to them where it can be avoided.
- No cookies, no localStorage for personal data, no tracking of any kind.
- Contact: link to GitHub issues for questions.

### README — privacy section

Dedicated Privacy section in README.md:
- "sysadminstuff.net does not log, store, or track queries."
- "No analytics. No cookies. No ads."
- "The fully client-side tools (Subnet Calculator, Cert Decode PEM/CSR, Password/Passphrase/UUID, and everything under Utils) run entirely in your browser and never transmit data."
- Link to PRIVACY.md for full details.
