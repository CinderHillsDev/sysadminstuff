# sysadminstuff.net — Claude Code Build Spec

A clean, ad-free sysadmin utility site hosted on Cloudflare Pages at sysadminstuff.net.
Pure HTML/CSS/JS frontend. Server-side logic runs in Cloudflare Pages Functions (JS, no Node deps).
Source lives in GitHub — Cloudflare Pages auto-deploys on every push to main.

---

## Architecture

- **Frontend:** Static HTML/CSS/JS — no framework, no build step
- **Backend:** Cloudflare Pages Functions in `functions/api/` — auto-routed by Cloudflare
- **DNS:** Domain already on Cloudflare — just point Pages to sysadminstuff.net in dashboard
- **Deploy:** Git push to main → Cloudflare auto-deploys everything

---

## Project Structure

```
sysadminstuff/
├── CLAUDE.md
├── wrangler.toml
├── index.html
├── css/
│   └── style.css
├── js/
│   ├── app.js              # tab routing, input handling, shared utils
│   ├── dns.js              # DNS lookup + propagation
│   ├── email.js            # SPF, DMARC, DKIM, MX, header analyzer, RBL
│   ├── web.js              # HTTP headers, redirect chain, TLS grade
│   ├── network.js          # ASN lookup, subnet calc, geo, reverse DNS
│   ├── cert.js             # cert info via crt.sh
│   ├── whois.js            # calls /api/whois
│   └── utils.js            # base64, URL encode, JWT decoder
├── functions/
│   └── api/
│       ├── whois.js        # proxies RDAP lookup, avoids CORS
│       ├── rbl.js          # blacklist/RBL checks across 15 lists
│       ├── tls.js          # TLS grade — protocol + cipher negotiation
│       ├── headers.js      # fetch URL server-side, return headers + redirect chain
│       └── asn.js          # ASN lookup via bgpview.io
└── README.md
```

---

## Tab Structure

```
DNS         → Lookup | Propagation
Email       → SPF | DMARC | DKIM | MX | Header Analyzer | Blacklist
Web         → HTTP Headers | Redirects | TLS Grade
Network     → ASN Lookup | Subnet Calculator | Geo | Reverse DNS
Cert        → (single tool)
Whois       → (single tool)
Utils       → Base64 | URL Encode | JWT Decoder
```

---

## Design — Dark Terminal Theme

- Background: `#0d1117`
- Surface/cards: `#161b22`
- Border: `#30363d`
- Primary text: `#e6edf3`
- Muted text: `#8b949e`
- Green (OK/valid): `#3fb950`
- Yellow (warning): `#d29922`
- Red (error/expired): `#f85149`
- Blue (links/accent): `#58a6ff`
- Font: `'JetBrains Mono', 'Fira Code', monospace` — load JetBrains Mono from Google Fonts
- Results rendered in monospace, terminal-style
- Responsive — works on mobile
- Subtle animated cursor blink on the input field

---

## index.html Structure

```html
<header>
  <h1>sysadminstuff.net</h1>
  <p>Clean sysadmin tools. No ads, no fluff.</p>
</header>

<main>
  <div class="input-bar">
    <input id="query" type="text" placeholder="domain, hostname, or IP address" autofocus />
    <button id="run-btn">Run</button>
  </div>

  <nav class="tabs primary">
    <button class="tab active" data-tab="dns">DNS</button>
    <button class="tab" data-tab="email">Email</button>
    <button class="tab" data-tab="web">Web</button>
    <button class="tab" data-tab="network">Network</button>
    <button class="tab" data-tab="cert">Cert</button>
    <button class="tab" data-tab="whois">Whois</button>
    <button class="tab" data-tab="utils">Utils</button>
  </nav>

  <!-- DNS -->
  <div id="tab-dns" class="tab-panel active">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="lookup">Lookup</button>
      <button class="subtab" data-subtab="propagation">Propagation</button>
    </nav>
  </div>

  <!-- Email -->
  <div id="tab-email" class="tab-panel">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="spf">SPF</button>
      <button class="subtab" data-subtab="dmarc">DMARC</button>
      <button class="subtab" data-subtab="dkim">DKIM</button>
      <button class="subtab" data-subtab="mx">MX</button>
      <button class="subtab" data-subtab="headers">Header Analyzer</button>
      <button class="subtab" data-subtab="rbl">Blacklist</button>
    </nav>
  </div>

  <!-- Web -->
  <div id="tab-web" class="tab-panel">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="httpheaders">HTTP Headers</button>
      <button class="subtab" data-subtab="redirects">Redirects</button>
      <button class="subtab" data-subtab="tls">TLS Grade</button>
    </nav>
  </div>

  <!-- Network -->
  <div id="tab-network" class="tab-panel">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="asn">ASN Lookup</button>
      <button class="subtab" data-subtab="subnet">Subnet Calculator</button>
      <button class="subtab" data-subtab="geo">Geo</button>
      <button class="subtab" data-subtab="rdns">Reverse DNS</button>
    </nav>
  </div>

  <div id="tab-cert" class="tab-panel"></div>
  <div id="tab-whois" class="tab-panel"></div>

  <!-- Utils — each tool is self-contained, no shared input bar -->
  <div id="tab-utils" class="tab-panel">
    <nav class="tabs secondary">
      <button class="subtab active" data-subtab="base64">Base64</button>
      <button class="subtab" data-subtab="urlencode">URL Encode</button>
      <button class="subtab" data-subtab="jwt">JWT Decoder</button>
    </nav>
  </div>
</main>

<footer>
  Open source · <a href="https://github.com/YOUR_GITHUB/sysadminstuff">GitHub</a>
</footer>
```

- Enter key triggers Run
- Switching tabs/subtabs re-runs if query changed
- Spinner/loading state per panel
- Copy icon on all result blocks
- URL params: `?q=example.com&tab=dns&sub=propagation` — update via history.pushState
- Small "?" tooltip on each subtab explaining what it does
- Utils tab ignores the shared input bar — each util has its own inputs

---

## Cloudflare Pages Functions

Each file in `functions/api/` exports an `onRequest` handler.
All functions return `Content-Type: application/json`.
All functions handle CORS with `Access-Control-Allow-Origin: *`.
All functions handle OPTIONS preflight requests.

### functions/api/whois.js
- Detect IP vs domain from `?q=` param
- Domain → `https://rdap.org/domain/{query}`
- IP → `https://rdap.arin.net/registry/ip/{query}`
- Return parsed RDAP JSON

### functions/api/rbl.js
Check these 15 blacklists — reverse IP octets, prepend to zone, do A lookup.
If it resolves = listed. Run all 15 in parallel.

Zones to check:
- `zen.spamhaus.org`
- `bl.spamcop.net`
- `b.barracudacentral.org`
- `dnsbl.sorbs.net`
- `spam.dnsbl.sorbs.net`
- `cbl.abuseat.org`
- `dnsbl-1.uceprotect.net`
- `dnsbl-2.uceprotect.net`
- `bl.mailspike.net`
- `hostkarma.junkemailfilter.com`
- `noptr.spamrats.com`
- `spam.spamrats.com`
- `dyna.spamrats.com`
- `ix.dnsbl.manitu.net`
- `db.wpbl.info`

Return: `[{ list, listed: bool, response }]`

### functions/api/tls.js
Use Cloudflare Workers `connect()` TCP API:
- Attempt TLS 1.0, 1.1, 1.2, 1.3 connections to the host
- Report which versions accepted/rejected
- Report negotiated cipher suite per successful connection
- Check: self-signed, expired, hostname mismatch
- Grade: A (TLS 1.3 only or 1.2+1.3 strong ciphers), B (TLS 1.2 weak ciphers), C (TLS 1.1 accepted), F (TLS 1.0 accepted or expired cert)

### functions/api/headers.js
- Accept `?url=` param
- Fetch target server-side, follow redirects manually (step by step)
- Return: `[{ url, status, headers }]` for each hop in the redirect chain
- Final entry is the destination

### functions/api/asn.js
- Accept `?q=` param — ASN number (AS13335 or 13335) or IP address
- ASN → `https://api.bgpview.io/asn/{asn}`
- IP → `https://api.bgpview.io/ip/{ip}`
- Return: ASN, name, country, description, announced prefixes

---

## Frontend Modules

### js/dns.js

**Lookup subtab:**
- Record type pills: A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, ALL
- Cloudflare DoH: `https://cloudflare-dns.com/dns-query?name={domain}&type={type}`
  - Header: `Accept: application/dns-json`
- ALL: run all types in parallel via Promise.all, group results by type
- PTR: auto-reverse IP input (1.2.3.4 → 4.3.2.1.in-addr.arpa)
- Display: table per type — Name | TTL | Type | Data

**Propagation subtab:**
- Query same record across 5 resolvers in parallel:
  - Cloudflare: `https://cloudflare-dns.com/dns-query`
  - Google: `https://dns.google/resolve`
  - OpenDNS: `https://doh.opendns.com/dns-query`
  - Quad9: `https://dns.quad9.net/dns-query`
  - AdGuard: `https://dns.adguard.com/dns-query`
- Table: Resolver | Answer | TTL | Status
- All agree → green summary; any differ → yellow warning
- "✓ Propagated consistently" or "⚠ Inconsistent — may still be propagating"

---

### js/email.js

**SPF subtab:**
- TXT lookup on bare domain via Cloudflare DoH
- Find record starting with `v=spf1`
- Display raw record + parsed mechanisms table: Mechanism | Value | Plain English
- Qualifiers explained: `+` pass, `-` fail, `~` softfail, `?` neutral
- Mechanisms explained: ip4, ip6, include, a, mx, exists, redirect, exp, all
- Summary card: overall policy in plain English
- If none found: "No SPF record found"

**DMARC subtab:**
- TXT lookup on `_dmarc.{domain}`
- Parse all tags: v, p, sp, pct, rua, ruf, adkim, aspf, fo, ri
- Display raw record + parsed tag table: Tag | Value | Plain English
- Summary card: policy badge NONE (grey) / QUARANTINE (yellow) / REJECT (green)
- Show report addresses, pct value
- Warning if `p=none`: "Monitoring mode only — mail will not be rejected"

**DKIM subtab:**
- Selector input (placeholders: google, selector1, default, mail)
- TXT lookup on `{selector}._domainkey.{domain}`
- Parse: v, k, p (truncated + bit length), t
- Warning if `t=y`: "Testing mode — failures won't affect delivery"

**MX subtab:**
- MX lookup, for each host: resolve to IPs, do PTR lookup on each IP
- Table: Priority | MX Host | IP(s) | PTR Record | PTR Match ✓/✗
- Flag PTR mismatches in yellow

**Header Analyzer subtab:**
- Large textarea: "Paste raw email headers here"
- Parse `Received:` chain in reverse — show each hop, timestamp, delay between hops
- Extract: SPF/DKIM/DMARC authentication results, X-Spam headers, Message-ID, Date
- Authentication results highlighted: pass = green, fail = red, none = grey
- Routing path displayed as a visual chain

**Blacklist subtab:**
- Input: IP or domain (resolve domain to IP first)
- Calls `/api/rbl?ip={ip}`
- Table: Blacklist | Status | Response
- Listed = red, Clean = green
- Summary: "Listed on X of 15 checked blacklists"

---

### js/web.js

**HTTP Headers subtab:**
- Calls `/api/headers?url={url}` 
- Display all response headers: Header | Value
- Security headers section — check presence of:
  - `Strict-Transport-Security` 
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `X-XSS-Protection`
- Present = green, Missing = yellow
- Overall security score: X/7 headers present

**Redirects subtab:**
- Uses same `/api/headers` endpoint
- Display each hop: Step | URL | Status Code | Location
- 301 = green (permanent), 302 = yellow (temporary), other = grey
- Final destination highlighted
- Warn if >3 hops

**TLS Grade subtab:**
- Calls `/api/tls?host={hostname}`
- Grade badge: A / B / C / F
- TLS versions table: Version | Supported ✓/✗
- Negotiated cipher suite per version
- Issues list: weak ciphers, old protocols, cert problems

---

### js/network.js

**ASN Lookup subtab:**
- Input: ASN number (AS13335 or 13335) or IP address
- Calls `/api/asn?q={query}`
- Display: ASN, org name, country, description, announced prefixes list

**Subnet Calculator subtab:**
- Input: CIDR (e.g. 192.168.1.0/24) or IP + subnet mask
- Entirely client-side, no API
- Display:
  - Network address
  - Broadcast address
  - Subnet mask + wildcard mask
  - Usable host range (first → last)
  - Number of usable hosts
  - IP class (A/B/C)

**Geo subtab:**
- If hostname: resolve to IP via Cloudflare DoH first
- `GET http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query,reverse`
- Display: IP, Country + flag emoji, Region, City, ISP, Org, ASN
- Note: "Geolocation is approximate"
- If blocked due to HTTP/HTTPS mismatch: show friendly explanation + link to ip-api.com

**Reverse DNS subtab:**
- Input: IP address
- PTR lookup via Cloudflare DoH (auto-reverse the IP)
- Display: IP → PTR hostname
- Then forward-confirm: resolve PTR hostname back to IP, check if it matches
- Show: PTR Record | Forward Confirmed ✓/✗

---

### js/cert.js

- `GET https://crt.sh/?q={domain}&output=json`
- Sort by `not_after` descending
- Primary cert display:
  - Status badge: VALID (green) / EXPIRING SOON ≤30 days (yellow) / EXPIRED (red)
  - Common Name, SANs (highlight queried domain), Issuer
  - Valid From → Valid To, days remaining
  - Serial number
- Collapsible: up to 5 historical certs below

---

### js/whois.js

- Detect IP vs domain
- Calls `/api/whois?q={query}`
- Domains: Registrar, Status flags, Created, Updated, Expires, Name servers
- IPs: Network name, CIDR, Country, Org, Abuse contact
- Fallback link to https://lookup.icann.org if empty result

---

### js/utils.js — all client-side, no API calls

**Base64 subtab:**
- Two textareas: Input | Output
- Encode / Decode buttons
- Auto-detect: if input looks like base64, default to decode mode

**URL Encode subtab:**
- Two textareas: Input | Output
- Encode / Decode buttons
- Uses `encodeURIComponent` / `decodeURIComponent`

**JWT Decoder subtab:**
- Single textarea for JWT paste
- Auto-decode on input (no button needed)
- Three sections: Header | Payload | Signature
- Pretty-print JSON for header and payload
- `exp` shown as human-readable date, highlighted red if expired
- Signature: show raw value, note that verification requires the secret key
- Prominent note: "Decoded entirely in your browser. Your token is never sent anywhere."

---

### js/app.js — Shared Utilities

```javascript
// URL param handling
function getParams() { ... }               // parse ?q=&tab=&sub=
function setParams(q, tab, sub) { ... }    // history.pushState

// Shared resolution
async function resolveToIP(hostname) { ... } // Cloudflare DoH A lookup

// UI helpers
function showLoading(panelId) { ... }
function showError(panelId, message) { ... }
function showResult(panelId, html) { ... }
function copyToClipboard(text) { ... }

// Input validation
function isIP(str) { ... }
function isDomain(str) { ... }
function isCIDR(str) { ... }
function isASN(str) { ... }    // matches AS12345 or bare 12345
function isURL(str) { ... }    // for web tab inputs
```

---

## Error Handling

- Network errors: "Could not reach [service]. Check your connection or try again."
- No records found: "No [type] records found for [domain]."
- Invalid input: validate before running, show inline error under input bar
- ip-api.com 429: "Rate limit reached (45 req/min). Wait a moment and try again."
- All errors styled red, non-blocking — each panel fails independently
- One broken API never breaks another tab

---

## wrangler.toml

```toml
name = "sysadminstuff"
pages_build_output_dir = "."
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
- APIs used with attribution: Cloudflare DoH, crt.sh, RDAP/ARIN, ip-api.com, bgpview.io, Spamhaus et al
- Run locally: `npx wrangler pages dev .` (runs static files + functions together)
- Cloudflare Pages deploy steps
- Contributing guide
- MIT License

---

## Implementation Notes for Claude Code

- No npm required for the frontend — plain JS files only
- For local dev with Functions: `npx wrangler pages dev .`
- Each js/ file exposes its run function on `window` (e.g. `window.runDNS = runDNS`)
- Each `functions/api/*.js` must export `onRequest` as a named export
- All functions must set `Access-Control-Allow-Origin: *` and handle OPTIONS preflight
- Test domains: `google.com`, `github.com`, `cloudflare.com`
- Test IP: `1.1.1.1`
- Test ASN: `AS13335` (Cloudflare)
- Utils tab tools work with zero network — fully offline capable
- Keep each js/ file and each function independently testable
- The shared input bar is hidden/ignored when Utils tab is active

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
- No localStorage or sessionStorage used for anything beyond UI state (e.g. last selected tab)
- No external scripts loaded except JetBrains Mono from Google Fonts — and add a note in the README that even this can be self-hosted if desired

### Client-side only tools — reinforce in UI

The following tools never send data anywhere and must display a visible note saying so:

- **JWT Decoder:** "Decoded entirely in your browser. Your token is never sent to our servers or anywhere else."
- **Base64:** "Encoded/decoded entirely in your browser."
- **URL Encode:** "Encoded/decoded entirely in your browser."
- **Subnet Calculator:** "Calculated entirely in your browser."

### Privacy notice on the page

Add a short privacy line in the footer, visible on every tab:

```html
<footer>
  No logs. No tracking. No ads. 
  Queries are not stored or recorded.
  <a href="/privacy">Privacy</a> · 
  Open source · <a href="https://github.com/YOUR_GITHUB/sysadminstuff">GitHub</a>
</footer>
```

### PRIVACY.md — add to repo root

Plain English, no legal boilerplate. Cover:
- What data we collect: nothing. Queries are not logged or stored.
- Cloudflare: as the hosting provider, Cloudflare may collect standard infrastructure metrics (request counts, error rates) but we do not have access to query content and do not enable Cloudflare analytics.
- Google Fonts: loading JetBrains Mono from Google Fonts means Google sees a font request from your browser. To avoid this entirely, the font can be self-hosted (instructions in README).
- Third-party APIs: queries are sent to public APIs (Cloudflare DoH, crt.sh, ip-api.com, etc.) to perform lookups — this is inherent to how the tools work. These services have their own privacy policies.
- No cookies, no localStorage for personal data, no tracking of any kind.
- Contact: link to GitHub issues for questions.

### README — privacy section

Add a dedicated Privacy section to README.md:
- "sysadminstuff.net does not log, store, or track queries."
- "No analytics. No cookies. No ads."
- "Utility tools (JWT decoder, Base64, URL encode, Subnet calculator) run entirely in your browser and never transmit data."
- Link to PRIVACY.md for full details.
