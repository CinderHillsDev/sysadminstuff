# CLAUDE.md

Guidance for working in this repo.

## What this is

`sysadminstuff.net` — a static, ad-free sysadmin toolbox on Cloudflare Pages. Plain HTML/CSS/JS frontend, no framework, **no build step**. A few Cloudflare Pages Functions (`functions/api/`) handle lookups that can't run in the browser (CORS or TCP).

## Architecture

- **Frontend:** `index.html` + `css/style.css` + `js/*.js`. Each `js/<tab>.js` module registers its tools via `window.registerRunner(tab, subtab, fn)`. `js/app.js` owns tab/subtab routing, the shared input bar, URL params (`?q=&tab=&sub=`), and shared helpers (exposed on `window`: `dohQuery`, `resolveToIP`, `card`, `showResult`, `isIP`, etc.).
- **Overview tab** (`js/overview.js`) is the landing tab: it fans out to the same lookups the other tabs use and renders a scored report. What each finding *means* — status, wording, score weight — is pure logic in `core.js` (`domainReport`, `reportToText`), so it stays unit-testable; `overview.js` only collects data and paints. Rows deep-link with `window.jumpTo('tab:sub')` (defined in `app.js`). It reuses the other tabs' machinery (`walkSpf`, the parsers in `core.js`) instead of reimplementing it, so the report and the detail tabs can't disagree.
  Its subtabs (`all · attention · dns · email · web · reg`) are **filters over one shared collection** (`ovState`, keyed by domain, with a run token) defined by `OV_VIEWS` — never start a second round of lookups when a subtab is clicked. `attention` shows only FAIL/WARN rows across all categories; keep its empty states non-blank (all-clean vs still-running read differently). If you add a view, add it to `OV_VIEWS` *and* the nav/subpanels in `index.html` with matching ids (e2e pins both).
- **Backend:** each `functions/api/*.js` exports `onRequest(context)`, returns JSON, sets `Access-Control-Allow-Origin: *`, and handles `OPTIONS`.
- **`mailcheck-probe/`** is a separate, temporary diagnostic Worker (its own `wrangler.toml`), not part of the site: it records *headers and a body hash only* to KV with a 24 h TTL so we can learn what an `email()` handler actually receives. Its `parse.mjs` is pure and smoke-tested; the middleware 404s that path so Pages never serves it. Delete the directory once the questions in its README are answered.
- **Deploy:** push to `main` → Cloudflare Pages auto-deploys static files + functions. Nothing to run by hand.

## Conventions

- The shared input bar is hidden on the **Utils** tab and for self-contained subtabs listed in `NO_QUERY_SUBTABS` (email Header Analyzer, network Subnet Calculator).
- Client-side-only tools (JWT, Base64, URL Encode, Subnet) must never make network calls and must show a visible "runs in your browser" note.
- Frontend modules attach their run functions through `registerRunner`; don't call runners directly.
- The RFC 7208 SPF limits (`SPF_DNS_LOOKUP_LIMIT`, `SPF_VOID_LOOKUP_LIMIT`) are defined once in `core.js` and read by both the SPF Lookups subtab and the Overview report. The 10-lookup cap is a *tree* limit — counting only the root record's mechanisms understates it, so grade it from `walkSpf`.
- Blacklist answers are interpreted by `rblVerdict()` in `lib/parse.mjs` — for the Spamhaus/CBL/Barracuda zones only the documented listing codes mean "listed" (`127.255.255.x` is a *refusal* to answer public resolvers, not a listing). Don't reduce an RBL check to "any answer means listed".

## Privacy — non-negotiable (see PRIVACY.md)

- **Never** log user input in a function: no `console.log`/`console.error` of query params, request URLs, client IPs, or anything derived from them. Logging is allowed only for internal errors with no user data (e.g. an upstream status code).
- No analytics, telemetry, or error-tracking services. No cookies. No third-party scripts except the optional Google Font.
- Don't forward the user's IP (`X-Forwarded-For`) to upstream APIs.

## Testing

- `node tests/smoke.mjs` — dependency-free pure-logic unit tests (subnet math, validators, SPF/DMARC/JWT parsing, RDAP/ASN shaping). Exits non-zero on failure; safe for CI.
- `node tests/e2e.mjs` — hits a running `npx wrangler pages dev .` and checks each `/api/*` endpoint end to end. Set `BASE_URL` to point elsewhere.
- Add/adjust a smoke test with any change.

## Local dev

```sh
npx wrangler pages dev .
```

Test targets: `google.com`, `github.com`, `cloudflare.com`, IP `1.1.1.1`, ASN `AS13335`.
