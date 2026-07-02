# CLAUDE.md

Guidance for working in this repo.

## What this is

`sysadminstuff.net` — a static, ad-free sysadmin toolbox on Cloudflare Pages. Plain HTML/CSS/JS frontend, no framework, **no build step**. A few Cloudflare Pages Functions (`functions/api/`) handle lookups that can't run in the browser (CORS or TCP).

## Architecture

- **Frontend:** `index.html` + `css/style.css` + `js/*.js`. Each `js/<tab>.js` module registers its tools via `window.registerRunner(tab, subtab, fn)`. `js/app.js` owns tab/subtab routing, the shared input bar, URL params (`?q=&tab=&sub=`), and shared helpers (exposed on `window`: `dohQuery`, `resolveToIP`, `card`, `showResult`, `isIP`, etc.).
- **Backend:** each `functions/api/*.js` exports `onRequest(context)`, returns JSON, sets `Access-Control-Allow-Origin: *`, and handles `OPTIONS`.
- **Deploy:** push to `main` → Cloudflare Pages auto-deploys static files + functions. Nothing to run by hand.

## Conventions

- The shared input bar is hidden on the **Utils** tab and for self-contained subtabs listed in `NO_QUERY_SUBTABS` (email Header Analyzer, network Subnet Calculator).
- Client-side-only tools (JWT, Base64, URL Encode, Subnet) must never make network calls and must show a visible "runs in your browser" note.
- Frontend modules attach their run functions through `registerRunner`; don't call runners directly.

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
