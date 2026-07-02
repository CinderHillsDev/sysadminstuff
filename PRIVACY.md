# Privacy

sysadminstuff.net is a privacy-first tool. You should be able to trust that nothing you type is stored or tracked.

## What we collect

**Nothing.** The queries you run are not logged or stored by us.

Every server-side function in `functions/api/` is written to never log:

- Query parameters (`q`, `url`, `ip`, `host`, or any user-supplied value)
- Request URLs (which contain user input)
- Client IP addresses
- Any data derived from user input

Logging is used only for internal errors with **no user data attached** — for example, an upstream HTTP status code.

## Hosting (Cloudflare)

The site runs on Cloudflare Pages. As the hosting provider, Cloudflare may collect standard infrastructure metrics (request counts, error rates). We do not have access to your query content, and we do not enable Cloudflare Web Analytics.

## Google Fonts

The page loads the JetBrains Mono font from Google Fonts, so your browser makes a request to Google for the font files. To avoid this entirely, the font can be self-hosted — see the README for instructions.

## Third-party APIs

Some tools send your query to public APIs to perform lookups:

- Cloudflare DNS-over-HTTPS (DNS, blacklist checks)
- crt.sh (certificates)
- RDAP registries (whois)
- ip-api.com (geolocation)
- bgpview.io (ASN data)

This is inherent to how those lookups work. Each service has its own privacy policy. We do not forward your IP address (no `X-Forwarded-For`) to upstream APIs where it can be avoided.

## Fully local tools

These never send data anywhere — they run entirely in your browser:

- **JWT Decoder** — your token is never sent to our servers or anywhere else.
- **Base64** — encoded/decoded in your browser.
- **URL Encode** — encoded/decoded in your browser.
- **Subnet Calculator** — calculated in your browser.

## Cookies & storage

No cookies are set — not even session cookies. No localStorage or sessionStorage is used for anything beyond basic UI state. There is no tracking of any kind: no Google Analytics, no Plausible, no Fathom, no tracking pixels, no beacons.

## Contact

Questions? Open an issue on [GitHub](https://github.com/chrismuench/sysadminstuff).
