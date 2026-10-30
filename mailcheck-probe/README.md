# mailcheck-probe

A **temporary diagnostic Worker**, not part of sysadminstuff.net. It exists to answer one
question that the documentation does not:

> When mail arrives at our MX and is handed to a Worker's `email()` handler, what do we
> actually get — can we see the connecting IP, and does any `Authentication-Results`
> survive to us?

That answer decides how much of a "send us an email and we check it" feature can state as
fact versus infer. Cloudflare's docs confirm inbound Email Routing is unlimited on
Workers Free, that a routing rule's destination must be a Worker with an `email` handler
(Pages Functions have none), and that inbound mail failing **both** SPF and DKIM is
rejected before a Worker ever sees it — but they say nothing about the header set.

**Delete this directory once you have the answer.** Nothing in the site depends on it.

## What it does

Receives mail on a throwaway subdomain, and stores **headers and a SHA-256 of the raw
message only** — no body, no attachments — in your own KV namespace with a 24 h TTL. The
message is accepted and dropped: nothing is forwarded to anyone, and nothing is logged.

## Setup (~10 minutes)

Keep the subdomain in its **own zone** so `sysadminstuff.net`'s MX and `v=spf1 -all` stay
untouched — that null-MX statement is one your own Overview report checks for.

```sh
cd mailcheck-probe
npx wrangler kv namespace create PROBE        # paste the id into wrangler.toml
npx wrangler secret put PROBE_KEY             # any long random string
npx wrangler deploy
```

Then in the dashboard:

1. **Add a site** for `mailcheck.<your-root-domain>` (a subdomain as its own zone), and add
   the NS records Cloudflare gives you to the parent zone.
2. **Compute → Email Service → Email Routing → Onboard Domain** for it. MX/SPF/DKIM TXT
   records go into *that* zone, not the apex one.
3. Turn on the **catch-all rule**, action = *Send to a Worker* → `mailcheck-probe`.
4. Wait for the MX to resolve: `dig MX mailcheck.<your-root-domain>`.

## Run the three tests that matter

| Send from | What it proves |
|---|---|
| Gmail (or M365) to `anything@mailcheck.…` | The common case: does a big provider's `Authentication-Results`/`ARC-*` chain reach us? |
| Direct SMTP from a VPS (`swaks`/`sendmail`) | Whether the **connecting IP** of the last hop is visible — the whole blacklist feature depends on this |
| A forward (Gmail auto-forward → us) | Whether forwarding rewrites the chain, i.e. what we'd be lying about |

Read the results:

```sh
KEY=*** 'echo -n "Paste the PROBE_KEY you set: " >/dev/null; read -rs K && echo $K'
curl -s "https://mailcheck-probe.<subdomain>.workers.dev/last?key=$KEY" | less
curl -s ".../last?key=$KEY&full=1"   # every header value, to see exactly what arrived
```

## How to read `conclusions`

| Conclusion | If yes | If no |
|---|---|---|
| `connectingIp` | The feature can blacklist-check the real sending IP | Skip IP reputation, or label it "as claimed by the sender" |
| `cloudflareHop` | The last hop is authoritative rather than self-reported | Treat any address as a claim, not a fact |
| `authResultsHeader` | Surface a downstream verdict, still verifying DKIM ourselves | Compute DKIM ourselves; report SPF only from the published record |
| `dkimSigned` | A real cryptographic verify is possible | Nothing to verify — check the message was signed at all |
| `bodyAccessible` | Body canonicalisation fits in one invocation | Keep to headers; move any verify out of the 10 ms budget |

`bodyAccessible: false` with `skipped: "over size cap"` is expected for big mail. If you
want the CPU number rather than the guess, check **Workers → Observability → Logs** for the
invocation: Free-plan handlers fail with `EXCEEDED_CPU` past 10 ms, which is the main
reason this Worker does exactly one hash and nothing else.

## What we keep from it

`parse.mjs` — header/Received/DKIM/ARC parsing and the conclusions — is pure and covered by
`node tests/smoke.mjs`. That file is the part worth promoting into `js/core.js` (or
`lib/`) when the real feature is built; the Worker around it is disposable.

## Removal

```sh
npx wrangler delete --name mailcheck-probe
```
Disable the catch-all rule first, then delete the zone. KV entries expire on their own
within 24 h.
