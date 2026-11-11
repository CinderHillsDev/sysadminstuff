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
rejected before a Worker ever sees it. They also state something we were hoping not to have
to take on faith: Email Routing validates DMARC **before** invoking the Worker and prepends
its own `Authentication-Results` with `mx.cloudflare.net` as the auth-service-id. The docs
say nothing about the rest of the header set — above all whether a connecting IP reaches us.

So the probe now tests a documented claim instead of guessing blind: if `cloudflareVerdict`
comes back false, the docs are wrong and that is the most useful result of the whole
exercise.

**Delete this directory once you have the answer.** Nothing in the site depends on it.

## What it does

Receives mail addressed to a token sub-address on one routing rule, and stores **headers
and a SHA-256 of the raw message only** — no body, no attachments — in your own KV
namespace with a 24 h TTL. The message is accepted and dropped: nothing is forwarded to
anyone, and nothing is logged.

## Why one rule is enough

Email Routing supports RFC 5233 subaddressing: with the toggle on, mail to
`probe+TOKEN@example.com` is matched by the plain `probe@example.com` rule, the `+TOKEN`
does not affect matching, and it arrives intact in `message.to` where the Worker can read
it. So a single literal rule hands out unlimited one-shot addresses — no catch-all, no
rule-per-test, and no re-deploying the Worker to add an address. (A rule for
`probe+exact@` would take precedence over `probe@`, so specific addresses can still be
reserved.)

Catch-all, for the record, is apex-only — it is not available on subdomains, and we do not
need it. Routing rules are capped at 200 per domain and 30 domains per zone, which the
one-rule design makes irrelevant.

## The constraint that does matter

Email Routing is **zone-level**: enabling it replaces the apex `MX` with Cloudflare's, so
*all* mail for that domain starts arriving at Cloudflare and anything no rule matches is
dropped. Do this on a domain that carries no mail you care about.

`sysadminstuff.net` is a poor candidate on its own — its apex publishes a null `MX` and
`v=spf1 -all` precisely to say "no mail here", and the Overview report checks for that. If
you want to reuse an existing live domain instead, keep its mail flowing with a catch-all
→ your real mailbox address (a verified destination) before adding any Worker rules.

Subdomains of a zone are added from the *apex*'s Email Routing **Settings → Subdomains**,
which requires the apex to be onboarded first — so a parked domain you already have on
Cloudflare is the fastest route, and no separate zone or NS delegation is involved.

## Setup (~10 minutes)

```sh
cd mailcheck-probe
npx wrangler kv namespace create PROBE        # paste the id into wrangler.toml
npx wrangler secret put PROBE_KEY             # any long random string
npx wrangler deploy                           # deploy BEFORE creating the rule
```

Then in the dashboard, on the chosen domain:

1. **Compute → Email Service → Email Routing → Onboard Domain.** Cloudflare adds the `MX`
   and `cf2024-1._domainkey` DKIM records; if the zone has no SPF record it adds one, and
   if it *does*, add Cloudflare's `include:` by hand.
2. (Optional, if you want a label rather than the apex) **Settings → Subdomains** → add
   `mailcheck`. Cloudflare writes that subdomain's records. Everything below then uses
   `@mailcheck.<domain>`.
3. **Settings → enable Subaddressing.**
4. **Routing rules → add rule**: `probe@<domain>` (or `probe@mailcheck.<domain>`), action
   = *Send to a Worker* → `mailcheck-probe`. Deploy the Worker first — the dashboard only
   lists Workers that already exist, and a rule with no destination stays disabled.
5. Wait for the `MX` to resolve: `dig MX <domain>` (or `mailcheck.<domain>`).

## Run the three tests that matter

| Send from | What it proves |
|---|---|
| Gmail (or M365) to `probe+aaaa1111@…` | The common case: does a big provider's `Authentication-Results`/`ARC-*` chain reach us? |
| Direct SMTP from a VPS (`swaks`/`sendmail`) to `probe+bbbb2222@…` | Whether the **connecting IP** of the last hop is visible — the whole blacklist feature depends on this |
| A forward (Gmail auto-forward → `probe+cccc3333@…`) | Whether forwarding rewrites the chain, i.e. what we'd be lying about |

Distinct tokens matter: each one is a separate KV key, so the three results do not
overwrite each other. Read them individually with `&to=aaaa1111`.

Read the results:

```sh
KEY=*** 'echo -n "Paste the PROBE_KEY you set: " >/dev/null; read -rs K && echo $K'
curl -s "https://mailcheck-probe.<subdomain>.workers.dev/last?key=$KEY" | less
curl -s ".../last?key=$KEY&full=1"   # every header value, to see exactly what arrived
```

`p:latest` is overwritten by every message, so send the three tests to **distinct token
addresses** to keep all of them side by side — a local part like `check+deadbeef@` is stored
under its own key as well:

```sh
curl -s ".../last?key=$KEY&to=deadbeef"
```

Use a different hex token per test: `probe+aaaa1111@` (Gmail), `probe+bbbb2222@` (direct
SMTP), `probe+cccc3333@` (forward).

## How to read `conclusions`

| Conclusion | If yes | If no |
|---|---|---|
| `connectingIp` | The feature can blacklist-check the real sending IP | Skip IP reputation, or label it "as claimed by the sender" |
| `cloudflareHop` | The last hop is authoritative rather than self-reported | Treat any address as a claim, not a fact |
| `authResultsHeader` | Surface a downstream verdict, still verifying DKIM ourselves | Compute DKIM ourselves; report SPF only from the published record |
| `cloudflareVerdict` | Report SPF/DKIM/DMARC as fact — Cloudflare computed them, no ARC chain to walk | Any `Authentication-Results` present was written upstream: show it as the sender's claim, unverified |
| `dkimSigned` | A real cryptographic verify is possible | Nothing to verify — check the message was signed at all |
| `bodyAccessible` | Body canonicalisation fits in one invocation | Keep to headers; move any verify out of the 10 ms budget |

`cloudflareVerdict` is the one that changes the product: it separates the checks we can do
on *any* domain's mail (DNS-side, which the Overview report already does) from a verdict on
a specific delivered message. If it is true, "we authenticated this message for you" is a
statement we can make from the header alone.

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
Delete the routing rule first (a rule pointing at a missing Worker is a silent black hole),
then undo the domain: if you onboarded it only for this, remove it from Email Routing and
restore its `MX` — leaving Cloudflare's `MX` in place means mail to that domain stops
delivering. Delete the zone only if you created one. KV entries expire on their own within
24 h.

## Handing out addresses (design notes for the real feature, not this probe)

The test local part should be a short random 6-digit code, so many people can be testing at
once without colliding. Three things follow from the platform limits:

1. **A bare `483920@` address needs a catch-all, and catch-alls are apex-only.** On a
   subdomain the only alternative is `probe+483920@` (subaddressing) or one literal rule per
   code, which runs into the 200-rules-per-domain cap immediately. So the product needs its
   own *apex* domain with no real mail on it — not a label under an existing zone.
2. **KV cannot allocate safely.** It is eventually consistent, `put()` has no create-if-absent
   option, and read-then-write races mean two people can be handed the same code. It also
   caps at 1,000 writes/day on Free, which would be the feature's throughput limit. Use a
   **SQLite-backed Durable Object** as the registry: `INSERT` on a PRIMARY KEY is atomic and
   single-writer, so a collision becomes "draw again" instead of two users sharing an inbox.
   SQLite-backed DO classes are available on Workers Free (key-value-backed ones are not);
   5 GB per account is orders of magnitude more than the rows need. A cron trigger deletes
   expired rows, since SQLite has no TTL.
3. **A 6-digit code is not a secret.** 1,000,000 combinations is enumerable, and the record
   behind it holds someone's message headers. Every row must therefore carry a second,
   unguessable read token handed to the requester in the result URL, and the read endpoint
   must return nothing on the code alone. Otherwise the toolbox would be shipping a window
   into strangers' mail, which is the one thing PRIVACY.md exists to prevent.

`tokenOf()` in `src/index.js` already keys a bare numeric local part as-is, so this probe
works unchanged under either addressing scheme.
