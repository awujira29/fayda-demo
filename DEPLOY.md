# Deploying the demo to Render

One service, one public HTTPS URL. FastAPI serves both the API and the built
React frontend from a single process — same origin, no CORS, and the
cookie/OIDC flow is identical to local dev. The mock Fayda IdP is enabled via
`DEMO_MODE` so visitors can log in with test personas and connect a real
wallet; none of the `/api/dev/*` surface (reset, fast-forward, test-wallet)
exists in this posture — a visitor cannot wipe the database or skip the
cooling period.

Everything below is verified against the code in this repo: the Docker image
was built and run locally with `PORT=10000`, `APP_ENV=production`,
`DEMO_MODE=1` and `RENDER_EXTERNAL_URL` set, and the full persona → cookie →
`/api/me` round trip passed with the `Secure` cookie, while every dev route
returned 404 (`backend/t.py` test 20 pins this).

## The click-path

1. **Push this repository to GitHub** (or GitLab/Bitbucket).

2. **Render Dashboard → New → Blueprint**, select the repo. Render reads
   `render.yaml` and shows one web service, `fayda-wallet-registry`
   (Docker runtime, free plan). Click **Apply**.

   *Without Blueprints:* New → Web Service → pick the repo → Language:
   **Docker** (it auto-detects `./Dockerfile`) → Instance type: Free. No
   build or start command needed — the Dockerfile carries both (the SPA is
   built in a Node stage; the container starts
   `uvicorn app:app --host 0.0.0.0 --port $PORT`).

3. **Environment variables** (Blueprint sets the first four automatically):

   | Key | Value | Why |
   |---|---|---|
   | `APP_ENV` | `production` | Dev surface absent, secrets required, cookie `Secure` |
   | `DEMO_MODE` | `1` | Mounts ONLY the mock Fayda IdP (personas). Never `/api/dev/*` |
   | `SESSION_SECRET` | generated (`generateValue: true`) | Signs the opaque session id. Rotating logs everyone out |
   | `FIN_PEPPER` | generated (`generateValue: true`) | HMAC pepper for FIN hashing. **Treat as permanent** — rotating orphans every identity row (CLAUDE.md) |
   | `PRIVY_APP_ID` | your app id (set manually) | Wallet connector. Runtime config via `/config.js` — set or change it without rebuilding. Leave unset and the UI shows a designed "connector not configured" state; personas still work |
   | `PUBLIC_URL` | *(leave unset)* | The app derives the public origin from `RENDER_EXTERNAL_URL`, which Render injects (e.g. `https://fayda-wallet-registry.onrender.com`). Set `PUBLIC_URL` only for a custom domain |
   | `SUPABASE_DB_URL` | your Supabase connection string (set manually) | Postgres storage (R1). Session-pooler string from the Supabase dashboard. Required — the app refuses to start without it |
   | `CHAIN_EXPLORER_URL` | *(optional)* | Block-explorer endpoint for R4's on-chain history, Etherscan-shaped (`https://api.etherscan.io/v2/api?chainid=1`). Leave unset and the compliance panel reports "no explorer configured" rather than showing an empty history — a distinction it must not blur |
   | `CHAIN_EXPLORER_KEY` | *(optional)* | API key for the above, if the provider needs one |
   | `FAYDA_CLIENT_PRIVATE_KEY` | required outside dev/demo | PEM of the RSA key whose public JWK is registered with Fayda during partner onboarding. The app refuses to start without it in production: the assertion key must be the registered one, not a per-process key that could never match |
   | `FAYDA_CLIENT_ID`, `FAYDA_AUTHORIZE_URL`, `FAYDA_TOKEN_URL`, `FAYDA_USERINFO_URL` | for a live IdP | Point the OIDC client at partner.fayda.et. Setting any of them alongside `DEMO_MODE=1` refuses to start — real identities must not sit behind a login any visitor can perform |
   | `RATE_LIMIT` | *(leave unset)* | On by default. `off` disables it — only the test suite should ever do that, because its deliberate bursts are exactly what a limiter refuses |
   | `TRUST_PROXY_HEADERS` | `1` on Render | The app sits behind Render's proxy, so the socket peer is always the proxy and without this every visitor shares one rate-limit bucket. Set it ONLY when a trusted proxy sets `X-Forwarded-For` — a spoofable header as the limiter key gives an attacker a fresh bucket per request |
   | `SUPABASE_CA_CERT` | *(optional, recommended)* | Path to Supabase's downloadable root certificate. Present, the connection upgrades from `sslmode=require` (encrypts but authenticates nothing) to `verify-full`. Not defaulted on: without the right CA bundle every connection would fail |
   | `SANCTIONS_LIST_PATH` | *(optional)* | JSON file of sanctions entries for R6 screening. Unset means screening reports "not configured" rather than pretending a clean result. No list is bundled |

4. **Privy dashboard step** (for real wallet connections): at
   [dashboard.privy.io](https://dashboard.privy.io) create an app (free under
   499 MAU), copy the App ID into the `PRIVY_APP_ID` env var on Render, and —
   this is the part people forget — add the deployed origin
   (`https://<your-service>.onrender.com`) to the app's **allowed
   origins/domains** in Privy's settings. Without it, Privy's modal refuses to
   open on the deployed site. Mobile wallets additionally need a WalletConnect
   project id configured in the Privy dashboard (see README).

5. **Deploy.** First build takes a few minutes (Node stage compiles native
   deps). The service URL is your shareable link. Health check:
   `GET /api/me` returns JSON with `"demo": true`.

## What a demo visitor can and cannot do

- **Can:** click a persona on the simulated-biometric screen (clearly labeled
  simulated), get a verified identity record, connect a real MetaMask through
  Privy, review and sign the attestation, bind, see the cooling window on a
  replacement, cancel their own pending replacement, browse the public
  registry.
- **Cannot:** reach `/api/dev/*` (404 — no reset, no cooling fast-forward, no
  server-side test keys), read anyone's raw FIN (never leaves the server),
  or bypass the sybil constraint (database unique indexes).

## What "the registry is no longer public" means in DEMO_MODE

R2 put `/api/registry` behind a session, and it no longer discloses the FIN
HMAC, the internal identity id, or identities with no wallet bound. Be clear
about what that buys **in the demo posture**: `DEMO_MODE=1` publishes the mock
IdP, so any visitor can click a persona and hold a valid session a second
later. Authentication is therefore not a meaningful barrier here — the gate is
real, the identities behind it are public test personas, and the demo is
designed for exactly that.

It becomes a real barrier the moment `DEMO_MODE` is off and login means a live
Fayda authentication. What the demo posture genuinely fixes either way: the
registry-wide `promote_due()` is off the unauthenticated surface, and the HMAC
serial is out of the response body.

## One security note carried into a real deployment

The mock `/authorize` validates `redirect_uri` by **path only** (`/callback`),
so it accepts that path on any host. Harmless for this mock demo — the
authorization `code` is unexchangeable without the `private_key_jwt` client
assertion (a server-held key generated at startup, never sent to the browser),
and it maps only to a public persona anyone can already pick — so the worst
case is a redirect to `<host>/callback` with a useless code. **When real Fayda
credentials replace the mock, redirect_uri validation must match the full
registered URI (host *and* path)**, because the code will then have real value.
Tracked with B1 (live Fayda integration).

## Storage: Supabase Postgres (R1)

Storage moved from ephemeral SQLite to Supabase Postgres. **Data now survives
redeploys, restarts and free-tier spin-down** — identities, bindings, cooling
timers and sessions all live in the managed database, independent of the app
container. The deploy MUST set `SUPABASE_DB_URL` (Supabase dashboard →
Connect → Session pooler string); without it the app refuses to start rather
than silently reverting to disposable storage. The credential is a secret:
env var only, never committed, never baked into the image (`.dockerignore`
excludes every `.env`).

One consequence for the demo posture: because data persists, `FIN_PEPPER`
and `SESSION_SECRET` genuinely must be treated as permanent now — rotating
the pepper orphans every identity row in a database that no longer resets
itself on redeploy.

## Moving to a custom domain (R7)

The code side is already done and was verified during R1/D1: the public origin
comes from `PUBLIC_URL || RENDER_EXTERNAL_URL` — env only, never influenced by
the `Host` header — the cookie is `Secure` outside dev, and `verify.py` builds
the signed message's stated origin from the same variable, so the domain the
wallet shows the user matches the address bar. A custom domain is therefore
configuration, in this order:

1. **Add the domain in Render** (Settings → Custom Domains) and create the CNAME
   it asks for. Wait for the certificate to issue — Render does this
   automatically via Let's Encrypt. Confirm `https://<domain>` serves the app
   before going further.
2. **Set `PUBLIC_URL=https://<domain>`.** Until this is set, the app keeps
   deriving its origin from `RENDER_EXTERNAL_URL`, so `/login` would redirect to
   the `.onrender.com` host, the session cookie would land there, and the user
   would come back to the custom domain signed out. This is the failure mode to
   expect if you skip the step, and it fails safe — never signed in as someone
   else.
3. **Add the domain to Privy's allowed origins** (dashboard → your app →
   Settings → Domains). Miss this and Privy's modal silently refuses to open on
   the new host; wallet connection is the only thing that breaks.
4. **If real Fayda credentials are in play**, the redirect URI registered with
   partner.fayda.et must be updated to `https://<domain>/callback` too — an
   OIDC provider matches it exactly, and a mismatch rejects every login.
5. Re-run the checks in "Rate limiting behind the proxy" below: the proxy chain
   is what changed.

Nothing here is verifiable from a development machine, which is why it is
written as a procedure rather than claimed as done.

## Rate limiting behind the proxy — verify this after the first deploy

The limiter buckets by client address. Behind Render's proxy the socket peer is
always the proxy, so `TRUST_PROXY_HEADERS=1` makes it read `X-Forwarded-For`
instead — **counting from the right**, because that header is a list each proxy
appends to and everything to the left of the last trusted hop is whatever the
caller chose to send. Reading it from the left made the limiter a no-op and let
an attacker drain a named victim's bucket.

`TRUSTED_PROXY_HOPS` (default 1) is how many proxies sit in front. **Leave it
at 1 for Render.** That is correct whether Render appends to the caller's
header (`1.2.3.4, <client>` → picks `<client>`) or replaces it outright
(`<client>` → picks `<client>`); both give the true client.

**Raising it is the dangerous direction, and it is not symmetric with lowering
it.** Each extra hop moves the key one position left — towards the part of the
header the caller wrote — so an over-counted hop hands the bucket back to the
attacker silently, with no symptom at all. Under-counting fails the other way:
everyone lands in one bucket and legitimate users see 429s under modest load,
which is visible and annoying but safe. If you see that symptom, the cause is
almost certainly something else; do not reach for this variable.

Check after the first deploy: two different clients hitting `/login` should
each get their own allowance, and a single client should be refused after
roughly 40 rapid requests.

## Backups — what is verified and what is not (R6)

Queried from the database itself: `wal_level=logical`, `archive_mode=on`,
`max_wal_senders=5`. WAL archiving — the mechanism managed backups and
point-in-time recovery are built on — **is enabled**.

That is the prerequisite, not the guarantee. Three things could not be checked
from the application and remain **unverified**:

1. **Retention.** Whether Supabase is keeping those archives, and for how long,
   is a project-plan setting visible only in the dashboard (Database →
   Backups). Free-tier projects historically get a shorter window than paid.
2. **That a restore actually works.** An untested backup is a hypothesis. The
   only way to know is to restore into a scratch project and run
   `APP_ENV=dev python backend/t.py` against it.
3. **That the pepper is backed up with the data.** This one bites hardest and
   is not a database setting at all: `FIN_PEPPER` lives in the platform's env
   vars, not in Postgres. Restoring the database without the same pepper
   orphans **every** identity row — each is keyed by `fin_hmac`, every FIN
   re-hashes differently, and the sybil index then blocks each user from
   re-binding their own wallet. Store the pepper wherever the backups are
   stored, and treat losing it as equivalent to losing the database.

**The drill, to run before this holds real data:** restore the most recent
backup into a scratch Supabase project, point `SUPABASE_DB_URL` at it with the
*same* `FIN_PEPPER`, run the suite, and confirm an existing identity can still
reach its own binding. Record the date it last passed.

## Local rehearsal (what CI or a fresh clone should do)

```bash
docker build -t fayda-registry .
docker run --rm -p 10000:10000 \
  -e PORT=10000 -e APP_ENV=production -e DEMO_MODE=1 \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  -e FIN_PEPPER=$(openssl rand -hex 32) \
  -e SUPABASE_DB_URL="$(grep '^SUPABASE_DB_URL=' backend/.env | cut -d= -f2-)" \
  fayda-registry
# open http://127.0.0.1:10000 — SPA loads, persona login works,
# /api/dev/* → 404. (Browsers accept Secure cookies on localhost.)
```

Tests: `APP_ENV=dev python backend/app.py` in one shell,
`APP_ENV=dev python backend/t.py` in another — 26 checks, including the
demo-mode gating and the Secure-cookie/`RENDER_EXTERNAL_URL` derivation
(test 20).

The suite resets the registry before it runs, so it works only against a
database explicitly marked throwaway (`APP_ENV=dev python backend/store.py
mark-disposable`, once per dev database). **Never mark the production
database.** The marker records the host it was written for, so pointing
`backend/.env` at production makes both the suite and `/api/dev/reset` refuse
instead of dropping the registry — the destructive path checks the target,
not the caller's environment variable.
