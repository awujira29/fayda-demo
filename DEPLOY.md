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
