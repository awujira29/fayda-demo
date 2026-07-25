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

## The SQLite caveat — read this before sharing the link

**The database resets on every redeploy and on free-tier spin-down.** SQLite
lives on the container's ephemeral disk; Render free instances spin down
after ~15 minutes idle and get a fresh filesystem on wake. Every cold start
is an empty registry: identities, bindings and cooling timers vanish.

That is acceptable — arguably convenient — for a mock-persona demo. It is
one of the two reasons a real deployment needs Postgres (the other being the
migration/startup hazards already tracked as M4 in PROGRESS.md; the
schema-on-fresh-DB pattern assumes a throwaway database). Do not attach a
Render persistent disk as a fix: the demo's per-boot secrets/pepper semantics
assume a fresh DB, and a durable deployment should move the storage layer,
not pin the demo's.

## Local rehearsal (what CI or a fresh clone should do)

```bash
docker build -t fayda-registry .
docker run --rm -p 10000:10000 \
  -e PORT=10000 -e APP_ENV=production -e DEMO_MODE=1 \
  -e SESSION_SECRET=$(openssl rand -hex 32) \
  -e FIN_PEPPER=$(openssl rand -hex 32) \
  fayda-registry
# open http://127.0.0.1:10000 — SPA loads, persona login works,
# /api/dev/* → 404. (Browsers accept Secure cookies on localhost.)
```

Tests: `APP_ENV=dev python backend/app.py` in one shell,
`python backend/t.py` in another — 20 checks, including the demo-mode gating
and the Secure-cookie/`RENDER_EXTERNAL_URL` derivation (test 20).
