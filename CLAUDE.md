# CLAUDE.md

Project knowledge for the Fayda identity to wallet registry. Read before touching anything.

## What this is

A registry binding one Fayda-verified Ethiopian identity to at most one verified
self-custodied wallet per chain (Ethereum, Solana). Takes no custody, holds no
private keys. Stores only cryptographic proof that a verified person controls an address.

Two processes: a Python / FastAPI API in backend/ (storage: Supabase Postgres,
connection string in SUPABASE_DB_URL — env or the gitignored backend/.env; no
SQLite fallback), and a React + Vite + Tailwind v4 frontend in frontend/. The wallet connector is Privy
(@privy-io/react-auth), used for connection only — identity always comes from
Fayda, embedded wallets are off, external self-custody only. The frontend
proxies every backend path so the browser never leaves its own origin — the
session cookie depends on it.

## Non-negotiables

Correctness properties, not preferences. Breaking any is a bug regardless of what else improves.

1. **The raw FIN is never persisted, logged, or sent to the browser.** Only
   HMAC-SHA256(pepper, FIN). A FIN is 12 digits, so 10^12 values is enumerable in
   minutes and a bare hash is functionally plaintext.
2. **The server never trusts the client's copy of a signed message.** Stored when the
   nonce is issued, reloaded at verification.
3. **One active wallet per (identity, chain). One active identity per (chain, address).**
   The second is the sybil constraint. Partial unique index AND re-checked at commit.
4. **Nonces are single-use, TTL-bound, bound to address and chain.**
5. **No private key reaches the server** except in /api/dev/*, which must not exist
   in production.
6. **Fayda is an identity provider, not a database.** No lookup endpoint exists.
   Never design anything assuming we can query a person's record.

## Things we know that the code does not say

**Fayda does not prove citizenship.** Ethiopia's definition of an eligible Fayda
resident includes foreign nationals legally resident in the country. Any citizens-only
feature needs a separate check. Do not treat a valid Fayda auth as proof of citizenship.

**The userinfo claim shape is confirmed** — from the official Python client,
github.com/National-ID-Program-Ethiopia/fayda-auth-python. It is: sub, name, birthdate,
gender, phone, picture, residenceStatus, address {kebele, region, woreda, zone}.
sub is the only identifier; there is no fayda_fin claim. Two consequences are
load-bearing: address carries kebele and woreda — neighbourhood-level location — which
is why sessions are server-side and the cookie holds only an opaque id; and
residenceStatus is the likely home for the citizenship distinction (see below) but its
value set is unconfirmed — check with NIDP before branching on it. mock_esignet.py is
still the only file to touch when real credentials arrive.

**Cooling period exists for session compromise, not user convenience.** If an attacker
with a live session swaps the wallet, the real user needs a window to cancel and their
existing wallet must keep working. Do not simplify this into an instant swap.

## Architecture

| File | Role |
|---|---|
| backend/app.py | OIDC client, session middleware, binding endpoints, registry API |
| backend/store.py | Schema and queries (psycopg / Supabase Postgres). Unique indexes live here. |
| backend/verify.py | secp256k1 recovery (EVM), ed25519 verification (Solana) |
| backend/mock_esignet.py | Throwaway. Deleted in production. |
| backend/t.py | End-to-end tests |
| frontend/src/wallet/ | THE Privy seam (R2). The only module that may import @privy-io. |
| frontend/src/App.jsx | State machine + composition; direction contract in its header |
| frontend/src/components/ | UI (shadcn-style primitives in ui/, product components beside) |
| frontend/src/styles/tokens.css | Design tokens (OKLCH) — the single source of visual values |

Two base URLs on the backend: BASE_URL is where the process is reachable for
server-to-server calls (token, userinfo); PUBLIC_URL is the origin the browser
stays on (the Vite server in dev). redirect_uri and the authorize URL are built
from PUBLIC_URL. Get this wrong and the session cookie lands on the wrong origin.

Design values (colour, type scale, spacing) live in
frontend/src/styles/tokens.css — change them there, never as literals in
components. The visual world (civil-registry record: Source Serif 4 300/700
display, Public Sans UI, Spline Sans Mono machine values, one Fayda green-teal
accent reserved for identity/verification/active) is recorded in DESIGN.md;
product truth in PRODUCT.md; review protocol in .claude/agents/design-critic.md.
Solana wallet connection is intentionally disabled (SOLANA_WALLETS_ENABLED in
frontend/src/wallet/index.jsx) until external-wallet support in the connector
is verified — never fake a chain.

No blockchain connection anywhere. Signature verification is pure cryptography. No RPC,
no gas, no testnet. Keep it that way absent a specific reason to read chain state.

## Conventions

- Comments explain why, never what. If a line needs a what-comment, rewrite the line.
- Every security-relevant decision gets a comment naming the attack it prevents.
- New invariants get a test in t.py. A test that cannot fail is not a test.
- Prefer database constraints over application checks. Do both where it matters.
- No new dependencies without justification.

## Running locally

Two shells:

    PUBLIC_URL=http://localhost:5173 APP_ENV=dev python backend/app.py
    cd frontend && npm run dev        # then open http://localhost:5173

Storage needs SUPABASE_DB_URL — normally supplied by the gitignored
backend/.env, which store.py loads (real env vars win). Without it the app
refuses to start.

Use localhost consistently in the browser — localhost and 127.0.0.1 are
different cookie origins. Real wallet connection additionally needs
VITE_PRIVY_APP_ID in frontend/.env.local (see README); without it the app
runs with a setup notice and the dev test-key path.

Production refuses to start without SESSION_SECRET and FIN_PEPPER, and registers none
of the dev surface.

DEPLOY: one FastAPI process serves the API and the built SPA (frontend/dist)
same-origin — see DEPLOY.md + render.yaml + Dockerfile. Outside dev the cookie
is Secure and the public origin derives from PUBLIC_URL || RENDER_EXTERNAL_URL.
DEMO_MODE mounts the mock IdP (personas) for a credential-less shared demo but
NEVER /api/dev/* — a demo visitor cannot wipe the DB or skip cooling. Storage
is Supabase Postgres (R1): data survives redeploy/restart/scale, and the
deploy must set SUPABASE_DB_URL or the app refuses to start.

## Testing

APP_ENV=dev python backend/app.py in one shell (PUBLIC_URL unset — the tests
drive the backend origin directly), APP_ENV=dev python backend/t.py in another.
All checks pass before anything is done. Add to t.py rather than creating
parallel test files. For UI states: cd frontend && npm run shots regenerates
screenshots/.

The suite starts by resetting the registry, so it runs only against a database
that has been explicitly marked throwaway — once per dev database:

    APP_ENV=dev python backend/store.py mark-disposable

Storage is durable now, so nothing may drop tables on the strength of the
caller's own APP_ENV alone: the marker records the host it was written for and
must still match. Point backend/.env at production and both t.py and
/api/dev/reset refuse rather than destroying it.

## What done means

- python backend/t.py exits 0 with every check passing
- No raw FIN in the database, logs, any response body, or any cookie
- Dev surface unreachable when APP_ENV is not dev
