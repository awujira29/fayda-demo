# CLAUDE.md

Project knowledge for the Fayda identity to wallet registry. Read before touching anything.

## What this is

A registry binding one Fayda-verified Ethiopian identity to at most one verified
self-custodied wallet per chain (Ethereum, Solana). Takes no custody, holds no
private keys. Stores only cryptographic proof that a verified person controls an address.

Two processes: a Python / FastAPI / SQLite API in backend/, and a React + Vite
frontend in frontend/. The frontend proxies every backend path so the browser
never leaves its own origin — the session cookie depends on it.

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
| backend/store.py | Schema and queries. Unique indexes live here. |
| backend/verify.py | secp256k1 recovery (EVM), ed25519 verification (Solana) |
| backend/mock_esignet.py | Throwaway. Deleted in production. |
| backend/t.py | End-to-end tests |
| frontend/src/wallet.js | THE Privy seam (R2). The only file that may import @privy-io. |
| frontend/src/App.jsx | State + flow composition |
| frontend/src/components.jsx | UI components |
| frontend/src/tokens.css | Design tokens — the single source of visual values |

Two base URLs on the backend: BASE_URL is where the process is reachable for
server-to-server calls (token, userinfo); PUBLIC_URL is the origin the browser
stays on (the Vite server in dev). redirect_uri and the authorize URL are built
from PUBLIC_URL. Get this wrong and the session cookie lands on the wrong origin.

Design values (colour, type scale, spacing) live in frontend/src/tokens.css —
change them there, never as literals in components. The visual language is
specified in .claude/agents/design-critic.md.

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

Use localhost consistently in the browser — localhost and 127.0.0.1 are
different cookie origins. Real wallet connection additionally needs
VITE_PRIVY_APP_ID in frontend/.env.local (see README); without it the app
runs with a setup notice and the dev test-key path.

Production refuses to start without SESSION_SECRET and FIN_PEPPER, and registers none
of the dev surface.

## Testing

APP_ENV=dev python backend/app.py in one shell (PUBLIC_URL unset — the tests
drive the backend origin directly), python backend/t.py in another. All checks
pass before anything is done. Add to t.py rather than creating parallel test
files. For UI states: cd frontend && npm run shots regenerates screenshots/.

## What done means

- python backend/t.py exits 0 with every check passing
- No raw FIN in the database, logs, any response body, or any cookie
- Dev surface unreachable when APP_ENV is not dev
