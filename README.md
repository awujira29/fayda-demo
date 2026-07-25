# Fayda identity → wallet registry

Internal proof of concept. Binds one Fayda-verified Ethiopian identity to at
most one verified self-custodied wallet per chain — one Ethereum, one Solana.

No custody is taken. No private keys are held. The only thing stored is proof
that a verified person controls a given address.

Two processes: a Python/FastAPI API in `backend/`, a React + Vite + Tailwind
frontend in `frontend/`.

## Run

**Backend** (Python 3.11+):

```bash
pip install -r backend/requirements.txt
PUBLIC_URL=http://localhost:5173 APP_ENV=dev python backend/app.py
```

**Frontend** (Node 20+):

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — use `localhost`, not `127.0.0.1`: they are
different cookie origins, and the session cookie is set during the OIDC
callback on the frontend origin. The Vite server proxies every backend path
(`/api`, `/login`, `/logout`, `/callback`, `/authorize`, `/v1`) to
`127.0.0.1:8000`, so the browser never leaves its own origin. If the backend
is started without `PUBLIC_URL`, the UI shows an origin-mismatch notice
instead of letting sign-in silently half-fail.

`APP_ENV=dev` mounts the mock IdP and `/api/dev/*`. Without it the app runs in
its production posture: no dev surface, and it refuses to start unless
`SESSION_SECRET` and `FIN_PEPPER` come from a secret manager.

## Wallet connection (Privy)

Real wallet connection runs through [Privy](https://privy.io) — as a
connector only. Identity comes from Fayda; Privy is never an identity
provider here, and embedded wallets are off (`createOnLogin: 'off'`, both
chains): external self-custody wallets only. Privy's connect modal performs
EIP-6963 multi-wallet discovery, so several installed extensions coexist
instead of fighting over `window.ethereum`.

Setup (free under 499 monthly users):

1. Create an app at [dashboard.privy.io](https://dashboard.privy.io)
2. `echo "VITE_PRIVY_APP_ID=<your app id>" > frontend/.env.local`
3. Restart `npm run dev`
4. **Mobile wallets only:** Privy uses WalletConnect for phone wallets. If you
   need those, also create a project id at
   [cloud.reown.com](https://cloud.reown.com) (formerly WalletConnect Cloud)
   and add it in the Privy dashboard under your app's WalletConnect settings.
   Desktop extension wallets (MetaMask, Rabby) need no project id.

Without an app id the UI renders a designed setup card; identity verification
and the dev test-key path work regardless.

Every `@privy-io` import is isolated in **`frontend/src/wallet/`** — the
connector seam. Nothing else imports it; swapping providers means rewriting
that one directory.

**EVM**: `wallet.getEthereumProvider()` + `personal_sign` over the message
bytes — the EIP-191 envelope that the backend's
`eth_account.encode_defunct(text=…)` + `recover_message` verifies. The
envelope is exercised end to end by the test suite; MetaMask is confirmed
present and EIP-6963-discoverable in the development browser. The
modal-connect leg needs your Privy app id plus a human click in the MetaMask
popup — run it once after setup.

**Solana — the honest truth**: Privy's docs contradict each other on whether
*external* Solana wallets (Phantom, Solflare) are supported — the
`useSolanaWallets` reference implies embedded-only; the connector guide shows
external working. Unverified support is not support: the Solana connect path
is **switched off in the UI** (an explicit "not yet enabled" state — see
`SOLANA_WALLETS_ENABLED` in `frontend/src/wallet/index.jsx`), rather than a
button that might silently fail. The backend already verifies ed25519
signatures, and the dev test-key path exercises that today, so enabling real
Solana wallets is frontend-only work once the connector is proven against a
live wallet.

## What it does

1. **Verify identity** — real OIDC against a local mock Fayda (authorization
   code flow, RS256 private-key-JWT client assertion, userinfo). The mock's
   authorize screen simulates biometric capture and says so; in production
   this is eSignet's fingerprint/iris/face step.
2. **Connect a wallet** — Privy modal, external wallets only.
3. **Review and sign** — the server issues a single-use nonce and a
   human-readable message; the wallet displays that exact message; the server
   verifies the signature against its own stored copy.
4. **Bind** — the first wallet on a chain activates immediately. A
   replacement enters a 72-hour cooling period during which the incumbent
   stays active; the delay exists so a hijacked session cannot swap your
   wallet instantly.

Reloading preserves the Fayda session (server-side, opaque cookie) and the
wallet connection (the connector reconnects). Switching accounts in the
wallet extension is reflected live, and a pending attestation for a
no-longer-connected address is blocked with an explanation.

## Files

| | |
|---|---|
| `backend/app.py` | OIDC client, server-side sessions, binding endpoints, registry API |
| `backend/mock_esignet.py` | Mock Fayda provider — the only throwaway component |
| `backend/store.py` | SQLite schema and queries; the unique indexes that carry the guarantees |
| `backend/verify.py` | EVM (secp256k1 recovery) and Solana (ed25519) verification |
| `backend/t.py` | End-to-end tests |
| `frontend/src/wallet/` | The connector seam — sole importer of `@privy-io` |
| `frontend/src/styles/tokens.css` | Design tokens (OKLCH) — single source of visual values |
| `frontend/scripts/screenshots.mjs` | Captures every UI state, both themes, desktop + 380px |
| `DESIGN.md` / `PRODUCT.md` | The committed visual world and product truth |

## Design decisions worth knowing

**The raw FIN is never stored.** Only `HMAC-SHA256(pepper, FIN)`. A plain
hash would be enumerable in minutes (12-digit space); the pepper must come
from a secret manager in production.

**Sessions are server-side.** Fayda claims include neighbourhood-level
address (kebele/woreda); that never sits in a decodable cookie. The cookie is
an opaque id + HMAC.

**Two partial unique indexes carry the guarantee** — one active wallet per
(identity, chain), one active identity per (chain, address); the second is
the sybil constraint, enforced in the database and re-checked at commit. The
pending tier has the same cross-identity index.

**The server never trusts the client's copy of the signed message.** Stored
at nonce issue, reloaded at verification. Nonces are single-use, 5-minute
TTL, bound to address and chain.

## Going to production

```bash
FAYDA_CLIENT_ID=...
FAYDA_AUTHORIZE_URL=https://<issued-host>/authorize
FAYDA_TOKEN_URL=https://<issued-host>/v1/esignet/oauth/v2/token
FAYDA_USERINFO_URL=https://<issued-host>/v1/esignet/oidc/userinfo
PUBLIC_URL=https://<frontend-origin>
SESSION_SECRET=<secret manager>
FIN_PEPPER=<secret manager>
```

Then remove `backend/mock_esignet.py` and register a real RSA keypair's
public JWK at [partner.fayda.et](https://partner.fayda.et). The `/api/dev/*`
surface is absent whenever `APP_ENV` is not `dev`.

## What this does not prove

**Claim shape confirmed; live integration not.** The userinfo schema matches
the official client
([fayda-auth-python](https://github.com/National-ID-Program-Ethiopia/fayda-auth-python)).
Unverified without partner credentials: the live endpoints and the
`residenceStatus` **value set** — display it, never branch on it, until NIDP
confirms.

**Fayda does not prove citizenship.** Valid Fayda holders include legally
resident foreign nationals (see persona "Daniel Otieno"); `residenceStatus`
is the likely home for the distinction, pending NIDP.

**Nothing is on-chain.** A binding is a database row; signature verification
is pure cryptography — no RPC, no gas, no testnet anywhere.

## Tests

```bash
APP_ENV=dev python backend/app.py     # shell 1 — PUBLIC_URL unset for tests
python backend/t.py                   # shell 2
```

18 checks: OIDC round trip, both chains, bad signatures, nonce replay,
cooling lifecycle, sybil constraint (active + pending tiers, raced variants),
IntegrityError translation, FIN-never-leaves-the-server, opaque cookie,
session fixation, dev/production gating. UI states:
`cd frontend && npm run shots` writes `screenshots/`; design findings live in
`DESIGN-REVIEW.md`.
