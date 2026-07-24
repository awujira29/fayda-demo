# Fayda identity → wallet registry

Internal proof of concept. Binds one Fayda-verified Ethiopian identity to at most
one verified self-custodied wallet per chain — one Ethereum, one Solana.

No custody is taken. No private keys are held. The only thing stored is proof that
a verified person controls a given address.

Two processes: a Python/FastAPI API in `backend/`, a React + Vite frontend in
`frontend/`.

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
`127.0.0.1:8000`, so the browser never leaves its own origin.

`APP_ENV=dev` mounts the mock IdP and the `/api/dev/*` helpers. Without it the
app runs in its production posture: none of the dev surface is registered and it
refuses to start unless `SESSION_SECRET` and `FIN_PEPPER` come from a secret
manager. `PUBLIC_URL` is the origin the *browser* stays on; `BASE_URL`
(default `http://127.0.0.1:8000`) is where the backend is reachable for
server-to-server calls. When `PUBLIC_URL` is unset it falls back to `BASE_URL`,
which is the single-origin mode the tests use.

## Wallet connection (Privy)

Real wallet connection runs through [Privy](https://privy.io) — connection
only, external self-custody wallets only. Identity comes from Fayda; Privy is
never an identity provider here, and embedded wallets are switched off
(`createOnLogin: 'off'` for both chains).

Setup:

1. Create an app at [dashboard.privy.io](https://dashboard.privy.io)
2. `echo "VITE_PRIVY_APP_ID=<your app id>" > frontend/.env.local`
3. Restart `npm run dev`

Without the app id the UI renders a setup notice instead of the connect
buttons; identity verification and the dev test-key path work regardless.

Every Privy call is isolated in **`frontend/src/wallet.js`** — the provider
seam. Nothing else imports from `@privy-io`. Swapping providers means
rewriting that one file.

**EVM**: `wallet.getEthereumProvider()` + `personal_sign` over the message
bytes — the EIP-191 personal-message envelope that `eth_account`'s
`encode_defunct(text=…)` verifies server-side. The envelope itself is
exercised end to end by the test suite and the dev test-key path; the
MetaMask-through-Privy-modal leg needs your app id, so run it once after
setup and expect it to work — `personal_sign` is the stable, universal path.

**Solana — the honest caveat**: Privy's docs contradict each other on whether
*external* Solana wallets (Phantom, Solflare) are supported — the
`useSolanaWallets` reference implies embedded-only, the connector guide shows
external working. The installed SDK (v3.35) types its Solana hook around
wallet-standard **external** wallets (`ConnectedStandardSolanaWallet`), and
this app implements signing against that surface (`signMessage` → ed25519
bytes → base58). But it has **not been verified against a live external
Solana wallet** in this environment (no Privy app id available). If the
Solana connect path fails for you, that is the known risk — the EVM path is
the verified one. Report what you see rather than assuming the button works.

## What it does

1. **Verify identity** — real OIDC against a local mock Fayda (authorization
   code flow, RS256 private-key-JWT client assertion, userinfo). The mock's
   authorize screen is a *simulated biometric prompt*: in production eSignet
   captures a fingerprint, iris or face; here, picking a resident stands in
   for a successful match.
2. **Connect wallet** — Privy modal, external wallets only.
3. **Prove control** — server issues a single-use nonce, the wallet signs a
   SIWE-style message, the server verifies against its own stored copy.
4. **Bind** — first wallet on a chain activates immediately. A replacement
   enters a 72-hour cooling period during which the incumbent stays active.

Reloading keeps both the Fayda session (server-side, opaque cookie) and the
wallet connection (Privy reconnects). Switching accounts in the wallet
extension is reflected live — a stale address cannot sit in the signing panel.

## Files

| | |
|---|---|
| `backend/app.py` | OIDC client, server-side sessions, binding endpoints, registry API |
| `backend/mock_esignet.py` | Mock Fayda provider — the only throwaway component |
| `backend/store.py` | SQLite schema and queries; the unique indexes that carry the guarantees |
| `backend/verify.py` | EVM and Solana signature verification |
| `backend/t.py` | End-to-end tests |
| `frontend/src/wallet.js` | The Privy seam — sole importer of `@privy-io` |
| `frontend/src/tokens.css` | Design tokens — single source of visual values |
| `frontend/scripts/screenshots.mjs` | Captures every UI state for design review |

## Design decisions worth knowing

**The raw FIN is never stored.** Only `HMAC-SHA256(pepper, FIN)`. A plain hash
would be useless — a FIN is 12 digits, so 10¹² values is exhaustively enumerable
in minutes. The pepper must come from a secret manager in production.

**Sessions are server-side.** The confirmed Fayda claims include
neighbourhood-level address (kebele/woreda), which must not sit in a
signed-but-unencrypted cookie. Session data lives in SQLite; the cookie is an
opaque id plus HMAC. (The official `fayda-auth-python` library uses Redis for
the same reason.)

**Two partial unique indexes carry the guarantee:**

```sql
UNIQUE (identity_id, chain) WHERE status = 'active'   -- one wallet per chain
UNIQUE (chain, address)     WHERE status = 'active'   -- one identity per wallet
```

The second is the sybil constraint, enforced at the database level and
re-checked at commit time. The pending tier has the same cross-identity index.

**The server never trusts the client's copy of the signed message.** Stored at
nonce issue, reloaded at verification.

**Cooling period protects against session compromise.** An attacker with a live
session who initiates a swap gives the real user 72 hours to cancel, and the
existing wallet keeps working throughout. Configurable via `COOLING_HOURS`.

## Going to production

Point the OIDC client at real Fayda by env var — no code changes:

```bash
FAYDA_CLIENT_ID=...
FAYDA_AUTHORIZE_URL=https://<issued-host>/authorize
FAYDA_TOKEN_URL=https://<issued-host>/v1/esignet/oauth/v2/token
FAYDA_USERINFO_URL=https://<issued-host>/v1/esignet/oidc/userinfo
PUBLIC_URL=https://<frontend-origin>
SESSION_SECRET=<from secret manager>
FIN_PEPPER=<from secret manager>
```

Then remove `backend/mock_esignet.py` and replace the generated RSA keypair
with one whose public JWK is registered at
[partner.fayda.et](https://partner.fayda.et). The `/api/dev/*` surface is
already absent whenever `APP_ENV` is not `dev`.

## What this does not prove

**The claim shape is confirmed; live integration is not.** The userinfo schema
matches the official client library
([fayda-auth-python](https://github.com/National-ID-Program-Ethiopia/fayda-auth-python)):
`sub, name, birthdate, gender, phone, picture, residenceStatus, address
{kebele, region, woreda, zone}`. What remains unverified without partner
credentials: the live endpoints, and the `residenceStatus` **value set** —
check with NIDP before any feature branches on it.

**Fayda does not prove citizenship.** An eligible Fayda resident may be a
foreign national legally resident in Ethiopia (see persona "Daniel Otieno").
Any citizens-only product needs a separate check — `residenceStatus` is the
likely home for it, pending NIDP confirmation.

**Nothing is on-chain.** The binding is a database row. If a smart contract
ever needs to read it, an attestation layer is required — referencing the
wallet address only, never anything FIN-derived.

**No production hardening.** No rate limiting, no audit log, no HTTPS
termination, no data-retention policy. See PROGRESS.md for the open items.

## Tests

```bash
APP_ENV=dev python backend/app.py     # shell 1 — PUBLIC_URL unset for tests
python backend/t.py                   # shell 2
```

Covers the OIDC round trip, both chains, bad-signature rejection, nonce replay,
the cooling lifecycle, the sybil constraint (active and pending tiers, including
the raced variants), IntegrityError translation, the FIN-never-leaves-the-server
property, the opaque-cookie property, session fixation, and production/dev
gating. UI states: `cd frontend && npm run shots` writes `screenshots/`;
design findings live in `DESIGN-REVIEW.md`.
