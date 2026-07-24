# Fayda identity → wallet registry

Internal proof of concept. Binds one Fayda-verified Ethiopian identity to at most
one verified self-custodied wallet per chain — one Ethereum, one Solana.

No custody is taken. No private keys are held. The only thing stored is proof that
a verified person controls a given address.

## Run

```bash
pip install fastapi uvicorn "pyjwt[crypto]" eth-account pynacl base58 httpx itsdangerous
APP_ENV=dev python app.py
```

`APP_ENV=dev` is required to run locally: it mounts the mock IdP and the
`/api/dev/*` helpers. Without it the app runs in its default production posture,
which registers none of the dev surface and refuses to start unless `SESSION_SECRET`
and `FIN_PEPPER` are set from a secret manager.

Open http://127.0.0.1:8000

Works with MetaMask, Rabby or Phantom if installed. If not, every screen has a
throwaway-test-key button that exercises the identical server path.

## What it does

1. **Verify identity** — real OIDC against a local mock Fayda. Authorization code
   flow, RS256 private-key-JWT client assertion, userinfo call.
2. **Connect wallet** — `window.ethereum` for EVM, `window.solana` for Phantom.
3. **Prove control** — server issues a single-use nonce, wallet signs a SIWE-style
   message, server verifies. EVM recovers the signer via secp256k1; Solana verifies
   ed25519 directly against the public key.
4. **Bind** — first wallet on a chain activates immediately. A replacement enters a
   72-hour cooling period during which the incumbent stays active.

## Files

| | |
|---|---|
| `app.py` | OIDC client, binding endpoints, registry API |
| `mock_esignet.py` | Mock Fayda provider — the only throwaway component |
| `store.py` | SQLite schema and queries |
| `verify.py` | EVM and Solana signature verification |
| `static/index.html` | UI |

## Design decisions worth knowing

**The raw FIN is never stored.** Only `HMAC-SHA256(pepper, FIN)`. A plain hash would
be useless — a FIN is 12 digits, so 10¹² values is exhaustively enumerable in minutes
on a laptop. The pepper must come from a secret manager in production; here it is
generated per run.

**Two partial unique indexes carry the guarantee:**

```sql
UNIQUE (identity_id, chain) WHERE status = 'active'   -- one wallet per chain
UNIQUE (chain, address)     WHERE status = 'active'   -- one identity per wallet
```

The second is the sybil constraint. Without it, one wallet could be claimed by two
identities and the whole premise collapses. It is enforced at the database level and
re-checked at commit time, not only when the nonce is issued.

**The server never trusts the client's copy of the signed message.** The message is
stored alongside the nonce when issued and reloaded at verification.

**Nonces are single-use, 5-minute TTL, bound to address and chain.** Replay, cross-address
and cross-chain reuse all fail.

**Cooling period protects against session compromise.** If an attacker with a live
session initiates a wallet swap, the real user has 72 hours to cancel, and their
existing wallet keeps working throughout. Configurable via `COOLING_HOURS`.

## Going to production

Swap the mock for real Fayda by setting environment variables — no code changes:

```bash
FAYDA_CLIENT_ID=...
FAYDA_AUTHORIZE_URL=https://<issued-host>/authorize
FAYDA_TOKEN_URL=https://<issued-host>/v1/esignet/oauth/v2/token
FAYDA_USERINFO_URL=https://<issued-host>/v1/esignet/oidc/userinfo
FIN_PEPPER=<from secret manager>
```

Then remove `mock_esignet.py`, delete every `/api/dev/*` route, and replace the
generated RSA keypair with one whose public JWK is registered at
[partner.fayda.et](https://partner.fayda.et).

## What this does not prove

**The claim names are a reconstruction.** `fayda_fin`, `birthdate`, `auth_method` and
the rest are my best guess at eSignet's userinfo response. The real scope names and
claim shape are only knowable with approved partner credentials, and this is the one
part likely to need rework.

**Fayda does not prove citizenship.** Ethio Telecom's own documentation defines an
eligible Fayda resident as a person living in Ethiopia *with or without proof of
Ethiopian citizenship*, including foreign residents. Any citizens-only product needs
a separate check — an open question worth putting to ECMA.

**Nothing is on-chain.** The binding is a database row. If a smart contract ever needs
to read it, an attestation layer is required — and in that case the attestation must
reference the wallet address only, never anything FIN-derived.

**No production hardening.** No rate limiting, no audit log, no HTTPS, no CSRF beyond
the OIDC state parameter, no data-retention policy. In production `SESSION_SECRET` and
`FIN_PEPPER` must be pinned from a secret manager — the app refuses to start without
them — and the pepper cannot be rotated in place without re-hashing every identity row.

## Tests

`APP_ENV=dev python app.py` in one shell, then `python t.py` in another. Covers the
OIDC round trip, both chains, bad-signature rejection, nonce replay, the cooling-period
lifecycle, the sybil constraint across two identities, cross-chain signature confusion,
the FIN-never-leaves-the-server property, and the production/dev environment gating.
