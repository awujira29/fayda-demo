# CLAUDE.md

Project knowledge for the Fayda identity to wallet registry. Read before touching anything.

## What this is

A registry binding one Fayda-verified Ethiopian identity to at most one verified
self-custodied wallet per chain (Ethereum, Solana). Takes no custody, holds no
private keys. Stores only cryptographic proof that a verified person controls an address.

Python / FastAPI / SQLite. Single-page vanilla-JS frontend, no build step.

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

**The userinfo claim names are a reconstruction.** fayda_fin, auth_method and the rest
are guesses at eSignet's real response. Isolated in mock_esignet.py deliberately. When
real credentials arrive that file should be the only thing needing change.

**Cooling period exists for session compromise, not user convenience.** If an attacker
with a live session swaps the wallet, the real user needs a window to cancel and their
existing wallet must keep working. Do not simplify this into an instant swap.

## Architecture

| File | Role |
|---|---|
| app.py | OIDC client, binding endpoints, registry API |
| store.py | Schema and queries. Unique indexes live here. |
| verify.py | secp256k1 recovery (EVM), ed25519 verification (Solana) |
| mock_esignet.py | Throwaway. Deleted in production. |
| static/index.html | UI |
| t.py | End-to-end tests |

No blockchain connection anywhere. Signature verification is pure cryptography. No RPC,
no gas, no testnet. Keep it that way absent a specific reason to read chain state.

## Conventions

- Comments explain why, never what. If a line needs a what-comment, rewrite the line.
- Every security-relevant decision gets a comment naming the attack it prevents.
- New invariants get a test in t.py. A test that cannot fail is not a test.
- Prefer database constraints over application checks. Do both where it matters.
- No new dependencies without justification.

## Running locally

APP_ENV=dev python app.py

Production refuses to start without SESSION_SECRET and FIN_PEPPER, and registers none
of the dev surface.

## Testing

APP_ENV=dev python app.py in one shell, python t.py in another. All checks pass before
anything is done. Add to t.py rather than creating parallel test files.

## What done means

- python t.py exits 0 with every check passing
- No raw FIN in the database, logs, any response body, or any cookie
- Dev surface unreachable when APP_ENV is not dev
