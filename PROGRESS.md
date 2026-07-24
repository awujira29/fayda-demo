# PROGRESS

The loop's memory. The agent forgets between runs; this file does not.
Update as work completes. Do not delete history, move items to Done.

Status: todo / doing / blocked / review / done

---

## Now

### M5 - sessions table grows without bound from unauthenticated /login
**Status:** todo
**Severity:** medium (auditor finding, 2026-07-24, session-storage review)
**Why:** Every /login hit persists an oidc_state session row; rows are swept only
lazily on load of that exact sid, so anonymous hits accumulate forever. Same class
as L1 (nonce growth) but attacker-drivable without auth.
**Do:** Periodic DELETE FROM sessions WHERE expires_at < now (share the sweep with
L1), and consider not persisting a session until it holds more than oidc_state.

### M6 - Every authenticated request rewrites its session row
**Status:** todo
**Severity:** medium (auditor finding, 2026-07-24)
**Why:** The middleware unconditionally re-saves and re-sets the cookie on every
response with a non-empty session, turning polled reads (/api/me, /api/registry)
into writes under the process-global DB lock.
**Do:** Save only when the session dict actually changed (compare a snapshot taken
at request start); refresh the sliding expiry at a coarser interval.

### M7 - Logout is not atomic against concurrent requests
**Status:** todo
**Severity:** medium (auditor finding, 2026-07-24)
**Why:** A second in-flight request for the same sid re-saves its request-start
snapshot at response time, resurrecting the row logout just deleted and re-setting
the cookie. Self-defeating concurrency, not attacker-exploitable directly.
**Do:** Tombstone deleted sids for the TTL window, or re-check row existence before
the middleware save.

### M4 - New pending index aborts startup on a DB that already hit M2
**Status:** todo
**Severity:** medium (auditor finding, 2026-07-24, from the M2 fix review)
**Why:** ux_pending_chain_address is created with CREATE UNIQUE INDEX IF NOT EXISTS,
which is evaluated against existing rows. A database that suffered M2 before the fix
still contains two pending rows on one (chain, address); index creation then raises
IntegrityError inside store.init() at import time and the app refuses to boot. For
exactly the population the fix targets, this trades a per-read 500 for a hard-down.
Irrelevant to fresh/throwaway DBs, which is why t.py passes.

**Do:**
- Before creating the index, cancel duplicate pending rows (keep the oldest per
  (chain, address), cancel the rest) as a one-time cleanup in init()
- Test: plant duplicate pendings in a DB without the index, re-init, assert boot
  succeeds and the duplicates are cancelled

### R1 - Record wallet provenance and assurance level
**Status:** todo
**Why:** A signature from a self-custody wallet proves the user controls the key. From
a provider-held embedded wallet (Privy et al.) it proves the user authenticated to the
provider and the provider co-signed. Weaker claim, same shape. This registry exists to
assert "this verified human controls this address", so the distinction must be recorded
at bind time. It cannot be reconstructed later.

**Do:**
- Add wallet_source (external | embedded | custodial) and assurance_level
  (self_custody | provider_assisted) to wallet_bindings. Both NOT NULL.
- Existing rows migrate to external / self_custody.
- Surface in /api/me, /api/registry and the UI. Provider-assisted must be visually
  distinguishable.
- Tests asserting defaults and round-trip.

### R2 - Wallet provider interface
**Status:** done (frontend seam) / open (embedded-wallet path) - 2026-07-24
**Why:** Privy or equivalent is likely needed for farmer lending, where users have no
wallet and cannot manage a seed phrase. Adding it later should be additive.

**What landed (S2):** the seam is real and lives client-side —
frontend/src/wallet.js is the only file that may import @privy-io, exposing
WalletProvider/useWalletConnection/signFor. Swapping providers = rewriting one
file. Privy is integrated for CONNECTION of external self-custody wallets only;
embedded wallets are off (createOnLogin: 'off', both chains). The binding
endpoint remains provider-agnostic (verifies signatures, nothing else).

**Still open:** the embedded-wallet path itself — gated on B3 (data residency)
and R1 (provenance columns must land BEFORE any provider-assisted binding is
accepted, or the distinction is unrecoverable).

### L1-L4 - Deferred
- L1 auth_nonces never pruned. Add periodic delete.
- L2 Solana addresses compared case-insensitively. base58 is case-sensitive; only EVM
  hex is case-insensitive. Normalise per chain. Auditor note (2026-07-24): the unique
  indexes (active tier and the new pending tier) are case-SENSITIVE while the app
  check lowercases, so case-variant EVM addresses can slip both — normalising at
  write time fixes the index gap too.
- L3 OIDC nonce generated but never validated. Dead scaffolding that reads as protection.
- L4 promote_due runs lazily on read. Should be a scheduled job. Auditor note
  (2026-07-24, N3): the new global DB lock makes access strictly serial, and the
  unauthenticated /api/registry driving promote_due amplifies the serialization.
  Acceptable single-process; folds into the scheduled-job fix.
- L5 (auditor N2, 2026-07-24) BindingConflict can cosmetically misclassify a
  same-identity double-bind as "different identity" when both unique indexes are
  violated at once (SQLite names (chain,address) first). Both paths 409; message
  polish only.
- L6 (auditor, 2026-07-24) /api/me returns kebele/woreda address in the body —
  owner's own data, consistent with the cookie rationale, but add
  Cache-Control: no-store to authenticated responses.
- L7 (auditor, 2026-07-24) A non-string sub from a real provider would 500 in
  hash_fin; coerce/validate at the callback boundary.
- L8 (auditor, 2026-07-24) Mock /authorize reflects state/scope/redirect_uri
  unescaped; dev-only, 404 in production. Re-flagged after the restructure:
  the Vite proxy now serves the mock page on the SPA origin, so the reflected
  XSS would run same-origin with the real app in dev. HTML-escape the params.
- L9 (auditor, 2026-07-24) PUBLIC_URL defaults to BASE_URL: running the SPA
  without PUBLIC_URL=http://localhost:5173 strands the session cookie on the
  backend origin — fails safe (never logged in), but the two-process dev run
  silently half-works. Consider warning at startup when APP_ENV=dev and
  PUBLIC_URL is unset.
- L10 (auditor, 2026-07-24) /api/me exposes "dev": DEV_MODE to any caller.
  False in production; used to gate dev-only UI. Informational.

---

## Blocked

### B1 - Live Fayda integration
Claim NAMES are no longer blocked: the userinfo shape is confirmed from the official
Python client (github.com/National-ID-Program-Ethiopia/fayda-auth-python) and
mock_esignet.py now mirrors it — sub, name, birthdate, gender, phone, picture,
residenceStatus, address {kebele, region, woreda, zone}. Still blocked on partner
credentials from partner.fayda.et for a live end-to-end test. The residenceStatus
VALUE SET remains unconfirmed (see B2).

### B2 - Citizenship check
Fayda proves residency, not citizenship. Foreign nationals resident in Ethiopia can hold
valid Fayda. Any citizens-only feature needs a separate mechanism. Open question for ECMA.
Update 2026-07-24: the confirmed schema carries residenceStatus — the most likely home
for this distinction. It is whitelisted, surfaced in the UI, and exercised by a
FOREIGN_NATIONAL mock persona (Daniel Otieno). Its value set is UNCONFIRMED — must be
checked with NIDP before any feature branches on it.

### B3 - Privy data residency
Privy is US-hosted and Stripe-owned since June 2025. Binding a Fayda-verified identity
to a wallet whose keys are partly held abroad is a question for NBE and NIDP under
Ethiopian data-protection rules. Unanswered. Do not integrate before it is.

---

## Done

### S2 - Restructure: backend/ + React/Vite frontend + Privy wallet layer - done 2026-07-24
Backend moved (not rewritten) into backend/; t.py changed only by subprocess
cwd. New URL split: BASE_URL (server-to-server token/userinfo) vs PUBLIC_URL
(browser-facing authorize/redirect_uri, defaults to BASE_URL so single-origin
t.py runs unchanged). Frontend rebuilt as React + Vite in frontend/: the Vite
dev server proxies /api,/login,/logout,/callback,/authorize,/v1 so the browser
never leaves localhost:5173 and the session cookie lands on the right origin —
verified end to end (login → cookie → authenticated API calls all on 5173).

Wallet layer: Privy (@privy-io/react-auth 3.35) for connection only, external
self-custody only, embedded wallets off. All Privy imports isolated in
frontend/src/wallet.js (see R2). EVM signs personal_sign/EIP-191 matching
verify.py's encode_defunct; Solana signs wallet-standard signMessage → base58.
External-Solana caveat documented honestly in README: implemented against the
SDK's wallet-standard (external) type surface but NOT verified against a live
wallet here (no Privy app id in this environment); EVM is the verified path.
Missing VITE_PRIVY_APP_ID renders a setup notice, not a crash. Account switch
in the extension is reflected live; the signing panel blocks on stale wallets.

Mock authorize page reframed as a simulated biometric capture (fingerprint
glyph, "SIMULATED CAPTURE — NO SENSOR READ", personas as match results);
OIDC contract untouched, t.py regexes intact. Design: two-pass design-critic
review (DESIGN-REVIEW.md, screenshots/ via frontend/scripts/screenshots.mjs +
playwright-core/Chrome) — 1 high + 5 medium + 4 low found in pass one, all
resolved in pass two, verdict "designed". Tokens extracted to
frontend/src/tokens.css, referenced from CLAUDE.md.

Auditor (AUDIT.md top section): 0 new criticals, 0 new highs; origin split
introduces no session/CSRF weakness; three lows recorded as L8 (re-flag),
L9, L10. python backend/t.py: all 18 checks pass. Note for B3: this Privy
integration takes no key custody (connection only), so B3's residency question
stays scoped to the future embedded-wallet path.

### S1 - Real userinfo schema + server-side sessions - done 2026-07-24
mock_esignet.py now returns the confirmed Fayda claim shape (source:
github.com/National-ID-Program-Ethiopia/fayda-auth-python): sub, name, birthdate,
gender, phone, picture, residenceStatus, address {kebele, region, woreda, zone}.
fayda_fin, given_name, family_name, phone_number, auth_method, auth_time removed;
sub is the only identifier (callback 502s without it). SAFE_CLAIMS is now
{name, birthdate, gender, address, residenceStatus}; sub, phone and picture are
deliberately excluded and tested (t.py 3c asserts names AND values absent from
/api/me). residenceStatus surfaced in the identity card; fourth persona
(FOREIGN_NATIONAL) exercises the B2 distinction.

Sessions moved server-side: address now carries kebele/woreda (neighbourhood-level
location), which must not sit in Starlette's signed-not-encrypted cookie. Session
data lives in a sessions table (SQLite — the official library uses Redis for the
same reason); the cookie holds only an opaque token_urlsafe(32) sid plus an HMAC
under SESSION_SECRET; HttpOnly, SameSite=Lax, 12h TTL. The sid rotates at login
(fixation defense, tested in 3b); test 3b also decodes every cookie segment and
asserts no session data is client-readable. Auditor: 0 new criticals, 0 new highs;
three mediums recorded as M5/M6/M7, lows as L6-L8. Design critic: approved; URL in
the banner set in mono per its nit. C1's residual (PII in the unencrypted cookie)
is now closed.

### M1 - IntegrityError surfaces as 500 instead of 409 - resolved 2026-07-24
store.create_binding wraps its INSERT: sqlite3.IntegrityError re-raises as
store.BindingConflict with a fixed client-safe message, distinguishing the two
index flavors by the columns SQLite names — (chain, address) → "bound to a
different Fayda identity", (identity_id, chain) → "already active or pending —
reload and retry". wallet_bind translates BindingConflict to 409. Test 17 races
two first-time binders on one address over HTTP (10 rounds, threads + barrier)
and asserts [200, 409] never 500 — verified to fail [200, 500] with the
translation removed. Test 18 drives both flavors at the store level.

Side discovery, fixed in the same diff: the race test deadlocked the whole
server inside the OS sqlite library (macOS: connection_close in sqlite3WalClose
vs connection_init in findReusableFd, both parked on the same inode mutex) — a
two-concurrent-requests DoS, pre-existing, just never triggered by the serial
test suite. store.conn() now serializes open/use/close behind a process-level
threading.Lock; no store function opens a nested connection (auditor-verified),
and the check-then-insert race window in app.py spans multiple store calls, so
test 17 still exercises the real race. Auditor: M1 resolved, 0 new criticals,
0 new highs; two lows recorded as L5 and the L4 note.

### M2 - Cross-identity pending race wedges the registry - resolved 2026-07-24
Was: ux_pending_identity_chain scoped per-identity let two identities hold pending
bindings on one address; promotion then raised IntegrityError inside promote_due,
which runs on every /api/me and /api/registry read → permanent 500 for everyone.
Fix: (1) new partial unique index ux_pending_chain_address on (chain, address)
WHERE status='pending' closes the pending-vs-pending race at the DB layer;
(2) promote_due wraps each promotion in a SAVEPOINT — on IntegrityError it rolls
back (the loser's incumbent stays active) and cancels the conflicting pending row
so it never re-detonates. Tests 15 and 16 in t.py: 15 plants the un-indexable
active-vs-pending raced state and asserts reads stay 200, the loser is cancelled,
and both incumbents survive (verified to fail with a wedged 500 against pre-fix
store.py); 16 asserts the index rejects a duplicate cross-identity pending.
Auditor review of the diff: 0 new criticals, 0 new highs; one new medium (M4,
migration hazard on already-wedged DBs) and one low folded into L2.

### C1 - Raw FIN sent to the browser (critical) - resolved 2026-07-24
Whitelist at the callback boundary. The original residual — claims sitting in a
signed-not-encrypted cookie — was closed by S1 (server-side sessions, opaque
cookie) on the same day.

### H1 - Unauthenticated dev_reset - resolved 2026-07-24
### H2 - fast-forward cooling bypass - resolved 2026-07-24
### H3 - Secret/pepper regeneration - resolved 2026-07-24
### N1 - APP_ENV defaulted open - resolved 2026-07-24
Default inverted to production so a forgotten env var fails closed.
### M3 - Dev surface unguarded - resolved as side effect of H1/H2/H3
