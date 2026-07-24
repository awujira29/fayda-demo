# AUDIT

Adversarial security audit of the Fayda identity → wallet registry.
Newest run at the top. The auditor reports; it does not fix.

---

## Verification pass — 2026-07-24 (post-fix)

Re-audit after a developer applied fixes for **C1, H1, H2, H3 only** (mediums/lows
deferred by design). Method: re-read all six files from scratch, re-derived each
finding, then ran `python t.py` against a live server. **All 14 checks pass**,
including the new adversarial ones (3b, 12, 13, 14). Findings below are independent
of the test outcome — the test is corroboration, not the basis.

### The four fixes

#### C1 — Raw FIN to the browser — **RESOLVED**
The callback now whitelists claims before anything enters the session. `SAFE_CLAIMS`
(`app.py:108-111`) is a positive allow-list — `name, given_name, family_name,
birthdate, gender, address, auth_method, auth_time`. `safe_claims()`
(`app.py:114-115`) keeps only those keys, and `callback` stores the filtered dict:
`request.session["claims"] = safe_claims(claims)` (`app.py:185`). The raw `fin` is
computed for hashing only (`app.py:175-177`) and never stored, logged, or returned.
`/api/me` echoes the already-filtered `claims` (`app.py:293`), so `sub`, `fayda_fin`,
and `phone_number` cannot reach the body, the DOM, or the signed-not-encrypted
cookie. This is a whitelist, not a blocklist: a newly-added sensitive claim is
dropped by default (fail-closed), which is the correct direction and directly
answers the original fix note. I tried to find a whitelisted claim that carries the
FIN — none does: in the mock, `address` is `{region, country}`, and no allow-listed
claim contains the 12-digit value. The three leak paths from the prior audit
(`/api/me` body, session cookie, DOM) are all closed. The only session writes are
`oidc_state`, `identity_id`, and the filtered `claims` (verified by grep).
**Residual (minor):** the token/userinfo *error* paths still echo upstream bodies
(`app.py:167`, `app.py:172`), reached only on a non-200 from the IdP; today's mock
returns no FIN there, but a real provider's error body should be treated as
untrusted before being surfaced. Not a C1 regression.

#### H1 — Unauthenticated `dev_reset` — **RESOLVED**
Two independent layers now stand between an attacker and `store.reset()`. First, the
whole dev surface is registered only inside `if DEV_MODE:` (`app.py:324`), so in a
non-dev deploy the route does not exist (404) — confirmed by test 13 hitting all
three dev routes plus `/authorize` and getting 404. Second, even within a dev
instance `dev_reset` calls `current(request)` before any side effect
(`app.py:344`), so an anonymous or cross-origin POST gets 401 — confirmed by test 12
(401, not 500/200). `store.force_due` and the reset path have no callers outside the
gated block (verified by grep). Resolved **given APP_ENV is set to a non-dev value
in production** — see N1.

#### H2 — Fast-forward cooling bypass — **RESOLVED**
`dev_fast_forward` is defined inside the `if DEV_MODE:` block (`app.py:326-338`) and
is the only caller of `store.force_due` (`app.py:335`, grep-confirmed). When
APP_ENV != dev the route is not registered at all, so the instant-swap primitive
cannot exist in production — test 13 confirms it 404s. `force_due` still lives in
`store.py`, but it is unreachable without the dev route. Resolved given N1.

#### H3 — Secret / pepper regeneration — **RESOLVED**
`SESSION_SECRET` and `FIN_PEPPER` are read from env (`app.py:59-60`). When
`not DEV_MODE`, the app hard-refuses to start if either is missing or empty —
`RuntimeError("refusing to start ...")` (`app.py:62-70`); `if not val` correctly
rejects `""` as well as unset. The random fallbacks (`app.py:80-81`) are assigned
only *after* that guard, so they can never apply in production. The pepper-rotation
hazard is documented in-code (`app.py:75-79`): rotating re-hashes every FIN and
orphans identity rows, so it must be treated as permanent / migration-only. Test 14
confirms a non-dev start with no secrets exits non-zero with the refusal message.
**Residual (by design):** in dev mode both remain ephemeral per run, so a dev
restart still re-buckets identities — acceptable for the throwaway demo DB.

### New criticals / highs

#### N1 — `APP_ENV` default left prod open — **RESOLVED** (follow-up fix, re-verified 2026-07-24)
**Location:** `app.py:52` (`APP_ENV = os.getenv("APP_ENV", "production")`)
The default was inverted from `"dev"` to `"production"` (`app.py:52`), so a deploy
that never sets the variable now fails closed. `DEV_MODE = APP_ENV == "dev"`
(`app.py:53`) is true only on the exact string `"dev"`; every other value — unset
(now → `"production"`), a typo, `"prod"`, or `""` — is production. I re-verified the
four states adversarially by importing the module directly:
- **APP_ENV unset, no secrets** → `RuntimeError: refusing to start` (guard at
  `app.py:64-72` fires). Fails closed.
- **APP_ENV=prod, no secrets** → same refusal. Any non-dev value is production.
- **APP_ENV unset, secrets set** → starts in production: `DEV_MODE=False`,
  `/api/dev/*` routes absent, mock `/authorize` absent. Dev surface stays closed.
- **APP_ENV=dev, no secrets** → starts, `DEV_MODE=True`, dev routes mounted — the
  demo still works with zero setup via the documented opt-in.
The forgotten-env-var path that previously re-opened H1/H2/H3 and the mock-IdP login
now hard-stops the process instead. Run docs were updated to match:
`README.md:13,16-18,114` and `CLAUDE.md:75-76` now require `APP_ENV=dev python
app.py` locally and state that the default production posture registers none of the
dev surface and refuses to start without `SESSION_SECRET`/`FIN_PEPPER`. Full suite
re-run with `APP_ENV=dev python app.py`: **all 14 checks pass** (tests 13/14 still
exercise the production-gating and refuse-to-start paths).

No new criticals or highs were introduced by the changed lines. The only behavioural
change is the default value; the guard, the `DEV_MODE` gate on the routes/mock
router, and the secret fallbacks are unchanged and all downstream of it. The new
default fails *closed* in every direction tested — there is no state where an unset
or malformed `APP_ENV` yields an open dev surface. The demo/test path is preserved
because `APP_ENV=dev` is now the documented, explicit local invocation.

No other new criticals or highs were found. The whitelist has no bypass; signature
verification, nonce binding, message integrity, and the active-tier sybil index
remain sound (unchanged from the prior "Verified safe" list).

### Deferred medium/low status (re-checked)

- **M1 (IntegrityError → 500):** still present and accurately characterized. The
  `INSERT` in `store.create_binding` (`store.py:243-251`) is still unwrapped;
  `wallet_bind` (`app.py:260`) has no `IntegrityError` handler. Unchanged.
- **M2 (cross-identity pending wedge):** still present. `ux_pending_identity_chain`
  is still `(identity_id, chain)`-scoped (`store.py:57-59`); `address_claimed_by_other`
  and `promote_due` unchanged. The lazy `promote_due` on every `/api/me` and
  `/api/registry` read (`app.py:273`, `app.py:282`) still amplifies it. Unchanged.
- **M3 (no production guard on dev surface):** **status changed → RESOLVED** as a
  side effect of the H1/H2/H3 fixes. The `DEV_MODE` flag now gates both the
  `/api/dev/*` routes (`app.py:324`) and the mock IdP router
  (`app.py:92-93`). This was the exact "guarded by a flag" done-criterion M3 called
  for. (Its lingering risk is now folded into N1: the flag exists but defaults to
  the open state.)
- **L1 (nonce table never pruned):** still present. `issue_nonce`/`consume_nonce`
  unchanged; no delete path except `reset()`. Unchanged.
- **L2 (Solana address case-folding):** still present. `store.py:180` and
  `store.py:213` still `LOWER()` the address. Latent correctness bug, not a live
  break. Unchanged.
- **L3 (OIDC nonce generated but never validated):** still present. `login` mints
  `nonce` and puts it in the authorize URL (`app.py:140-144`); `callback` never
  checks it and it is no longer even stored in the session. Dead scaffolding.
  Unchanged.
- **L4 (lazy `promote_due`):** still present and unchanged; see M2 for how the same
  lazy read becomes a 500 amplifier.

### Verdict

**Yes, safe to build on with respect to the four fixed issues, and N1 is now also
RESOLVED.** C1, H1, H2, and H3 are all genuinely fixed (whitelist stops the FIN leak;
the dev surface is double-gated and reset requires auth; secrets fail-start in
production; pepper rotation documented), M3 resolved as a bonus, and the follow-up
inverted `APP_ENV`'s default to `"production"` (`app.py:52`) so the whole dev surface
now fails closed on a forgotten env var — re-verified across four states, all
fail-closed, docs updated, and all 14 tests pass under the new `APP_ENV=dev` local
invocation. **No remaining or new criticals or highs.** The cryptographic core and
the deferred mediums/lows are unchanged (M1, M2, L1–L4 still open as previously
characterized and appropriately deferred).

---

## Audit — 2026-07-24

Scope: `app.py`, `store.py`, `verify.py`, `mock_esignet.py`, `static/index.html`,
`t.py`. Method: attack each CLAUDE.md non-negotiable directly, then walk the R3
"known suspects" list to confirm or clear each.

**Counts:** 1 critical · 3 high · 3 medium · 4 low.

Ranked by exploitability. The FIN leak is trivial (log in, read one response). The
dev-endpoint issues are trivial too but partly gated by "these must not ship to
prod" — except nothing enforces that, so they are live today.

---

### Critical

#### C1 — Raw FIN is sent to the browser in the `/api/me` response body, the session cookie, and the rendered DOM
**Location:** `app.py:131`, `app.py:239`; `mock_esignet.py:218-219`; `static/index.html:194`
**Confidence:** certain
**Invariant broken:** Non-negotiable #1 — *"The raw FIN is never persisted, logged,
or sent to the browser. Only `HMAC-SHA256(pepper, FIN)`. A FIN is 12 digits — 10¹²
values is exhaustively enumerable in minutes, so a bare hash is functionally
plaintext."*

**The attack (three independent paths, all live):**
1. `callback` stores the entire userinfo response in the session: `request.session["claims"] = claims` (`app.py:131`). That dict contains `"fayda_fin": "301884729166"` and `"sub": "301884729166"` — the raw 12-digit FIN (`mock_esignet.py:218-219`).
2. `/api/me` returns that dict verbatim to the client: `"claims": request.session.get("claims", {})` (`app.py:239`). So any authenticated user can `GET /api/me` and read their own raw FIN in the JSON body. No decoding, no cookie inspection — it is plaintext in an HTTP response.
3. The UI then paints it into the DOM: `document.getElementById('claimsBox').textContent = JSON.stringify(ME.claims,null,2)` (`static/index.html:194`). The raw FIN is visible in the page under the "Claims returned by userinfo" disclosure.
4. Additionally, Starlette's `SessionMiddleware` **signs but does not encrypt** the session cookie (`app.py:55`). The cookie value is base64-encoded JSON that anyone holding the cookie can decode client-side — and it contains `claims` including `fayda_fin`. Confirmed as the R3 suspect predicted, but the response-body leak (path 2) is the more direct violation.

Repro: authenticate as any persona, then
`curl --cookie <session> http://127.0.0.1:8000/api/me | python -c "import sys,json;print(json.load(sys.stdin)['claims']['fayda_fin'])"`
prints `301884729166`.

**Why the test misses it:** `t.py:26` asserts `"301884729166" not in str(me["identity"])`
— it only inspects the `identity` object, which is clean (it carries `fin_hmac`
only, `app.py:236`). The FIN rides along in the sibling `claims` object, which the
test never checks. The test passes while the FIN leaks. A test that cannot fail on
the thing it names is not a test.

**Fix direction (not applied):** never put `claims` in the session or any response.
If the UI must show non-sensitive claims, whitelist them (`name`, `birthdate`,
`region`) and strip `fayda_fin`/`sub`/`phone_number` at the `callback` boundary,
before anything is stored. Extend `t.py` to assert the raw FIN appears in **no**
part of `/api/me`, not just `identity`.

---

### High

#### H1 — `/api/dev/reset` has no authentication; anyone can wipe the entire registry
**Location:** `app.py:271-275`
**Confidence:** certain
**Invariant broken:** Non-negotiable #5 (dev endpoints must not exist in
production) — and there is no guard making that true.

**The attack:** `dev_reset` calls `store.reset()` (drops and recreates the DB) with
**no** `current(request)` check — contrast every other mutating route, which starts
with `iid = current(request)`. Unauthenticated:
`curl -X POST http://127.0.0.1:8000/api/dev/reset` deletes `registry.db`, every
identity, and every binding. On any shared demo instance, any visitor wipes it. It
is also reachable cross-origin: a malicious page issuing a "simple" `fetch(...,
{method:'POST'})` triggers the side effect even though it cannot read the response,
and it needs no cookie because there is no auth to satisfy.

#### H2 — `/api/dev/fast-forward` lets any live session collapse the cooling period, defeating the exact protection cooling exists for
**Location:** `app.py:261-268`, `store.force_due` (`store.py:296-306`)
**Confidence:** certain
**Invariant broken:** CLAUDE.md "Things we know" — *"Cooling period exists for
session compromise, not user convenience. If an attacker with a live session swaps
the wallet, the real user needs a window to cancel... Do not 'simplify' this into an
instant swap."*

**The attack:** the threat model is an attacker holding a live session. That same
attacker can (a) bind a replacement wallet → goes pending, then (b) call
`POST /api/dev/fast-forward {"chain":"evm"}`, which backdates `activates_at` to one
second ago and immediately `promote_due`s it. The 72-hour window the real user was
supposed to use to cancel is reduced to zero. `fast-forward` is exactly the "instant
swap" the design forbids, exposed to any authenticated session. It requires
`current(request)` but that is precisely the credential the attacker already has.

#### H3 — Session secret (always) and FIN pepper (by default) regenerate on restart, orphaning identities and locking users out of their own wallets
**Location:** `app.py:55` (session), `app.py:47` (pepper), `store.upsert_identity`
(`store.py:112-140`), `store.address_claimed_by_other` (`store.py:208-217`)
**Confidence:** certain (pepper path requires `FIN_PEPPER` unset; session path is
unconditional)

**The attack / failure:**
- `secret_key=secrets.token_hex(32)` is generated fresh every process start and is
  **never read from the environment** — there is no env var that pins it. Every
  restart invalidates all session cookies (users silently logged out) and makes
  multi-worker / multi-instance deployment impossible (each worker signs with a
  different key).
- `FIN_PEPPER = os.getenv("FIN_PEPPER", secrets.token_bytes(32).hex())` — if the env
  var is unset (the default, and the demo never sets it), the pepper is random per
  run. After a restart, `hash_fin(FIN)` produces a **different** HMAC for the same
  person. `upsert_identity` looks the person up by `fin_hmac` (`store.py:115-117`),
  fails to find the old row, and inserts a **new** identity. The person's real
  wallet bindings are stranded under the old, now-unreachable identity id.
- The kicker: the stranded binding still enforces the sybil index. When the person
  re-authenticates (new identity) and tries to re-bind their **own** wallet,
  `address_claimed_by_other` (`store.py:208`) reports the address as claimed by
  "another" identity (the orphan) → permanent 409. The user is locked out of their
  own address with no recovery path in the app. Self-inflicted sybil lockout plus
  silent data fragmentation.

---

### Medium

#### M1 — `IntegrityError` from the unique indexes is unhandled; a concurrent same-address bind 500s instead of 409
**Location:** `app.py:206`, `store.create_binding` (`store.py:220-252`)
**Confidence:** likely (race-dependent; the code path is certain)

**The attack:** two identities (or two tabs) race a first-time bind of the same
address. Both pass the check-then-insert `address_claimed_by_other` gate
(`app.py:170`, `app.py:193`) before either commits — a classic TOCTOU window. Both
reach `store.create_binding`'s `INSERT` with `status='active'`. The
`ux_active_chain_address` partial unique index (`store.py:54-55`) correctly rejects
the second row — **the sybil invariant itself holds at the DB layer** — but the
resulting `sqlite3.IntegrityError` is not caught anywhere, so FastAPI returns a raw
500 with a stack trace instead of the intended 409. Data integrity is preserved;
error handling and the client contract are not. Wrap the `INSERT` and translate
`IntegrityError` → `HTTPException(409, ...)`.

#### M2 — Cross-identity pending races can create two pending bindings to one address, then wedge the registry with a permanent 500 on promotion
**Location:** `store.py:57-59` (pending index is per-identity only),
`store.create_binding` (`store.py:220-252`), `store.promote_due` (`store.py:268-293`)
**Confidence:** worth checking (tight race + attacker must control one key and drive
two identities), but the consequence is severe and persistent

**The attack:** `ux_pending_identity_chain` is scoped `(identity_id, chain)`, so it
does **not** prevent two *different* identities from each holding a pending binding
to the *same* address — nothing at the DB layer covers cross-identity pending
same-address. The only thing stopping it is the application check
`address_claimed_by_other` (which does cover `pending`), and that check has the same
TOCTOU window as M1. An attacker who controls one wallet key and can drive two
identities (trivial against the mock persona picker; in production, two enrolled
Fayda identities) issues nonces for both, signs both server-issued messages (each
message differs only by display name + nonce, both signable with the one key), and
races both `bind` calls through the window → two pending rows for address X under
two identities. When each cooling period elapses, `promote_due` tries to set both to
`active` for `(chain, X)`; the second hits `ux_active_chain_address` →
`IntegrityError` raised **inside** `promote_due`, which is called on every
`/api/registry` and `/api/me` read (`app.py:219`, `app.py:228`). The transaction
rolls back but the two conflicting pending rows persist, so every subsequent read
re-raises → the registry returns 500 indefinitely for everyone. Denial of service
plus a demonstrated crack in the sybil constraint at the pending tier.

#### M3 — Entire `/api/dev/*` surface and the mock IdP ship with no production guard
**Location:** `app.py:56` (`app.include_router(mock_esignet.router)`),
`app.py:261/271/282` (dev routes), `store.reset`/`force_due`
**Confidence:** certain
**Invariant broken:** Non-negotiable #5 — *"No private key ever reaches the server
except in `/api/dev/*`, which must not exist in production."* The project's own R3
done-criterion also requires dev code be *"guarded by a flag."* There is **no flag.**

**The finding:** `grep -rn "api/dev"` shows three routes; none is wrapped in any
`if DEV_MODE`/env check, and `mock_esignet.router` is mounted unconditionally.
`/api/dev/test-wallet` (`app.py:282-319`) generates the private key server-side and
signs on the server — a direct #5 violation, acceptable only because it "must not
exist in production," which nothing enforces. If this image is deployed as-is, H1
(open DB wipe), H2 (instant cooling bypass), server-side key custody, and the mock
persona login all go live simultaneously. Gate all of it behind a single explicit
flag that defaults to off.

---

### Low

#### L1 — `auth_nonces` is never pruned; the table grows without bound
**Location:** `store.issue_nonce` (`store.py:153-161`), `store.consume_nonce`
(`store.py:164-183`)
**Confidence:** certain
Rows are only ever inserted or flipped `consumed=1`; nothing deletes expired or
consumed nonces except `store.reset()`. Every `/api/wallet/nonce` and
`/api/dev/test-wallet` call (both authenticated, but freely repeatable) adds a
permanent row. Slow unbounded storage growth / eventual DoS. Add a periodic
`DELETE FROM auth_nonces WHERE expires_at < now OR consumed = 1`.

#### L2 — Solana addresses are compared case-insensitively, which is wrong for base58
**Location:** `store.consume_nonce` (`store.py:180`),
`store.address_claimed_by_other` (`store.py:213`)
**Confidence:** likely (correctness), certain (not practically exploitable)
Both comparisons lowercase the address. base58 is case-sensitive; `Abc` and `abc`
are different public keys but compare equal here, and the binding is then stored and
verified against whatever case the client sent (`req.address`, `app.py:207`),
possibly not the address the nonce was issued for. Exploiting it would require
finding a second ed25519 keypair whose base58 pubkey case-insensitively matches a
target — a partial preimage that is infeasible — so this is a latent correctness bug,
not a live break. Compare Solana addresses exactly; only EVM addresses are
case-insensitive (hex).

#### L3 — OIDC `nonce` is generated but never validated
**Location:** `app.py:88` (generated, sent to `/authorize`), `app.py:97-132`
(`callback` never checks it)
**Confidence:** certain
The `nonce` minted at `/login` is passed to the authorize URL and then ignored;
`callback` uses the userinfo endpoint rather than an ID token, so there is no
`id_token` nonce claim to bind. Harmless today, but it is dead security scaffolding
that reads as protection and is not. When a real ID token is introduced, this nonce
must actually be stored and checked.

#### L4 — `promote_due` runs only lazily on read
**Location:** `store.promote_due` (`store.py:268-293`), called from `app.py:219`,
`app.py:228`
**Confidence:** certain
Acknowledged in-code ("In production this is a scheduled job"). A pending binding
whose cooling elapsed does not activate until someone reads `/api/registry` or
`/api/me`. Liveness/UX issue, not a security hole on its own — but see M2 for how the
same lazy call becomes a 500 amplifier. A user cannot exploit it to hold an
indefinite pending state that blocks their own future binds beyond the normal
cooling period; the pending index already limits them to one in flight, and reading
their own page promotes it.

---

### R3 suspects — confirm/clear

Walking the PROGRESS.md R3 "Known suspects" list by name:

1. **Raw FIN readable in the session cookie** — **CONFIRMED (critical, C1).** True as
   stated (signed-not-encrypted cookie carries `claims.fayda_fin`), and worse than
   stated: the raw FIN is also returned in the `/api/me` JSON body (`app.py:239`) and
   rendered into the DOM (`static/index.html:194`). Non-negotiable #1 broken three
   ways. The existing test (`t.py:26`) does not catch it because it inspects only
   `me["identity"]`, not `me["claims"]`.

2. **`dev_reset` does not check the session — anyone may wipe the DB** — **CONFIRMED
   (high, H1).** No `current(request)` call; unauthenticated `POST /api/dev/reset`
   drops the database. Also cross-origin-triggerable as a side effect.

3. **`promote_due` runs lazily on read; nothing promotes if nobody reads** —
   **CONFIRMED (low, L4).** Accurate. Liveness issue, acknowledged in code as
   needing a scheduled job. Note it also amplifies M2 into a persistent 500.

4. **`auth_nonces` is never pruned** — **CONFIRMED (low, L1).** No delete path except
   full reset; unbounded growth.

5. **`IntegrityError` from unique indexes likely unhandled — race may 500 not 409** —
   **CONFIRMED (medium, M1).** The index correctly protects the sybil invariant, but
   the uncaught `IntegrityError` surfaces as a 500. Bonus finding M2 shows the
   pending tier is not covered by any index at all across identities, enabling a
   promotion-time wedge.

6. **Session secret and FIN pepper regenerate on restart, orphaning identity rows** —
   **CONFIRMED (high, H3).** Session secret is unconditionally random (never env-
   pinned); pepper is random whenever `FIN_PEPPER` is unset. A restart re-buckets the
   same person into a new identity and — via the still-live sybil index — locks them
   out of re-binding their own wallet.

All six suspects confirmed. None cleared.

---

### Verified safe

Things actively attacked that held up. Recorded so the next run does not re-plough
this ground.

- **Signature verification fails closed.** Malformed, truncated, oversized, or
  non-base58 signatures raise inside `verify_evm`/`verify_solana` and are caught,
  returning `False` — there is no error path that treats an exception as success
  (`verify.py:51-74`). No "skip verification on error" branch exists.
- **Server never trusts the client's message.** `wallet_bind` verifies against the
  message returned by `consume_nonce` (server-stored, `app.py:188`, `store.py:183`),
  never against anything in the request body. Non-negotiable #2 holds.
- **Cross-chain signature replay blocked.** `verify` dispatches strictly on the
  `chain` bound into the nonce; the message text embeds `Chain: Ethereum|Solana`
  (`verify.py:33`, `verify.py:77-82`); an EVM signature on a Solana bind fails
  (t.py step 11).
- **Cross-message replay blocked.** Each message embeds a fresh single-use nonce and
  the identity display name (`verify.py:34-48`), so a signature for one bind does not
  validate another.
- **Nonce hygiene.** Single-use (`consumed` flag), TTL-bound (`expires_at`), and
  bound to address + chain (`store.consume_nonce`, `store.py:164-183`). Replay,
  expiry, and cross-address/cross-chain reuse are all rejected. Non-negotiable #4
  holds at the logic level (aside from the L2 case-folding nit and L1 growth).
- **Sybil data integrity holds.** The `ux_active_chain_address` partial unique index
  (`store.py:54-55`) does prevent two *active* identities on one address even if the
  application check is raced — the failure mode is a 500 (M1), not a duplicate row.
  The gap is the pending tier (M2), not the active tier.
- **DB and logs are clean of the raw FIN.** Only `fin_hmac` is stored
  (`store.py:27`, `store.py:112-140`); `registry()` and `get_identity()` never expose
  the raw value; the two error responses that echo upstream text (`app.py:115`,
  `app.py:120`) carry token/error bodies, not userinfo. The leak is exclusively the
  session/response/DOM path in C1.
- **Replayed authorization code cannot mint a second session.** The mock pops the
  code (`mock_esignet.py:192`), so a second token exchange with the same code fails.
- **Client assertion is genuinely verified, not just parsed.** The token endpoint
  runs `jwt.decode` with the registered public key, `RS256`, audience check, and
  `require=[exp,aud,iss,sub]`, plus an `iss==sub==client_id` check
  (`mock_esignet.py:178-190`). (This is mock-side, but it is the contract the real
  client code is written against.)
- **OIDC state/CSRF check present.** `callback` compares `state` to the session copy
  and pops it (`app.py:101-103`); a mismatch or missing session value rejects.

---

### Verdict

**No — not safe to build on yet.** One critical (the raw FIN is handed to the
browser in plaintext via `/api/me`, the cookie, and the DOM, defeating the single
most important non-negotiable) and three highs (open DB wipe, a dev endpoint that
nullifies the cooling-period protection, and pepper/secret regeneration that locks
users out of their own wallets) must be fixed before this is a foundation. The
cryptographic core — signature verification, nonce binding, message integrity, and
the active-tier sybil index — is sound; the failures are in what leaves the server,
what runs unauthenticated, and lifecycle/deployment hygiene.
