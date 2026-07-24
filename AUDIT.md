# AUDIT

Adversarial security audit of the Fayda identity → wallet registry.
Newest run at the top. The auditor reports; it does not fix.

---

## Diff review — 2026-07-24 (repo split: backend/ + React/Vite frontend, origin split BASE/PUBLIC)

Scope: the uncommitted restructure only. Backend logic is UNCHANGED from the five
prior rounds except the five items below; I did not re-derive the binding/crypto/
session core (see the prior sections — still holds). New surface reviewed:
- `backend/app.py` — `PUBLIC_URL` split (`AUTHORIZE_URL`/`REDIRECT_URI` from PUBLIC,
  PUBLIC defaults to BASE), root route now returns JSON `{service, ui}`, `/api/me`
  gains `"dev": DEV_MODE`.
- `backend/mock_esignet.py` — authorize page redesigned (simulated-biometric
  framing). OIDC contract (endpoints, params, RS256 client assertion, code pop)
  unchanged.
- `backend/t.py` — `cwd=HERE` on the two subprocess spawns (import-path fix).
- `frontend/` — new React+Vite SPA: `vite.config.js` proxy, `src/api.js`,
  `src/wallet.js` (Privy), `src/App.jsx`, `src/components.jsx`. Also a committed
  `frontend/dist/` prebuilt bundle.

Method: read every changed backend hunk and every hand-written frontend source
file, traced the OIDC dance through the proxy, grepped the frontend for any
off-origin sink, then ran the suite. Killed :8000, started `APP_ENV=dev python
backend/app.py` WITHOUT `PUBLIC_URL`, ran `python backend/t.py` against a fresh
server: **ALL 18 CHECKS PASSED** (3b/3c FIN-and-claims asserts included). Server
log grep for every persona FIN / `fayda_fin` / `sub` / `picture` / `phone`:
nothing.

### The origin-split / CSRF answer (requested explicitly)

**Routing the OIDC dance through the Vite proxy introduces no new session or CSRF
weakness.** Walked it end to end:

- The browser stays on one origin (`http://localhost:5173`). `/login`, `/authorize`,
  `/callback`, `/logout`, `/api/*`, `/v1` are all proxied to `127.0.0.1:8000`
  server-to-server; the browser never issues a request to the backend origin, so
  the `Set-Cookie` from the proxied `/callback` lands on `localhost:5173` and every
  later `/api/*` call carries it. `RedirectResponse("/")` after callback is
  relative → resolves on the SPA origin, never the backend.
- The OIDC `state` check is untouched (`callback` compares to `session["oidc_state"]`
  and rejects on mismatch). The session id is an opaque 256-bit token + HMAC,
  `HttpOnly`, `SameSite=Lax`, server-side store — a forged/truncated sid is rejected
  by `hmac.compare_digest` before any DB hit. `SameSite=Lax` still permits the
  top-level-navigation GET `/callback` to carry the cookie, which is required and
  safe because `state` binds the callback to the initiating session.
- **No cross-origin leak between `localhost:5173` and `127.0.0.1:8000`.** They are
  distinct cookie origins; a cookie set on one is never sent to the other. Someone
  hitting `127.0.0.1:8000` directly runs an independent flow whose cookie cannot
  reach the SPA origin, and vice versa. Nothing the proxy does bridges them.
- The proxy makes no new cross-origin *request* pattern possible: every proxied
  path was already served by the backend; the proxy only relabels the origin the
  browser sees. `/v1` (mock token/userinfo) is now reachable through the proxy but
  is dev-only (mock router mounted only under `DEV_MODE`) and still requires the
  RS256 client assertion / bearer token.
- Vite binds to localhost by default (no `--host`), `strictPort:true` — the dev
  server is not exposed on the network.

The one real behavioural footgun and the one raised-exploitability item are below;
neither is a critical or high.

### Low — `PUBLIC_URL` defaulting to `BASE` strands the session cookie in a mixed-origin dev run
`backend/app.py:44-49`. `PUBLIC` defaults to `BASE` (`127.0.0.1:8000`) when
`PUBLIC_URL` is unset, so `AUTHORIZE_URL`/`REDIRECT_URI` point at the backend
origin. If a developer runs the SPA on `localhost:5173` but forgets to set
`PUBLIC_URL=http://localhost:5173`, `/login` (proxied) returns an absolute redirect
to `http://127.0.0.1:8000/authorize`; the browser leaves the SPA origin, the whole
dance completes on `127.0.0.1:8000`, and the session cookie is set there — stranded
off the SPA origin, which stays unauthenticated. This is a **fail-safe** footgun
(the outcome is "not logged in", never "logged in as someone else" or a leak), and
it is exactly what the in-code comment warns about; the default is deliberately
chosen to keep the single-origin `t.py` path working. Not a security break, but the
two-process dev run silently half-works unless `PUBLIC_URL` is set. Confidence:
certain. Worth a startup log line or a README call-out; no code-security change.

### Low — mock `/authorize` reflected XSS now shares the SPA origin (dev-only, exploitability raised)
`backend/mock_esignet.py:130-160`. The redesigned authorize page still interpolates
`state`, `nonce`, `redirect_uri` into hidden-input `value="..."` attributes and
`scope` into page text with **no escaping** (unchanged from the prior-round Low). A
crafted `GET /authorize?...&redirect_uri="><script>...` breaks out of the attribute
and executes. Pre-existing — but the proxy changes the blast radius: the mock page
is now served *through* `localhost:5173`, so the injected script runs **same-origin
with the real SPA** and can drive authenticated `/api/*` calls off the HttpOnly
session cookie, rather than executing on an isolated backend origin. Still bounded
to **dev** — the entire `mock_esignet.router` is mounted only under `DEV_MODE`
(test 13 confirms `/authorize` 404s in production), so it cannot ship. The paired
open-redirect (authorize_confirm 302s to the client-supplied `redirect_uri`) is
likewise dev-only. Flagging so the reflected values get escaped before this framing
is ever copied toward a real login page, and so the proxy-raises-severity note is on
record. Confidence: certain (dev-only).

### Low/info — `/api/me` now advertises `dev: DEV_MODE` to any caller, authenticated or not
`backend/app.py:389-395`. Both branches return `"dev": DEV_MODE`. It exists to let
the SPA gate the dev buttons (`me.dev` in `App.jsx`/`components.jsx`), and it is the
correct second gate — the routes themselves 404 in production regardless. The only
residual is that an unauthenticated `GET /api/me` now reports whether an instance is
in dev mode. In production it is `false`, and the dev surface is already probeable by
hitting a dev route, so this discloses nothing new of value. Not a bug. Confidence:
certain.

### Frontend — no off-origin exfiltration path (verified)
- Grepped all hand-written `src/`: the only network sink is `fetch(path, …)` in
  `api.js` with **relative paths only** (comment enforces it), and the only env read
  is `VITE_PRIVY_APP_ID`. No absolute URLs, no second `fetch`/`axios`/
  `XMLHttpRequest`/`sendBeacon`/`ws://`. The signed message, claims, and any test
  signature travel only to same-origin `/api/*`.
- `wallet.js` Privy config is genuinely wallet-only / no-embedded as claimed:
  `loginMethods:['wallet']`, `embeddedWallets.ethereum.createOnLogin:'off'` and
  `.solana.createOnLogin:'off'`. `signFor` does `personal_sign` (EVM, hex message)
  and wallet-standard `signMessage` + local base58 (Solana) against a *connected
  external* wallet; no private key is ever in the app's hands. All `@privy-io`
  imports are isolated to this one file as the comment claims.
- The dev test-key path (`api('/api/dev/test-wallet')`) is UI-gated by `me.dev` and
  server-gated by `DEV_MODE`; it is the pre-existing server-side-key dev surface
  (#5), not a new frontend weakening — the key is generated and signed on the
  backend, never touched by frontend code.
- Note (hygiene, not security): `frontend/dist/` is a committed prebuilt bundle
  (hundreds of third-party JS chunks). Not a runtime vuln, but it is untracked build
  output that should not be in the repo — review/regenerate rather than trust it.

### Verified safe (this diff)
- **OIDC state/CSRF check intact under the proxy** — unchanged, and the same-origin
  proxy keeps the cookie on the SPA origin end to end.
- **Cookie stays opaque + server-side** — sid+HMAC only, `HttpOnly`, `SameSite=Lax`;
  test 3b decodes every segment and finds no FIN, `identity_id`, or `claims`. The
  origin split touched only URL construction, not the middleware.
- **Confirmed userinfo schema drops the FIN and the new PII** — `SAFE_CLAIMS` now
  `{name, birthdate, gender, address, residenceStatus}`; `sub` (the FIN), `phone`,
  and `picture` (face image) are stripped at the callback boundary. Tests 3b/3c
  assert absence by name *and* by value (`+2519…`, `base64,/9j/…`); server log
  carries no FIN. Non-negotiable #1 holds.
- **Empty `sub` → 502** (`callback` raises "userinfo returned no sub") — a blank
  identifier cannot collide identities.
- **Dev surface still fully gated** — `/api/dev/*` and the mock IdP 404 when
  `APP_ENV != dev` (test 13); production refuses to start without secrets (test 14).
  The new `me.dev` flag is a UI convenience layered on top, not the gate.
- **Binding / crypto / nonce / sybil core unchanged** — M1/M2 resolutions, the
  global DB lock, and signature verification are byte-identical to the prior round;
  tests 4–12 and 15–18 pass.
- **`t.py cwd` fix is inert** — it only sets the subprocess working directory so
  `app:app` imports resolve from `backend/`; no behavioural change, suite green.

### Verdict
Safe to build on — **yes**. The restructure is overwhelmingly a move plus a new
same-origin SPA; the origin split is fail-safe (a misconfig strands the cookie into
an unauthenticated state, never a bypass or a leak), the CSRF/state posture is
unchanged and sound through the proxy, and the frontend has no off-origin sink and
no embedded-wallet/private-key custody. No new critical or high. Three lows: the
`PUBLIC_URL` default footgun (fail-safe), the dev-only mock XSS whose blast radius
the proxy raises to the SPA origin (still unshippable), and the informational
`me.dev` flag. Pre-existing mediums (unbounded `sessions`/`auth_nonces` tables,
write-on-read under the global lock, non-atomic logout, the M4 migration hazard)
remain open and untouched by this diff.

New criticals: 0, new highs: 0.

---

## Diff review — 2026-07-24 (real userinfo schema, SAFE_CLAIMS whitelist, server-side sessions)

Scope: the new uncommitted changes only — `mock_esignet.py` (confirmed Fayda
claim shape, `sub`-only identifier, FOREIGN_NATIONAL persona), `app.py`
(`ServerSideSessionMiddleware`, `SAFE_CLAIMS`, `hash_fin(sub)`), `store.py`
(`sessions` table + `load/save/delete_session`), `static/index.html`
(residenceStatus surfaced), `t.py` (3b/3c fixation + whitelist asserts). The M1/M2
binding work below was audited in the prior run and is out of scope here.

Method: read all changed files, derived each attack against CLAUDE.md's
non-negotiables, then corroborated live against a freshly restarted dev server.
**All 18 checks pass.** Findings below are independent of that pass — the run
confirms the wins; the mediums are behaviours the suite does not exercise. Every
medium was reproduced empirically (row counts, expires_at deltas, a threaded
logout race, an /api/me body dump), not reasoned about in the abstract.

### Medium — sessions table grows without bound from unauthenticated `/login`
`app.py:227-236` — `/login` writes `oidc_state` into the session, so the
middleware (`app.py:152-160`) mints a sid and persists a `sessions` row on every
hit, authenticated or not. Those rows are only ever expired *lazily, on load of
that exact sid* (`store.load_session`, `store.py:186-194`) — and a random
attacker sid is never loaded again, so it is never swept. There is no background
reaper and no rate limit. Reproduced: 50 fresh unauthenticated `GET /login`
calls added exactly 50 orphan rows (`{"oidc_state": ...}`, 12h TTL) that nothing
will ever reclaim. A script can add rows as fast as it can request, growing the
DB and — because every write serialises on the process-global `_DB_LOCK`
(`store.py:113`) — contending with legitimate traffic. Invariant strained: the
DoS posture in CLAUDE.md ("unbounded tables, expensive unauthenticated ops").
Confidence: certain (measured).

### Medium — every authenticated request rewrites its session row and re-sets the cookie
`app.py:152-160` — the middleware persists whenever the in-memory session is
non-empty, unconditionally, on `http.response.start`. So a plain `GET /api/me`
or `GET /api/registry` from a logged-in user issues a `Set-Cookie` *and* an
`INSERT … ON CONFLICT DO UPDATE` that slides `expires_at` forward. Reproduced:
two `/api/me` reads 1.1s apart produced two different `expires_at` values and a
`Set-Cookie` on the read. Because every DB op — including this write-on-read —
takes the global `_DB_LOCK`, an authenticated client polling `/api/me` turns
each read into a serialized write. Combined with the finding above, the new
session store converts the read path into a lock-bound write path. Not a
correctness break, but a real throughput/starvation surface the old signed-cookie
design did not have. Confidence: certain (measured).

### Medium — logout is not atomic: a concurrent in-flight request resurrects the session
`app.py:285-288` (`logout` → `session.clear()`) and `app.py:141-167`
(save-whole-snapshot on response). The middleware loads the session at request
start and re-saves that snapshot at response start. So if any other request for
the same sid is in flight when `/logout` runs, that request's response re-INSERTs
the row (`store.save_session` is upsert, `store.py:197-206`) *and* re-sets the
cookie — after logout deleted the row and sent `Max-Age=0`. Reproduced: with one
cookie jar, firing `/api/me` reads concurrently with `/logout`, logout returned
200 but the `sessions` row survived and the cookie still authenticated
(`/api/me` → `authenticated: true`). The realistic trigger is two tabs (one
loading, one signing out) — the UI keeps the page open and `load()` fires on
every action. Sign-out is a security operation (the user's means of ending a
possibly-compromised session); it must not be defeatable by the user's own
overlapping request. Note this is self-defeating concurrency, not attacker-driven
against a victim — an attacker cannot cause a victim's row to resurrect.
Confidence: certain (measured).

### Low — `/api/me` returns neighbourhood-level address (kebele/woreda) in the body
`app.py:395` echoes `session["claims"]`, which includes the whitelisted `address`
`{kebele, region, woreda, zone}` (confirmed in a live `/api/me`), and
`static/index.html:197` renders the full claims blob into the DOM. This is the
authenticated owner's *own* data over their *own* session, and the store.py
rationale (`store.py:80-83`) is explicitly about the **cookie** — "must never sit
in a signed-but-unencrypted cookie … the browser gets only the opaque sid" —
which is honoured. So this is consistent with design intent, not a leak. The only
residual: `/api/me` carries no `Cache-Control: no-store`, so neighbourhood-level
PII is cacheable by the browser/intermediaries. Worth a header; not a bug.
Confidence: worth checking.

### Low — `store.reset()` unlinks the DB file outside the global lock (dev only)
`store.py:133-140` unlinks `registry.db`/`-wal`/`-shm` *before* re-`init()`, and
the unlink is not under `_DB_LOCK`. A concurrent request holding the lock has an
open fd to the now-unlinked inode and could write to a ghost file. Only reachable
via `/api/dev/reset`, which is not registered in production, so blast radius is a
shared dev instance. Confidence: likely.

### Low — mock `/authorize` reflects `state`/`scope`/`redirect_uri` unescaped
`mock_esignet.py:131-175` interpolates request params straight into the HTML
(`state`/`nonce`/`redirect_uri` into attribute values, `scope` into text) with no
escaping — reflected XSS in the mock IdP page. Dev-only surface: the whole
`mock_esignet.router` is mounted only when `APP_ENV == "dev"` (`app.py:177-178`),
verified 404 in production by test 13. Flagging so it is not copied into any
real login page. Confidence: certain (dev-only).

### Low/info — a non-string `sub` from a real provider would 500
`app.py:266-268` accepts any truthy `sub`; `hash_fin` (`app.py:185`) calls
`fin.encode()`. The mock always sends a string, but a real userinfo returning a
numeric/JSON `sub` would raise inside `hash_fin` → 500 rather than a clean 502.
Robustness only. Confidence: worth checking.

### Verified safe (actively attacked, held)
- **Cookie is opaque and unforgeable.** `session=<sid>.<hmac>`; `_sid_from_cookie`
  (`app.py:117-128`) rejects a missing dot, verifies the HMAC with
  `hmac.compare_digest` (constant-time), and returns None on any mismatch. A
  forged or truncated sid never reaches the DB. Without `SESSION_SECRET` an
  attacker cannot mint a valid cookie.
- **No session data leaks client-side.** The cookie holds only sid+HMAC; test 3b
  base64-decodes every segment and confirms neither the raw FIN, `identity_id`,
  nor `claims` bytes are present. Confirmed the whole session lives in SQLite.
- **Raw FIN / `sub` never persisted, logged, or returned.** Only `fin_hmac`
  (HMAC-pepper) is stored; `sub` is stripped by `SAFE_CLAIMS` before it enters the
  session; `/api/me` and `/api/registry` bodies carry no `sub`/FIN (tests 3/3b).
  Grepped: no logging of claims, sid, or FIN anywhere.
- **Session fixation.** The pre-login sid is deleted and a fresh sid minted at the
  privilege change (`__rotate__`, `app.py:149-160`); `__rotate__` is popped before
  persist so it never lands in a row; rotation is committed together with the login
  redirect, so a fixated pre-auth sid cannot ride in. Test 3b asserts the cookie
  changes across login (non-vacuous: pre-login cookie is real).
- **Expired/replayed sid.** `load_session` deletes the row and returns None on
  expiry; the middleware then treats the request as anonymous and mints a new sid
  on any write — a replayed expired cookie cannot resurrect the old session.
- **`phone`/`picture` stripped.** Whitelist excludes both; test 3c confirms
  absence by claim name *and* by value (`+2519…`, `base64,/9j/…`).
- **Empty/missing `sub`.** `callback` raises 502 (`app.py:267-268`) — a blank sub
  cannot hash to a shared identity. `residenceStatus` survives the whitelist and
  is display-only (`index.html` renders verbatim, never branches on it).
- **Dev surface + secrets guard.** `/api/dev/*` and the mock IdP 404 when
  `APP_ENV != "dev"`; production refuses to start without `SESSION_SECRET`/
  `FIN_PEPPER` (tests 13/14).
- **Binding lifecycle unchanged.** Sybil, nonce single-use/binding, cooling, and
  the M1/M2 race handling are untouched by this diff and still pass (tests 4-12,
  15-18).

### Verdict
Safe to build on — **yes**. No new critical or high: the session rewrite
introduces no auth bypass, no FIN/`sub`/PII leak, and fixation is closed. The
three mediums are DoS/robustness properties of the new SQLite session store
(unbounded orphan rows, write-on-read under the global lock, non-atomic logout) —
fix before production load, but none breaks a CLAUDE.md correctness invariant.

---

## Diff review — 2026-07-24 (M1 fix, M2 tests, deadlock fix)

Scope: the uncommitted diff only — `store.py`, `app.py`, `t.py`, `PROGRESS.md`.
Three changes: (1) M2's `ux_pending_chain_address` + savepoint promotion (tests
15/16); (2) M1 — `create_binding` translates `sqlite3.IntegrityError` →
`store.BindingConflict`, `wallet_bind` maps it to a 409 (tests 17/18); (3) a
process-level `threading.Lock` serializing `conn()` open/use/close.

Method: read all three files, derived each attack, then ran the suite against a
freshly restarted dev server (pepper is per-process in dev). **All 18 checks pass.**
Findings are independent of that; the run is corroboration. Empirically probed the
SQLite error strings, the multi-index-violation report order, and cancel-then-rebind.

### M1 — IntegrityError → 500 — **RESOLVED**
`store.create_binding` (`store.py:268-292`) wraps the `INSERT` and re-raises every
`sqlite3.IntegrityError` as `BindingConflict` with a fixed, client-safe string;
`wallet_bind` (`app.py:265-270`) catches it and returns `HTTPException(409, str(e))`.
`str(e)` is the `BindingConflict` message (a constant), never the chained cause, so
no raw driver text reaches the body. Verified two ways: (a) at the store level the
cause is `sqlite3.IntegrityError` but `str(BindingConflict)` is one of the two fixed
strings; (b) SQLite's unique-constraint message names only columns
(`UNIQUE constraint failed: wallet_bindings.chain, wallet_bindings.address`) — never
row values, addresses, or the FIN — so even the chained cause carries no PII. Test 17
runs a real two-thread HTTP race 10 rounds and asserts `[200,409]`, never 500; test 18
drives both index flavors at the store level and asserts the cause is
`IntegrityError`. Neither is vacuous: 17 requires exactly one 200 and one 409 (both-200
or both-409 fail the sort), 18 asserts both distinct messages.

### M2 — cross-identity pending wedge — **RESOLVED** (was resolved prior run; this diff adds the tests)
`ux_pending_chain_address` (`store.py:67-68`) closes the pending-vs-pending race at
the DB layer, and `promote_due` (`store.py:330-350`) wraps each promotion in
`SAVEPOINT promote_one`, rolling back and cancelling the conflicting pending row on
`IntegrityError` so it cannot re-detonate. Test 15 plants the un-indexable
active-vs-pending state and confirms reads stay 200, the loser is cancelled, and both
incumbents survive; test 16 confirms the index rejects the duplicate pending with an
`IntegrityError` cause. Confirmed the savepoint cancels only `p["id"]`, the outer
transaction survives, and the loop continues.

**Note — M4 still open, not addressed by this diff.** PROGRESS.md's M4 (the
`CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_chain_address` in `init()` will raise at
import time on a legacy DB that already holds two pending rows on one `(chain,address)`
— the exact population the M2 fix targets) is untouched here. Fresh/throwaway DBs
(all t.py runs) never hit it, so the suite stays green while the hazard remains. Still
medium, still todo.

### Deadlock fix — global connection lock — **sound, no new high/critical**
The non-reentrant `_DB_LOCK` (`store.py:101-113`) is safe: I confirmed no store
function opens a second `conn()` while holding one. `create_binding`, `cancel_pending`,
and `force_due` each call their helper read (`active_binding`/`pending_binding`)
*before* entering their own `with conn()` block (`store.py:252` vs `268`, `297` vs
`300`, `356` vs `359`), so the helper's lock is released before the outer acquire.
`promote_due` and the rest hold a single connection and issue no nested store calls.
No `conn()` body performs network I/O or crypto (signature verification runs outside
any connection in `wallet_bind`), so the lock is never held across a slow operation.
The claim in the comment is accurate.

### Pending-index lockout question — **answer: NO**
`ux_pending_chain_address` cannot lock a legitimate owner out of their own wallet via
someone else's stale or cancelled pending row:
- **Cancelled/archived rows are outside the partial index** (`WHERE status='pending'`).
  A cancelled or archived row has `status` `'cancelled'`/`'archived'`, so it is not in
  the index and blocks nothing. Verified live: cancel a pending bind on address C, then
  re-bind C — succeeds. `address_claimed_by_other` likewise only counts
  `('active','pending')`, so a cancelled row does not block at the app layer either.
- **No resurrection.** Nothing flips a cancelled/archived row back to `pending`;
  `promote_due` only reads `status='pending'`, `cancel_pending` only writes
  `'cancelled'`. A once-cancelled row stays out of the index permanently.
- **A live pending row can only be created by a party who proved control of the
  address's key** (a valid signature over the server-issued message). The "leaked/shared
  key" park is therefore the inherent sybil/key-control tradeoff that already exists at
  the *active* tier — whoever proves control and is Fayda-verified can claim the address.
  The pending index adds no new lockout: it only forbids a *second* pending on an
  address already pending, which is precisely M2.
- **A never-promoting pending row does not park indefinitely.** `/api/registry` is
  unauthenticated and runs `promote_due()` for *all* identities, so anyone can drive a
  due pending row to resolution; it then either promotes (the key-holder takes the
  address, as designed) or is cancelled on an active-tier collision. Either way it only
  ever blocks *that one address*, never a different one the owner might bind.
The owner's recourse is unchanged: cancel their own pending during cooling (session
compromise) or dispute a genuinely leaked key out of band.

### New findings

#### N2 — `BindingConflict` message can misclassify a same-identity collision as "different identity" — **low (cosmetic)**
**Location:** `store.py:285-291`
When a single `INSERT` violates *both* a `(chain,address)` and a `(identity_id,chain)`
unique index, SQLite reports only one, and empirically it names the `(chain,address)`
one first — routing to "already bound to a different Fayda identity". In the security-
relevant direction this is safe: that message appears **only** when a `(chain,address)`
index is genuinely violated, which at the active tier always means a *different*
identity holds the address (an active `INSERT` only happens when the inserting identity
has no active row for that chain, so it can never self-collide on the active-tier
index). The residual is purely cosmetic: a same-identity double-submit that *also*
happens to collide on address at the pending tier could show "different identity"
instead of "reload and retry". No security impact — both are 409, same actor, and the
app-level `pending_binding` check catches the ordinary double-submit before
`create_binding` is even reached. Worth a one-line comment; not worth code change.

#### N3 — global lock makes all DB access strictly serial; unauthenticated `/api/registry` amplifies it — **low (DoS, largely pre-existing)**
**Location:** `store.py:104-113`, `app.py:279-282`
The lock serializes every connection open/use/close in the process, reads included.
`/api/registry` is unauthenticated and calls `promote_due()` (a full scan of all
pending rows) on every hit; under the global lock, an attacker spamming it now
serializes the entire server rather than merely competing for the writer lock. This is
the old L4 ("promote_due on every read") with a strictly-serial concurrency profile,
not a new capability, and for a single-process demo it is acceptable — the same lock
also *eliminates* intra-process `SQLITE_BUSY`. Flag only so a future multi-worker /
production move reconsiders: move promotion to a scheduled job and gate `/api/registry`.

### Verified safe (this diff)

- **No raw SQLite text or PII reaches any response body.** `BindingConflict` messages
  are two fixed strings; `str(e)` in `wallet_bind` uses the `BindingConflict`, not the
  chained cause; and SQLite unique-constraint messages carry column names only, never
  values or the FIN.
- **Cancelled/archived rows never block a rebind** (partial index + app check both scope
  to `active`/`pending`); cancel-then-rebind of the same address verified to succeed.
- **The non-reentrant lock cannot self-deadlock** — no nested `conn()` acquisition
  anywhere; helper reads run before the outer `with conn()` in all three functions that
  call them.
- **The savepoint promotion isolates failures** — only the conflicting row is cancelled,
  the outer transaction and every other read survive (test 15, three reads stay 200).
- **Tests are not vacuous** — 17 requires exactly `[200,409]`; 16 and 18 assert the
  `IntegrityError` cause and both distinct client messages.
- **The active-tier sybil invariant still holds under the race** — test 17's 10 rounds
  never produce a duplicate active row; the loser always 409s.

### Verdict

**Yes, safe to build on with respect to these three changes.** M1 and M2 are genuinely
resolved, the deadlock fix is correct and self-deadlock-free, and the new pending index
introduces no owner lockout — cancelled/archived rows sit outside it and only a proven
key-holder can create a blocking pending row, which is the pre-existing key-control
tradeoff. No new criticals or highs. Two lows (N2 cosmetic message, N3 serialization/DoS
amplification), and the previously-recorded M4 migration hazard remains open and
untouched by this diff.

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
