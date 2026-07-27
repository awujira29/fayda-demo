# PROGRESS

The loop's memory. The agent forgets between runs; this file does not.
Update as work completes. Do not delete history, move items to Done.

Status: todo / doing / blocked / review / done

---

## Now

### M5 - sessions table grows without bound from unauthenticated /login
**Status:** RESOLVED 2026-07-27 (R1 sweep + R6 rate limit). The TTL sweeper
reclaims expired rows every 10 minutes, pre-auth rows get 30 minutes instead of
12 hours, and the login tier now bounds the arrival rate — a sweep alone only
bounds a table at rate x TTL, and both terms are now controlled.
**Severity:** medium (auditor finding, 2026-07-24, session-storage review)
**Why:** Every /login hit persists an oidc_state session row; rows are swept only
lazily on load of that exact sid, so anonymous hits accumulate forever. Same class
as L1 (nonce growth) but attacker-drivable without auth.
**Do:** Periodic DELETE FROM sessions WHERE expires_at < now (share the sweep with
L1), and consider not persisting a session until it holds more than oidc_state.

### M6 - Every authenticated request rewrites its session row
**Status:** RESOLVED 2026-07-27 (R6). The middleware snapshots the session at
request start and writes only on a real change; the sliding expiry refreshes
hourly rather than per request. Test 47.
**Severity:** medium (auditor finding, 2026-07-24)
**Why:** The middleware unconditionally re-saves and re-sets the cookie on every
response with a non-empty session, turning polled reads (/api/me, /api/registry)
into writes under the process-global DB lock.
**Do:** Save only when the session dict actually changed (compare a snapshot taken
at request start); refresh the sliding expiry at a coarser interval.

### M7 - Logout is not atomic against concurrent requests
**Status:** RESOLVED 2026-07-27 (R6), on the second attempt — the first fix put
the tombstone in the logging-out request's own dict, where no concurrent
request could see it, and failed 5 times in 6 under audit. It now lives in the
row (sessions.revoked_at) and save_session refuses to write over it. Test 49.
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
frontend/src/wallet/ (rebuilt in S3) is the only module that may import @privy-io, exposing
WalletProvider/useWalletConnection/signFor. Swapping providers = rewriting one
file. Privy is integrated for CONNECTION of external self-custody wallets only;
embedded wallets are off (createOnLogin: 'off', both chains). The binding
endpoint remains provider-agnostic (verifies signatures, nothing else).

**Still open:** the embedded-wallet path itself — gated on B3 (data residency)
and R1 (provenance columns must land BEFORE any provider-assisted binding is
accepted, or the distinction is unrecoverable).

### L1-L4 - Deferred
- L1 RESOLVED (R1): auth_nonces are pruned by the TTL sweeper (test 25).
- L2 RESOLVED (R1): addresses are canonicalised per chain by a GENERATED
  column, so the app and the sybil indexes agree on what "the same wallet"
  means. base58 is case-sensitive and only EVM hex is not, and the mismatch
  between a lowercasing app check and case-sensitive indexes let two identities
  hold one wallet with no race required (test 22).
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
- L8 RESOLVED (2026-07-24) Mock /authorize reflected state/scope/redirect_uri
  unescaped. The Render deploy publishes the mock via DEMO_MODE, which promoted
  this to a live medium (reflected XSS same-origin with the wallet SPA). Fixed:
  all reflected params html.escape'd, and redirect_uri constrained to a
  /callback path at both /authorize and /authorize/confirm (also closes the
  paired open redirect). Test 21.
- L11 (auditor, 2026-07-24) The redirect_uri check is PATH-ONLY, so
  <any-host>/callback passes → a restricted open redirect after a persona
  click. Harmless in the mock (leaked code unexchangeable without the
  server-held client-assertion key; persona is public). MUST become a full
  host+path match against the registered URI when real Fayda credentials
  replace the mock (see B1). Deliberately not host-matched now: Render's
  Host-forwarding is unverified from here and a wrong guess would 400 every
  live login.
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

### B4 - Lawful basis for the identity-to-financial-history join (R4/F1)
**Status:** OPEN — recorded, not assumed resolved. Required by F1's own brief.

R4 shipped the capability: an operator can pull a Fayda-verified identity's
in-app history and the on-chain activity of the wallets bound to it. That is
the most sensitive thing this system does, and it has no documented legal
basis. The technical controls are real — operator-only, per-access logging that
the subject can read, append-only at the database, on-chain data cached rather
than stored — but controls are not a basis.

Questions for NBE and NIDP, before this is used against real people:
- Under what authority may a national identity be joined to financial history,
  and by whom? Is a compliance operator inside this system such a body?
- What retention applies to the access log itself? (Deliberately unimplemented:
  a log that prunes itself contradicts its purpose, and the retention period is
  a legal answer, not an engineering one.)
- Must the subject be notified of an access, or is after-the-fact visibility
  (/api/me/access-log) sufficient?
- Does pulling a public chain address's full transaction history, once that
  address is linked to a named person, constitute processing personal data
  under Ethiopian rules?

Until these are answered, treat the operator role as demo-only. Do not grant it
to anyone against a database holding real identities.

### B3 - Privy data residency
Privy is US-hosted and Stripe-owned since June 2025. Binding a Fayda-verified identity
to a wallet whose keys are partly held abroad is a question for NBE and NIDP under
Ethiopian data-protection rules. Unanswered. Do not integrate before it is.

---

## Done

### R4 / F1 - Transaction history behind the operator role - done 2026-07-26

The payoff feature and the most sensitive thing this system does: a
Fayda-verified identity joined to on-chain activity. It lives entirely behind
R3's operator role, is logged per access, and appears in no user or public view.

**In-app timeline** is derived from the binding rows themselves — each
binding's timestamps ARE its history — rather than from a parallel event
table, so it cannot drift out of sync with what it describes. Bind, replace,
promote, cancel and archive all produce distinct events (t.py 40).

**On-chain** (`backend/chain.py`) is read-only, cached in memory with a TTL,
and never written to the database: the data is public and refetchable, so
caching it is the most it may be. Four rules, each of which turned out to
matter: never fabricate (with no provider configured the answer is
`not_configured`, not an empty list that reads as "this wallet has never
transacted"), never block (absolute wall-clock budget, not just per-operation
timeouts), never write, never raise.

**Split into two endpoints** so a slow third-party explorer cannot make every
case file open at the speed of the worst explorer day.

**Auditor: 1 critical, 2 highs, all resolved.** The critical is the one worth
remembering:

- **CRITICAL — an unauthenticated linkage oracle.** The ownership check ran
  BEFORE `require_operator`, so an anonymous caller got three distinguishable
  answers ("no such identity" / "not bound to this identity" / the auth error)
  and could confirm whether a given public wallet belongs to a given Fayda
  identity — the exact linkage the whole feature is gated to protect — with no
  operator, no reason, and no log entry. An ordering mistake, not a design one,
  but it made the flagship privacy join publicly queryable. Authorization and
  logging now precede any answer that varies with stored data. Worse: the test
  written to prove the endpoint was closed to anonymous callers probed with a
  *bound* address, the one input that reached the auth check — so it passed
  precisely by avoiding the bug. It now fires all three shapes and requires the
  answers to be byte-identical.
- **HIGH — a slow-drip provider could stop the service.** httpx timeouts are
  per-operation; a provider sending one byte just inside the read timeout,
  forever, never trips them, and these endpoints are sync, so each such request
  pinned a worker thread. Measured: 45 concurrent lookups took down `/api/me`,
  `/login` and `/config.js`. Now bounded by an absolute deadline checked per
  chunk (verified: terminates at 12.1s against a dribbling server) plus a 1 MB
  cap while streaming, which also fixed a 134 MB buffer for a 25-row answer.
- **HIGH — the JSON parse sat outside the try**, so any non-object top level
  escaped as a 500 *after* the log row was written. Six hostile payloads now
  degrade to a status.

Four mediums fixed too. The one with a real judgement in it: the ownership
check accepted **cancelled** bindings. Cancellation is precisely how a user
repudiates a swap they did not authorise, so honouring it would pull an
attacker's address into the victim's case file and write it to a log that
cannot be corrected. Now active and archived only — archived bindings were
genuinely live once and are that person's history. Also: the subject's own view
now includes `detail`, so a person can see WHICH of their wallets was traced,
not merely that one was.

A second audit round then found an **audit-integrity** flaw worth recording:
the access entry was written before the ownership check (which is what closed
the critical) but recorded as a COMPLETED trace, so an operator could write a
permanent, subject-visible entry claiming they traced any address they cared to
name — indistinguishable afterwards from a real one, and uncorrectable in an
append-only log. Attempts and completions are now separate actions
(`view_onchain_attempted` / `view_onchain`); an attempt with no matching
completion is exactly what a reviewer should notice. In the same round:
`looks_like_address` accepted `0x` plus any 40 characters with no hex check, so
arbitrary text — markup included — reached that permanent log field; and the
on-chain cache keyed on a blanket `.lower()`, which collapsed two DIFFERENT
Solana public keys onto one entry, serving one person's transactions under
another's name on a compliance screen. Both fixed with tests (43, 44).

Smaller: the `operator` flag in /api/me now mirrors BOTH server-side conditions
(role and Fayda session), so a passkey-session operator is not shown a panel
where every button 403s; OperatorPanel is lazily loaded, so it is no longer
shipped to every visitor enumerating the operator routes in the main bundle;
a size-cap trip reports `provider_error` rather than falsely claiming the
provider was unreachable; and a malformed `CHAIN_CACHE_TTL` falls back instead
of crashing the boot of the whole registry over an optional cache setting.

**Verification:** all 60 checks pass; tests 40-44 are new, and the on-chain
path is exercised against local stub servers (hostile shapes, oversized flood,
slow drip) rather than a real API. The full flow was also driven in a real
browser against a stub explorer: search with a mandatory reason → case file →
7-event timeline → per-wallet on-chain trace, with the failure states rendered
as failures.

**Lawful basis: OPEN, recorded as B4.** The controls are real; controls are not
a basis. Do not grant the operator role against a database of real identities
until NBE/NIDP have answered.

### R3 - Operator role + append-only access log - done 2026-07-26

The first change that lets one person read another's record, so the rule is:
**nothing cross-user is returned until the access is durably logged.**
`require_operator()` checks the session, checks membership, demands a
substantive reason, and writes the log entry — and is deliberately not wrapped
in try/except, so a failed log write fails the request. A lookup that answers
without leaving a trace is the thing R3 exists to prevent.

Operator membership is granted by `python backend/store.py grant-operator` and
by no HTTP route; a route that can grant privilege is a route that can be
tricked into granting it. Revocation is a tombstone, not a DELETE — hard
deletion left the log full of entries by an actor with no recorded authority,
so a reviewer could no longer tell whether the lookups were legitimate at the
time. Grant and revoke are themselves logged, in the same transaction as the
change they describe.

**The log is append-only in the database, not by convention.** A trigger
refuses UPDATE and DELETE for every caller including the table owner the app
connects as; a second statement-level trigger refuses TRUNCATE (which does not
fire row triggers, and was the single most effective way to erase everything);
and both are `ENABLE ALWAYS`, because a plain trigger is skipped whenever
`session_replication_role = 'replica'` — one statement, no DDL, both guards
off.

**The subject can see the surveillance.** `GET /api/me/access-log` shows who
looked at their record, RLS-scoped so it is not a window onto anyone else's.
The frontend replaces the registry ledger with it. A capability that points one
way with nobody able to see it is the version worth being afraid of.

**Auditor: 0 criticals, 3 highs, all resolved.** Every one was a case of the
rule being written but not applied everywhere:
1. `/api/registry` returned the name→wallet mapping for every bound identity to
   any authenticated session with **zero** log entries — the most sensitive
   cross-user join, by the one route that left no trace. Now operator-only and
   logged; the old GET is gone; ordinary users no longer see a registry at all.
2. Both log views were capped at `LIMIT 200` with no pagination, so ~210 cheap
   lookups pushed a sensitive entry out of the only view anyone reads, in both
   the operator's view and the subject's. Now keyset-paged with the true total.
   The cursor is `(at, id)`, not `at` — timestamps are not unique (one search
   writes an entry per result in a tight loop) and an `at`-only cursor skipped
   every row sharing the last one's timestamp. Test 37 plants five entries at a
   byte-identical timestamp and walks them one at a time.
3. Search logged the query but not who it returned, so the discovery phase was
   invisible to the people discovered — and `%` matches everyone. Now one entry
   per surfaced identity. The same fix was then needed for the registry, which
   discloses strictly more (auditor's follow-up round).

Five mediums also fixed: operator powers now require a Fayda-established
session (a passkey session was too weak to add a passkey yet strong enough to
read every identity); `revoked_at` migrates in place via ALTER (CREATE TABLE IF
NOT EXISTS adds nothing to an existing table, so every operator route would
have 500'd on a pre-existing database — fail-closed but silent until someone
needed compliance access); TRUNCATE and replica-mode; an index matching the
paging order; and `identity_full` no longer hands operators the `fin_hmac` that
`registry()` withholds by name for exactly the same correlation reason.

Also: FastAPI's interactive docs are disabled outside dev — they were open and
published the whole route table, operator endpoints included.

**Deferred deliberately:** retention/pruning of the access log (a log that
prunes itself contradicts its own rationale — this is a policy question for the
NBE/NIDP review, not a code decision) and rate limiting, which is R6. The
`count(*)` behind each log read is the cost worth watching there.

**Verification:** all 49 checks pass; tests 33-39 are new.

### R2 - Row-Level Security + passkey return-login + non-public registry - done 2026-07-26

**RLS is enforced by Postgres, not by WHERE clauses.** The catch: the app
connects as `postgres`, which carries `rolbypassrls` — policies written against
that role are decoration. So a role `fayda_app` (NOLOGIN, NOBYPASSRLS) is
created and granted to the connected user, and `store.user_conn(identity_id)`
runs `set_config('app.identity_id', …, true)` + `SET LOCAL ROLE fayda_app` for
the transaction. Policies on identities, wallet_bindings and
webauthn_credentials are `USING`/`WITH CHECK (<col> = nullif(current_setting(
'app.identity_id', true), ''))`. The `nullif` is load-bearing: on a REUSED
pooled connection `current_setting` returns the empty string rather than NULL,
so a bare comparison becomes `id = ''` — a predicate an unbound transaction can
satisfy and then share with every other unbound transaction. Verified: a
`SELECT` with no WHERE clause at all returns exactly one identity's rows; an
INSERT for another identity is refused; an unbound transaction reads and writes
nothing; neither role nor GUC survives a pool checkout, including after an
exception mid-transaction (t.py 27, 32a).

**The interaction that mattered: RLS hides rows the sybil check needs.** The
unique indexes are not RLS-filtered, so a same-tier collision is still caught
even though the querying identity cannot see the conflicting row. The cross-tier
case (an identity with a wallet claiming one held by another) has no index to
catch it, which is exactly why `address_claimed_by_other` stays on the
privileged connection — scoped, it would see nothing and report the address
free. Both halves are asserted against a row RLS hides (t.py 27).

**Passkey return-login, deliberately NOT Supabase Auth** though R2 named it: its
passkey support is beta ("API may change without notice"), and adopting it would
put a client-readable JWT in the browser and a second identity authority beside
Fayda — S1 moved sessions server-side precisely because the claims carry
kebele/woreda, and the SPA is same-origin with a third-party wallet connector.
WebAuthn is implemented directly (py_webauthn) against our own Postgres, so
Fayda stays the only source of identity and Supabase stays what it is: the
database enforcing the policies. A passkey session carries name and birthdate
only — it proves device control, not a fresh national-ID check, and must not
resurrect neighbourhood-level claims from an older session.

**The security property that took three rounds to get right:** a passkey
outlives logout, so an attacker holding a live session could register one and
convert a temporary compromise into permanent access — the precise failure the
cooling period exists to prevent, made unrecoverable. Three rules, each closing
a gap the previous round left:

1. Registration requires `auth_method == "fayda"` (set explicitly at the
   callback, never inferred from a missing key), so a passkey cannot
   chain-register another.
2. Registration also requires a RECENT verification (`auth_at` within 15
   minutes). Gating on how the session was *created* was not enough — the
   auditor pointed out that a stolen cookie inherits the victim's Fayda login
   and could register at any point in the session's 12 hours. Freshness shrinks
   that to minutes and forces the attacker through the one step a cookie cannot
   replay.
3. Revocation ends the sessions that passkey opened, not just its next login.
   The attacker who registered it is already signed in; without this, revoking
   left them working for the rest of a 12-hour TTL and the escape hatch was
   decorative.

Verified end to end (t.py 30, 30b, 30c — 30c backdates `auth_at` through the
store so staleness is tested deterministically rather than by waiting), and in
real Chrome with a CDP virtual authenticator: register → sign out → return with
the passkey alone, register disabled in a passkey session, revoke present and
effective.

**The registry stopped being public.** `/api/registry` requires a session; the
payload drops `fin_hmac` (a stable pseudonymous key that lets any reader
correlate a person across rows) and the internal id (the RLS scoping key), and
lists only identities that actually hold a wallet — an identity with none was
the sensitive half of the row without the useful half. This also takes the
registry-wide `promote_due()` off the unauthenticated surface. Honest caveat
recorded in DEPLOY.md: under `DEMO_MODE` a persona click buys a session, so the
gate is real but the identities behind it are public test data.

**Auditor: 0 criticals. Two highs, both resolved.** (1) The unrevokable-passkey
persistence above. (2) `requirements.txt` was unresolvable — `cryptography==46.0.6`
against webauthn's `>=49`, which would have failed every Docker and Render
build while tests passed on a venv upgraded out of band; verified fixed with a
`--dry-run` install in a fresh venv, not the local one. Five mediums also fixed:
the `nullif` fail-closed gap, `reset()` orphaning credentials and permanently
dropping their foreign key, the registry disclosure, `require_user_verification`
not enforced at registration (which would have stored unusable keys), and three
unauthenticated 500s from malformed JSON bodies.

Also made structural rather than documented: `DEMO_MODE` publishes a login any
visitor can perform, so a deploy that sets it AND points at a real Fayda
endpoint now refuses to boot instead of putting real identities behind a
one-click login (t.py 32d). The remaining DEMO_MODE caveat — that the gate is
real but the identities behind it are public test personas — is written down in
DEPLOY.md.

**Verification:** all 34 checks pass; tests 27-32 are new. The Docker image
builds clean (the `cryptography` pin fix verified in the context it was
breaking, not just via `pip --dry-run`). Full flow driven in real Chrome via a
CDP virtual authenticator, not only the software authenticator in t.py.

**Known and accepted:** a stolen session can revoke the victim's OWN passkeys
(revoke is gated on the session alone). That is the safe direction — worst case
the victim is pushed back through Fayda, which is where a compromised session
should end up anyway — so it stays un-privileged deliberately.

### R1 - Supabase Postgres migration (KEYSTONE) - done 2026-07-26
Storage is managed Postgres, not a file on the container's disk. Data survives
deploy, restart and scale-out, the sybil indexes hold across every instance
because they live in one shared database, and RLS (R2) becomes possible at all.
`SUPABASE_DB_URL` only — env or the gitignored `backend/.env`; no SQLite
fallback, and the app refuses to start without it rather than silently
reverting to disposable storage.

**The migration itself:** psycopg3 + `ConnectionPool` (max_size 12, idle
recycle, `check_connection` so a pooler-dropped connection surfaces as a fresh
one rather than a failed request). Partial unique indexes ported unchanged;
`sqlite3.IntegrityError` → `psycopg.errors.UniqueViolation`, distinguished by
`e.diag.constraint_name`. The process-global `_DB_LOCK` is gone.

**What real concurrency then required** (SQLite's single-writer model had been
providing these for free): `consume_nonce` takes `FOR UPDATE` so two racing
binds serialize and the loser sees `consumed=1`; `cancel_pending` reads and
writes under one row lock, because an unguarded read-then-write let a
concurrent promotion resurrect the cancelled row and activate an attacker's
swap — precisely what the cooling period exists to prevent; `promote_due` uses
`FOR UPDATE SKIP LOCKED` with `ORDER BY id` and re-checks status under the
lock; `upsert_identity` uses `ON CONFLICT` so two first logins of one persona
don't 500 the callback. Tests 22 and 23 are new and both were verified to fail
against the unguarded code.

**A sybil hole found and closed en route:** the indexes compared exact strings
while the app lowercased, so `0xAbC…` and `0xabc…` were two rows to Postgres —
two identities could hold one wallet with no race needed. Canonical form is now
a GENERATED column (`address_norm`), so the *database* computes it and no code
path, present or future, can write a row that escapes the index. Test 22 races
case-variant spellings and asserts exactly one live claim.

**Auditor: 0 criticals. Three highs found across three rounds, all resolved:**
(1) quadratic base58 decode on an uncapped address — 1 MB body ≈ 345 s of
GIL-held CPU, and `wallet_bind` never validated `chain`, so any payload could
reach that branch. Now gated three ways; re-verified flat across a 2000x size
range, and measured against 200,000 random keys to confirm no legitimate
address is rejected (test 24). (2) Durability removed the redeploy-wipe that
had been the only thing reclaiming `sessions`/`auth_nonces` — added a
`lifespan` sweeper thread plus a 30-minute TTL for pre-auth rows (down from 12 h;
a sweep bounds a table at rate × TTL and TTL is the term we control). Session
table steady state at 500 req/s: 0.25 GB, from 18 GB (test 25).
(3) **Self-inflicted, and the one worth remembering:** the fix for the suite's
non-idempotency set `APP_ENV=dev` two lines before calling `store.reset()`,
satisfying reset's own guard — turning the most-run command in the repo into a
one-command wipe of whatever `SUPABASE_DB_URL` named. A guard that reads the
caller's environment is not a guard. Destruction is now gated on the TARGET:
`registry_meta` carries a marker naming the cluster's `system_identifier`
(server-attested, unique per cluster, not carried by `pg_dump` — host:port/dbname
would NOT have worked, since every Supabase project in a region shares them
behind the session pooler). Both gates refuse independently (test 26), and
`mark-disposable` additionally refuses a populated registry.

**Verification:** `APP_ENV=dev python backend/t.py` — 26/26, twice consecutively
(idempotency), each new test verified to fail against the code it guards. The
suite now resets first, so it runs only against a database explicitly marked
throwaway; point `.env` at production and it refuses instead of destroying it.

**Deferred to R6, recorded honestly:** the pool saturates under ~30 concurrent
authenticated reads (p50 22 s) — recovers, never wedges, but needs fewer
checkouts per request and the M6 write-on-read fix; `sslmode=require` encrypts
without authenticating the server (`verify-full` needs Supabase's root cert
shipped); a nonce is not bound to the issuing identity, so a durable
`proof_message` can name a different person than the binding's owner; and there
is still no rate limiting anywhere.

### D1 - Single-service Render deploy (API + SPA, DEMO_MODE) - done 2026-07-24
One FastAPI process serves the API and the built React SPA (frontend/dist),
same-origin, so the cookie/OIDC flow is unchanged and there is no CORS. Vite
base './' for relative assets; app.py mounts /assets and adds a catch-all
(registered last, so no /api|/login|/callback|/logout|/v1|/authorize|/config.js
route is shadowed; api_route over all methods so an unmatched POST 404s not
405s; resolve()+is_relative_to traversal guard). Production cookie is Secure
(non-dev, both set and delete paths); SameSite=Lax still admits the top-level
/callback nav. PUBLIC/BASE and verify.py's message origin derive from
PUBLIC_URL || RENDER_EXTERNAL_URL || BASE (env-only, not Host-influenced);
BASE tracks $PORT for the server's self-calls. Privy app id is runtime config
via /config.js (no rebuild to set/rotate).

DEMO_MODE mounts ONLY the mock IdP (personas) — never /api/dev/*, so a demo
visitor cannot wipe the DB (H1) or skip cooling (H2); the secrets guard and
Secure cookie stay. Dockerfile (Node build stage → python:3.12-slim runtime,
native-dep toolchain in the build stage only), render.yaml (Docker web
service, generateValue secrets, DEMO_MODE=1, PRIVY_APP_ID sync:false,
RENDER_EXTERNAL_URL auto), DEPLOY.md (exact click-path, every env var, the
Privy allowed-origins step, and the SQLite-resets-on-redeploy caveat plainly).

Verified: image built and run as Render would (PORT=10000, prod, DEMO_MODE),
full persona→Secure-cookie→/api/me round trip passed over one origin, every
/api/dev/* 404, message names the deployed origin, traversal cannot escape
dist. backend/t.py: 21/21 (tests 20 demo-gating, 21 mock XSS+open-redirect).
Auditor on the deploy deltas: 0 new criticals, 0 new highs; one medium (the
DEMO_MODE-published mock XSS) found and fixed (L8), two lows. Dropped stale
itsdangerous dep.


### S3 - Frontend rebuild v2: financial-grade UI + real wallet connector - done 2026-07-24
Old frontend deleted, rebuilt as React + Vite + Tailwind v4 with shadcn-style
primitives themed to a committed visual world (DESIGN.md: civil-registry
record — Source Serif 4 300/700, Public Sans, Spline Sans Mono, OKLCH tinted
neutrals, one Fayda green-teal accent for identity/verification/active only,
guilloché band, ruled ledgers, full dark + light). Privy is the wallet
connector (connection only; identity stays Fayda; embedded wallets off;
EIP-6963 discovery), isolated in frontend/src/wallet/ — the R2 seam. Solana
connect is honestly disabled (SOLANA_WALLETS_ENABLED=false) until external
Solana support in the connector is verified; never fake a chain. Every state
designed: loading, empty, error+recovery, disconnected, signature-pending,
cooling (warning-toned), missing-config, origin-mismatch (new public_origin
field in /api/me).

Backend deltas: signed message origins derive from PUBLIC_URL (no more
three-origin mismatch at the signing moment — NOTE production must set
PUBLIC_URL or the message names the backend host); message gained a
public-registry consequence line and an Expiration Time line; nonces record
issued_via server-side and bindings persist proof_method, so a dev test-key
attestation can never masquerade as a wallet attestation (t.py test 19; the
first cut of this silently no-oped — auditor caught it, fixed and re-verified
against the DB). Mock capture panel labeled "Step 1 of 2".

Verification: Impeccable detector zero findings (twice); two-pass design
review — design-critic + ux-heuristics-review + cognitive-load-conversion +
ai-trust-builders + accessibility ran in parallel, ~30 named findings all
applied, pass 2 verified all resolved, no regressions, no banned patterns,
verdict "designed" (DESIGN-REVIEW.md, screenshots/ desktop+380px both
themes). Auditor: 0 new criticals, 0 new highs; 1 medium (the proof_method
no-op) found, fixed, re-verified. backend/t.py: 19/19. Live-verified in the
user's Chrome: MetaMask installed and EIP-6963-announcing. The full
MetaMask-through-Privy-modal demo needs the user's Privy app id (no dashboard
session existed; not automatable) plus a human click in the extension popup —
the single remaining human step, documented in README.


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

---

## Now

### F1 - Transaction history tied to a verified user
**Status:** todo
**Severity:** feature (boss-requested; mirrors Sumsub Transaction/Crypto Monitoring)
**Why:** The identity-to-wallet binding exists precisely so a verified person can be
tied to on-chain activity. This is the payoff feature -- pick a verified identity,
see everything their bound wallets did, plus every in-app event. It is also the
first piece of the compliance/monitoring layer that turns identity-proofing into
something closer to full KYC/AML.

**Two data sources, both required ("both" per boss):**
1. IN-APP event history -- already have the raw material. Every bind, verification,
   pending replacement, cancel, promotion, and archive is a row or a derivable event.
   Build a per-identity timeline from wallet_bindings (+ their status transitions and
   timestamps) and the verification/login events. This is local, cheap, and exact.
2. ON-CHAIN transaction history -- for each active bound wallet, fetch its
   transactions from a chain data provider (e.g. an EVM explorer API / RPC for
   Ethereum, and the Solana equivalent if/when Solana ships). Read-only, public data.
   Show tx list per wallet: hash, timestamp, direction, counterparty, value.

**Do:**
- A per-identity view: identity header (name, residenceStatus), their active +
  historical wallets, an interleaved timeline of in-app events and on-chain txs.
- Gate it: this is sensitive. It must be an authenticated, authorized view (a
  compliance/operator role), NOT the public registry. Decide the auth model before
  building -- who is allowed to pull another person's history.
- On-chain fetching is external I/O: cache it, handle provider failure gracefully,
  never block the page on a slow explorer call. Show in-app history immediately,
  stream on-chain in progressively.
- Do NOT store on-chain data as source of truth -- it's public and refetchable;
  cache with a TTL at most.
- Privacy note: binding a national identity to a full on-chain history is exactly
  the kind of surveillance capability that needs a clear lawful basis. Flag for the
  same NBE/NIDP data-protection review as the rest of the identity data. Record the
  question; do not assume it's permitted.

**Done when:**
- Given a verified identity, an authorized operator sees a combined timeline of
  in-app events and on-chain transactions for the bound wallet(s)
- The view is access-controlled, never public
- On-chain fetch is cached, non-blocking, and degrades cleanly when the provider is down
- A test covers the in-app timeline assembly; the on-chain path is mockable in tests
- The auditor reviews the new authorization boundary specifically
- The lawful-basis/privacy question is recorded as an open item for NBE/NIDP

---

## Login, RLS, and roles -- sequenced (do IN ORDER)

Requested: a login layer so users see their own data, with Row-Level Security,
plus an operator/compliance role. RLS as asked for is a Postgres feature; SQLite
can only fake it in app code (one missed WHERE clause = full leak). So Postgres
is now a PREREQUISITE, not a someday. Three ordered goals:

### G1 - Migrate SQLite -> Postgres (prerequisite, was M4)
All SQL is isolated in store.py. Partial unique indexes (ux_active_chain_address,
ux_pending_chain_address) port to Postgres unchanged. Replace sqlite3.IntegrityError
handling with psycopg UniqueViolation. Drop the process-global _DB_LOCK -- Postgres
has real concurrency, so the deadlock fix and the write-on-read serialization go
away. Fixes three things at once: data survives deploy, sybil holds across instances,
and RLS becomes possible. backend/t.py must pass against Postgres.

### G2 - Login layer + Row-Level Security
- Return-login: Fayda once to establish the identity, then register a passkey
  (WebAuthn) so the user returns with device biometric (Face ID / fingerprint),
  phishing-resistant, without re-running the full Fayda flow.
- Postgres RLS: every table carrying user data gets a row policy so a user session
  can only read/write its OWN rows -- enforced by the database, not just app code.
- A user dashboard: the signed-in person sees ONLY their identity, their wallets,
  their in-app history. Nothing of anyone else's.
- The public registry stops being public once real identities exist -- decide what,
  if anything, stays publicly visible.

### G3 - Operator/compliance role + F1 transaction history
- A privileged role that CAN look up other identities (this is the F1 feature).
- Every operator lookup is written to an IMMUTABLE access log: who viewed whose
  data, when, why. This is mandatory for the surveillance capability F1 represents
  -- Sumsub calls it Case Management; regulators call it access logging.
- F1 (combined in-app + on-chain transaction history) lives HERE, behind the
  operator role, never in the user or public view.
- Lawful-basis / data-protection review with NBE/NIDP before this ships -- binding
  a national ID to full financial history is the most sensitive thing the app does.

Do not bundle these. Each is one goal, reviewed and audited on its own.

---

## DEMO -> REAL APP roadmap

The switch from demo to production. Ordered; earlier items are prerequisites for later.
Persistence requirement (explicit): data must NEVER be lost on deploy/restart/scale.
Supabase chosen as the base -- it is managed Postgres + Auth + Row-Level Security in
one platform, which collapses persistence, the login layer, and RLS into one decision.

### R1 - Migrate to Supabase Postgres (KEYSTONE) - DONE 2026-07-26 (see Done)

### R2 - Auth + passkey return-login + RLS - DONE 2026-07-26 (see Done)

### R3 - Operator role + immutable access logging - DONE 2026-07-26 (see Done)

### R4 - Transaction history (F1), behind the operator role - DONE 2026-07-26 (see Done)

### R5 - Real Fayda credentials — **BLOCKED** on partner credentials (code now ready)

**Why blocked:** there are no Fayda partner credentials in this environment and
none can be obtained from here. Verified rather than assumed: no `FAYDA_*` env
vars are set, `backend/.env` holds only `SUPABASE_DB_URL`, and there is no key
material anywhere in the repo. Onboarding at partner.fayda.et is an external,
human process (B1). Faking it — pointing at a stub and calling it live — would
be worse than not doing it, so the mock stays and this item stops here.

**What I did do, because it did not need credentials: made the claim true.**
The roadmap said "mock_esignet.py is the only thing that should change (the
OIDC client is already written against the real contract)." Checked against the
code, that was **wrong in two ways**, both of which would have surfaced only
during a live integration, i.e. at the worst possible moment:

1. **The client assertion was signed with a keypair generated per process**
   (`app.py` called `mock_esignet.generate_client_keypair()` at import). Partner
   onboarding registers ONE public JWK. A key regenerated every boot — and
   different on every instance — could never match it, so token exchange would
   have failed on the very first request. The key now comes from
   `FAYDA_CLIENT_PRIVATE_KEY`; the ephemeral key remains only for dev and the
   persona demo, where the mock verifies against whatever this process made.
   Production without a registered key refuses to boot rather than failing at
   the first user's login.
2. **`app.py` imported `mock_esignet` at module scope**, so the posture
   CLAUDE.md describes — "Throwaway. Deleted in production." — could not
   actually boot. The import is now conditional on the mock being mounted.

A follow-up audit round found three more of the same species — configurations
that booted green, passed the health check, and would have failed at the first
user's login, which is precisely what this change existed to eliminate:
a malformed key (a truncated PEM, the PUBLIC half, an EC key) was only checked
for truthiness, so it was never parsed until someone tried to sign;
`FAYDA_CLIENT_ID` silently kept its demo default, so a real IdP would have been
handed an assertion claiming to be `fayda-wallet-demo`; and `DEMO_MODE=1`
alongside a real key booted happily — the guard checked the three URL variables
but not the one credential that cannot be rotated without going back to Fayda.
All three now refuse at boot, and the DEMO guard runs before the mock is
imported so the operator reads why rather than a missing-module error.

Test 45 proves the lot without any credentials: it copies the backend to a temp
directory **omitting mock_esignet.py entirely**, boots it with real
`esignet.fayda.et` URLs and a registered key, and asserts the mock was never
imported, the authorize URL is the real one, the assertion is RS256 carrying
the *registered* client id with the real token endpoint as its audience, and
that it verifies against the *configured* key. Then it walks five credential
misconfigurations and the DEMO_MODE combination, requiring each to be refused
at boot with a message that names the actual problem.

**What remains for whoever has credentials** — genuinely only configuration
plus one code check:
- Set `FAYDA_CLIENT_ID`, `FAYDA_AUTHORIZE_URL`, `FAYDA_TOKEN_URL`,
  `FAYDA_USERINFO_URL`, `FAYDA_CLIENT_PRIVATE_KEY`; unset `DEMO_MODE` (the app
  refuses to start if both are set — real identities must never sit behind a
  login any visitor can perform).
- Delete `backend/mock_esignet.py`. Verified to work.
- Confirm the userinfo claim names against the live response. The mock mirrors
  the official Python client (sub, name, birthdate, gender, phone, picture,
  residenceStatus, address{kebele,region,woreda,zone}) but that is a reading of
  a client library, not an observation of the live service — see B1, and
  `residenceStatus`'s value set is still unconfirmed (B2).
- L11: the mock's `redirect_uri` check is path-only. It disappears with the
  mock, but the real IdP's registered redirect URI must be the full origin.

### R6 - Production hardening - done 2026-07-27

R5 is blocked on an external credential issuance, not on anything unverifiable
here, and R6/R7 do not depend on it — so the sequence continued rather than
stopping on a dependency no amount of work in this repo could resolve.

**Rate limiting, which every audit round had named as the single biggest gap
("nothing anywhere has any").** Token buckets per (client address, route
tier) in `backend/ratelimit.py`, four tiers assigned by longest-prefix match,
registered last so it runs first — a refused request does no database work,
verified empirically rather than by reading the registration order. In-process
and documented as such: with N instances the effective limit is N x the rate.
A shared counter belongs in Redis and there is none; putting it in Postgres
would spend the exact resource the limiter protects.

**The limiter's own key was the more interesting bug.** `X-Forwarded-For` is a
list each proxy appends to, so the left-most entry is whatever the caller sent.
Reading from the left made the limiter a *no-op* wherever
`TRUST_PROXY_HEADERS` was set — which `render.yaml` sets for production
(measured: 60/60 spoofed requests allowed against a refusal at 13 unspoofed) —
and additionally let an attacker drain a named victim's bucket. It now counts
from the right by trusted hop count and validates the result is an address.

**M7, logout, which took two attempts and is worth recording.** The first fix
wrote a `__killed__` flag into the logging-out request's own session dict — a
place no concurrent request can observe. It failed 5 times in 6 against an
attacker polling a session-writing endpoint with a stolen cookie, because that
request re-saved its own request-start snapshot and the UPSERT recreated the
row with a fresh 12-hour TTL. The tombstone now lives in the row
(`sessions.revoked_at`), `save_session` is a conditional upsert that will not
write over it, and `/logout` revokes synchronously in the handler. Signing out
is how a user ends a session they believe is compromised; it must not be
undone by their own overlapping request.

**M6**: a read no longer rewrites its session row. The middleware snapshots at
request start and writes only on a real change, refreshing the sliding expiry
hourly rather than per request — polling `/api/me` was a write against a
managed database where every write is a network round trip.

**The rest**: nonce bound to its issuing identity (the signed message embeds
the requester's NAME, so a nonce redeemed by another identity persisted a
`proof_message` attesting to someone who did not make the binding);
`SUPABASE_CA_CERT` upgrades the connection to `verify-full`, since `require`
encrypts while authenticating nothing, and a path set-but-unreadable now
refuses to boot rather than silently falling back; structured JSON logging
through a field WHITELIST, so a field added later cannot leak by default;
sanctions screening that screens against a list you supply and is honest about
what it is — unset reports `not_configured` rather than a clean-looking empty
result, a hit is labelled a signal requiring human adjudication, and nothing
blocks a binding, because refusing a Fayda-verified person on a fuzzy name
match is a determination this system has no authority to make.

**Auditor: 0 criticals, 2 highs, both resolved** (the logout resurrection and
the attacker-chosen limiter key), plus six mediums. Two are worth naming
because both were *my defence being the vulnerability*: the bucket table's
`min()` eviction held a lock for ~0.8ms per new key once full, capping the
process at ~1300 req/s — a denial of service inside the denial-of-service
defence, now O(1) (22,000 keys in 0.04s); and screening's one-way subset match
returned **no hits** for a three-part Ethiopian name against a two-part list
entry while reporting `screened`, which reads as cleared — the exact false-clean
the module's own docstring forbids.

A third round then found **the same bug one door over**, which is the part
worth remembering: logout had been fixed to tombstone, but
`delete_sessions_for_credential` — the passkey revocation path — still
hard-DELETEd, and `save_session`'s guard only refuses to overwrite a
*tombstoned* row. A deleted row has no row to refuse, so the upsert took its
INSERT branch and recreated the session with a fresh 12-hour TTL and no
tombstone, leaving the owner no lever at all. It defeated revocation 5 times
out of 5, on the route whose own docstring says revocation must not be "a
formality", and nothing in the tests covered it. Fixing one instance of a class
is not fixing the class; every kill path now tombstones (test 52).

The limiter key needed a second pass too: it read only the FIRST
`X-Forwarded-For` header and stopped, so a proxy that emits its own header
rather than appending left position 0 caller-controlled — 70 requests claiming
`127.0.0.1` drew 0 refusals where an honest client drew 30. It now joins every
such header before counting from the right, and the loopback self-call
exemption is judged on the socket peer rather than the derived key, so a header
cannot buy it (test 53).

A fourth round found two more, and both were the same shape a third time — *the
guard is correct, the input to it is not*:

- **uvicorn rewrites `scope["client"]` from `X-Forwarded-For` before any
  application middleware runs** (its `ProxyHeadersMiddleware` is on by
  default and trusts loopback). So the limiter's "is this the socket peer?"
  test was answering from the very header it exists to distrust — two
  X-Forwarded-For parsers with different trust models, ours reading a value
  the other had already rewritten. Measured with the default config: **0 of 90
  requests refused** while varying a forged header, i.e. the limiter was a
  complete no-op; with `--no-proxy-headers`, 34 refused. Disabled in app.py,
  the Dockerfile and the test harness, so the app owns that decision.
- **Shortening the tombstone TTL reopened resurrection.** The tombstone stops a
  revoked row being *overwritten* but says nothing about a row that has been
  *swept away*, and the 10-minute reclaim (itself a fix, for table growth)
  brought that window from 12 hours to 10 minutes. Park a request mid-body —
  the session loads when headers arrive and uvicorn has no body timeout — wait
  for the logout and the sweep, then finish the body: no row, no conflict,
  INSERT branch, session back with a fresh TTL. No race timing, just patience.
  Only a freshly minted sid may now insert; a cookie-bearing request may only
  update a row that still exists.

The auditor also found five of my tests contained assertions that could not
fail against what they named — test 49 re-logged-in each round and raced a
read-only endpoint, so it was structurally incapable of reaching the
resurrection path it claimed to cover; test 46's eviction bound was 10s against
O(n) code that ran in 1.5s; test 51's "must not sweep" check compared names
sharing no token. All rewritten.

**Verification:** 55 steps / 109 assertions pass; the Docker image builds; the
full browser flow (login, passkey register, sign out, return by passkey) works
with rate limiting ON.

**Assumed, not verified:** that Render appends exactly one proxy hop, so
`TRUSTED_PROXY_HOPS=1` picks the real client. Wrong would be visible, not
silent — everyone lands in one bucket and legitimate users see 429s under
modest load. DEPLOY.md records how to check after the first deploy.

### R7 - Real domain + HTTPS - remaining

Everything R7 needs from the code is already in place and was verified during
R1/D1: the public origin derives from `PUBLIC_URL || RENDER_EXTERNAL_URL`
(env-only, never Host-influenced), the cookie is `Secure` outside dev, and the
signed message's stated origin comes from the same variable, so a custom domain
is `PUBLIC_URL=https://<domain>` plus two dashboard steps.

What it actually requires is not code: a purchased domain, DNS pointed at
Render, a certificate issued, and the domain added to Privy's allowed origins.
None of that is reachable from here, and inventing a domain to "verify" it
would be theatre. Left as configuration with the exact steps in DEPLOY.md.

### R6 - Production hardening
AML/sanctions screening layer (the Sumsub-style compliance piece), rate limiting on
all endpoints, the deferred audit mediums (unbounded tables, mock /authorize XSS,
etc.), error monitoring, Supabase automated backups verified, structured logging.

### R7 - Real domain + HTTPS
Custom domain, cookie/OIDC origin updated, Privy allowed-origins updated.

Lawful-basis / data-protection review with NBE/NIDP runs alongside R3-R5 -- binding
a national ID to persistent, queryable financial history is the most sensitive thing
this app does and needs a documented legal basis before it goes live with real users.
