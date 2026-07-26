# AUDIT

Adversarial security audit of the Fayda identity → wallet registry.
Newest run at the top. The auditor reports; it does not fix.

---

## Fix review 2 — 2026-07-26 (target-gated reset, COLLATE "C", lifespan sweeper, pre-auth TTL)

Scope: the second fix round only — `store.py` (`registry_meta` table,
`_target`, `mark_disposable`, `disposable`, two-gate `reset`, `_create_schema`
refactor, single-transaction reset, `COLLATE "C"` in `sweep_expired` and
`promote_due`, `ix_sessions_expires` / `ix_auth_nonces_expires`, the
`__main__` mark-disposable command), `app.py` (`lifespan` replacing
`on_event`, `_sweep_loop` failure reporting, `PRE_AUTH_SESSION_TTL_HOURS`
and TTL selection in the middleware), `t.py` (no `APP_ENV` write, exit-2
guidance, test 26).

Method: read every hunk, then attacked the fixed server on 127.0.0.1:8000 and
the live database. Enumerated `reset()`'s refusal matrix by patching `_target`
and `_DISPOSABLE_KEY` in my own process so no real marker was touched;
decomposed `_target()`'s fingerprint against the actual Supabase topology (all
values redacted below); proved the index/collation question on an isolated
40,000-row ANALYZEd scratch table rather than trusting `EXPLAIN` on the live
near-empty ones — my first attempt at that measurement was planner noise and I
threw it out; reproduced the reset/init lock interaction with two real
concurrent transactions on a scratch table; verified the sweeper actually
starts by planting an expired row and booting a fresh uvicorn subprocess
against the same database; and measured the pre-auth TTL end to end including
a login deliberately aged past it. Scratch objects were dropped after use.

**Counts (this review): 0 critical / 0 high / 1 medium / 5 low.**

**Status carried forward: the round-1 High (`t.py` as a one-command production
wipe) is RESOLVED — evidence under its original heading below. R1 High #2's
residual drops again, from Medium to Low. Of the five Lows this round set out
to fix, four are fixed; one is not, and one fix introduced a new one.**

---

### Medium (new) — the disposable marker's target fingerprint cannot tell two Supabase projects apart, which is exactly the case its docstring says it defends

**Location:** `backend/store.py:346-351` (`_target`), relied on by
`disposable()` (`:375-392`) and therefore by `reset()` (`:395-423`).
**Confidence:** certain — decomposed against the live connection.
**Invariant strained:** the stated purpose of putting a target in the marker at
all — *"so a dump of a dev database restored onto a production host does not
carry permission to wipe it along with the data."*

`_target()` is `f"{c.info.host}:{c.info.port}/{c.info.dbname}"`. Decomposed
against this project's actual connection (identifiers redacted, structure
intact):

```
host   : aws-1-us-west-2.pooler.<REDACTED>.com     <- shared by every project in the region
port   : 5432                                      <- same for every project
dbname : postgres                                  <- same for every project
user   : <REDACTED>.<REDACTED>                     <- the ONLY field naming the project…
                                                      …and it is not in the fingerprint

_target() = aws-1-us-west-2.pooler.<REDACTED>.com:5432/postgres
```

Every Supabase project in a region, reached through the session pooler the
`DEPLOY.md` instructions specify, produces a **byte-identical** fingerprint.
Project identity lives entirely in the username (`postgres.<project-ref>`),
which `_target()` omits.

The consequence is precisely the scenario the docstring names. Restore a dump
of the marked dev database onto a same-region production project — an ordinary
"seed prod from a known-good snapshot" or "reproduce the bug on staging"
action — and the dump carries the `registry_meta` row with it. `disposable()`
then compares the restored marker's value against the live target, both are
`aws-1-us-west-2.pooler.<REDACTED>.com:5432/postgres`, they match, and the
grant transfers to production. The one defence the target comparison exists to
provide is the one it does not provide.

Two smaller things fall out of the same decomposition, worth stating because
the docstring asserts otherwise. `_target()` reads `c.info.host/port/dbname`,
described as *"read from the live connection, not from configuration a caller
could have rewritten."* libpq's `PQhost`/`PQport`/`PQdb` echo the **connection
parameters**; I confirmed `conninfo['host'] == c.info.host`. So the fingerprint
is caller-supplied configuration after all — it just happens not to help an
attacker, because the marker is read *out of* whatever database was reached.
And because the fingerprint is the pooler hostname, marking through the session
pooler and later connecting via the direct `db.<ref>.supabase.co:5432` string
(or the transaction pooler on 6543) makes `disposable()` refuse on the same
database. That direction is safe — it fails closed, with a clear message — but
it means the marker is bound to the *route*, not the database.

The fix is available and server-attested:
`SELECT system_identifier FROM pg_control_system()` — I confirmed it is
readable on this Supabase project (returned a 19-digit value). It is unique per
physical cluster, so it distinguishes two projects, and `pg_dump`/`pg_restore`
does not carry it, so a dev dump restored onto production would *not* match and
the grant would correctly fail to transfer. Adding `c.info.user` to the string
fixes the project-collision half but not the dump-restore half; the system
identifier fixes both.

---

### Low (new) — the two new `expires_at` indexes cannot be used by the queries they were added for, because the other fix in the same diff forces a different collation

**Location:** `backend/store.py:128-132` (indexes created with no `COLLATE`
clause, i.e. the database default) versus `:523-528` (`sweep_expired` filters
on `expires_at COLLATE "C"`).
**Confidence:** certain — measured on an isolated table with realistic
cardinality and fresh statistics.
**Status:** round-1 Low ("no index on `expires_at`") is reported fixed. It is
not fixed.

The `COLLATE "C"` change (correct, see below) and the index change (correct in
isolation) collided. A btree on a text column is ordered in the column's
collation; a predicate that forces a different collation cannot use it. The
catalog confirms both indexes recorded `collname: default`.

I initially ran `EXPLAIN` against the live tables and got contradictory results
between two runs — the tables held single-digit rows and the plans were noise.
Discarded that and built an isolated 40,000-row table with the same column type
and the exact index DDL `SCHEMA_INDEXES` ships, then `ANALYZE`d it:

```
predicate  expires_at COLLATE "C" < ?   ->  Seq Scan                     <- what the code does
predicate  expires_at < ?               ->  Index Scan using ix_probe_default
after adding an index on (expires_at COLLATE "C"):
predicate  expires_at COLLATE "C" < ?   ->  Index Scan using ix_probe_c
```

So `sweep_expired` still sequentially scans both tables every 600 seconds —
the "defence gets more expensive the more it is needed" property the index
comment names is still live — and the app now additionally pays btree
maintenance on every session write and every nonce issue for two indexes no
query can use. Net effect versus before this round: slightly worse.
`CREATE INDEX … ON sessions (expires_at COLLATE "C")` (and likewise for
`auth_nonces`) closes it; the third line above is that index, proven usable.

`promote_due`'s `activates_at COLLATE "C"` is unaffected — there is no index on
`activates_at` to lose.

---

### Low (new) — the single-transaction reset inverts lock order against `init()`; I reproduced a real deadlock

**Location:** `backend/store.py:412-423` — `reset()` executes
`DROP TABLE … CASCADE` (ACCESS EXCLUSIVE on the four tables) and *then* calls
`_create_schema(c)`, whose first statement is
`SELECT pg_advisory_xact_lock(727401)` (`:294`). `init()` (`:338-340`) reaches
`_create_schema` directly, so it takes the advisory lock **first** and the
table locks second.
**Confidence:** certain — reproduced with two concurrent transactions.
**Status:** round-1 Low ("reset is not atomic") is genuinely fixed — there is no
longer a committed window with no tables — but the refactor that fixed it
created this.

Reproduced on a scratch table with a scratch advisory lock id, mirroring the
two orderings exactly:

```
reset-shaped  (table lock, then advisory):  acquired both
init-shaped   (advisory, then table lock):  DeadlockDetected: deadlock detected
```

Postgres detects it and aborts one side, so there is no corruption and no
partial schema — the transaction is all-or-nothing, which is the point of the
refactor. The cost is which side loses. If `init()` loses, a booting instance
raises at import and **fails to start**. If `reset()` loses, the exception is
`psycopg.errors.DeadlockDetected`, which is not a `RuntimeError`, so `t.py`'s
`except RuntimeError` guidance path at `:26-31` is skipped and the suite
tracebacks instead of printing its message.

Reachability is genuinely low: `reset()` is dev-gated and marker-gated, so it
can only meet `init()` in a dev environment where a server boots while a reset
runs (a `--reload` restart, or a second shell). Moving
`pg_advisory_xact_lock(727401)` to before the `DROP` in `reset()` makes both
callers take the locks in the same order and removes it entirely.

---

### Low (new) — `mark_disposable()` is gated only on `APP_ENV`, and the grant it writes is permanent and non-revocable

**Location:** `backend/store.py:354-372`.

The two-gate design moved the *check* onto the target, which is the right move
and resolves the High. The *grant*, though, is still authorized by the same
mutable in-process value the original finding was about:
`if os.getenv("APP_ENV") != "dev"`. The bypass therefore did not disappear, it
got one line longer — `os.environ["APP_ENV"]="dev"; store.mark_disposable();
store.reset()` still wipes an unmarked production database from inside any
process.

That is a real difference in kind, not just degree, and I do not want to
overstate it: the round-1 High was severe because a file the team runs
constantly performed the bypass *by accident*. Nothing routine calls
`mark_disposable()` — not `app.py`, not `t.py` — and there is no reason for
anything to. So the accident is gone and only a deliberate act remains, which
is the correct place to land.

What is worth fixing is the grant's lifetime. There is no `unmark`, no expiry,
and `set_at` is recorded but never compared against anything (confirmed: no
comparison on `set_at` exists anywhere in `store.py`). `reset()` deliberately
preserves `registry_meta`, so the grant also survives every reset it authorizes.
A database marked disposable once is disposable forever — including a dev
project that later accumulates real data, or gets promoted, or has its
connection string reused. An `unmark-disposable` command and a `set_at`-based
expiry (re-confirm every N days) would make the grant match the risk.

---

### Low (new) — `t.py` tracebacks instead of guiding when pointed at a database that has never been initialised

`backend/t.py:24-31` calls `st.reset()` and catches `RuntimeError` to print the
"run as `APP_ENV=dev python backend/t.py`" guidance and exit 2. But `reset()`
reaches `disposable()`, which does `SELECT value FROM registry_meta` — and on a
database where `init()` has never run, that table does not exist. Confirmed the
exception class: `psycopg.errors.UndefinedTable`, not a `RuntimeError`. So a
fresh clone pointed at a brand-new empty Supabase project gets a traceback
instead of the message telling it to run `store.py mark-disposable` (which does
call `init()` first, so the documented setup path itself is fine). Catching
`Exception` there, or having `disposable()` treat a missing `registry_meta` as
"not marked", closes it.

Related and smaller: test 26 deletes the marker and restores it at the end. If
the suite dies in between, the dev database is left unmarked and the next run
exits 2 — fail-closed and recoverable with one command, but worth knowing that
is the cause rather than hunting a phantom.

---

### Low (new) — a login slower than the pre-auth TTL fails with "possible CSRF"

`backend/app.py:126` sets `PRE_AUTH_SESSION_TTL_HOURS = 1/6`. Measured on the
fixed server: an anonymous `GET /login` row now carries `TTL = 0:10:00` holding
only `oidc_state`, with a matching `Max-Age=600` cookie. Correct and effective
(see High #2 below). The consequence at the boundary: once the row expires,
`request.session.get("oidc_state")` is `None`, and `/callback` compares the
returned `state` against it. Reproduced by aging a real in-flight login past
its TTL:

```
/callback after the pre-auth row expired -> 400 {"detail":"state mismatch — possible CSRF"}
```

It fails closed, which is the right posture, and the CSRF check itself is
untouched. Two notes. The diagnostic is misleading — the operator debugging a
user's failed login sees a CSRF accusation for what is a timeout, and there is
no way to tell them apart from the response. And ten minutes is comfortable for
clicking a mock persona but not obviously comfortable for the real flow
`mock_esignet.py` stands in for: a biometric capture with retries, or an OTP
over a rural mobile network. Distinguishing "no oidc_state at all" (expired)
from "oidc_state present but different" (actual CSRF) costs one branch and
makes both the message and the TTL choice defensible.

---

### Verified safe (this round, actively attacked)

- **`reset()` refuses on every path I could reach.** APP_ENV unset,
  `APP_ENV=production`, `APP_ENV=dev` with the marker absent, and `APP_ENV=dev`
  with a marker naming another database — all four refused with the correct
  distinct message. Both gates are genuinely independent. The `__main__` block
  exposes only `mark-disposable` (anything else prints usage and exits 2) and
  never calls `reset()`; nothing in `app.py` or `t.py` calls
  `mark_disposable()`; importing `store` has no destructive side effect. The
  only remaining route is a caller that deliberately marks first, recorded as a
  Low above.
- **`COLLATE "C"` genuinely fixes the ordering.** All four comparisons that were
  wrong in round 2 are now correct, including the two that were wrong in the
  dangerous direction:
  `'…12:00:00+00:00' < '…12:00:00.500000+00:00'` → True,
  `'…12:00:00.500000+00:00' < '…12:00:00+00:00'` → False,
  `'…12:00:00.000001+00:00' < '…12:00:00+00:00'` → False,
  `'…12:00:01+00:00' < '…12:00:00.900000+00:00'` → False. The corrected comments
  now state the true reason (the default collation does **not** order ISO-8601
  chronologically) instead of the false one. `promote_due` keeps its Python
  re-check as defence in depth.
- **The lifespan sweeper really starts, under a real uvicorn.** Planted a
  five-hours-expired session row, booted a fresh `uvicorn app:app` subprocess
  against the same database, and the row was gone within seconds of the port
  opening — so the boot sweep runs and `lifespan` fires where `on_event` used
  to. Clean startup output, no deprecation warning. `store.init()` still runs at
  import, i.e. before `lifespan`, so schema creation still precedes the first
  sweep. `_sweep_loop` now reports to stderr with a consecutive-failure count
  and still cannot die.
- **Single-transaction reset removed the no-tables window.** `DROP` and
  `_create_schema` share one transaction, so concurrent statements block rather
  than hitting `UndefinedTable`; `registry_meta` is correctly excluded from the
  `DROP` so the marker that authorized the reset survives it. (Its only cost is
  the lock-order Low above.)
- **The pre-auth TTL breaks nothing in the working flow.** A prompt login still
  completes (`/callback` 307, `authenticated: true`), the session id still
  rotates at login — so test 3b's fixation assertion is unaffected — and the
  authenticated row measured `12:00:02`, i.e. the full TTL is earned only once
  `identity_id` is set. The TTL is chosen in the send wrapper *after* the
  handler has populated the session, so the rotation-and-elevate path gets 12 h
  on the very response that authenticates, not 10 minutes.
- **Test 26 is a real test.** It asserts each gate refuses *independently*
  (APP_ENV unset; marker naming another host; marker absent), matches on the
  distinct message each path produces rather than just "it raised", and restores
  the marker so the suite stays runnable. It would fail if either gate were
  removed.
- **Nothing in this round touched the correctness core.** Re-read the diff for
  changes to `promote_due`'s savepoint logic, `consume_nonce`'s `FOR UPDATE`,
  the generated `address_norm` column, the unique indexes, or the round-1
  address gates: none. The `_create_schema` refactor is a pure extraction —
  same statements, same order, now taking a caller-supplied connection.

---

### Verdict

**New criticals: 0, new highs: 0.** The round-1 High is dead, and it died the
right way.

The reset gate is now the shape it should have been from the start: the
destructive path asks the database whether it consents, not the caller whether
it feels like a developer. All four refusal paths hold, the bypass is no longer
something a routine command performs by accident, and test 26 pins each gate
separately. That closes the finding.

The one Medium is that the marker's notion of "which database" is too coarse to
do the job it was given. `host:port/dbname` is identical for every Supabase
project in a region behind the pooler, so the dump-restore case named in the
docstring — dev snapshot onto production — transfers the grant intact.
`pg_control_system().system_identifier` is readable here and is exactly the
right primitive: unique per cluster, and not carried by a dump. That is a
small change to a function that is otherwise well designed.

The rest is bookkeeping, but two pieces matter more than their severity. The
`COLLATE "C"` fix and the `expires_at` index fix landed in the same diff and
cancelled each other — the indexes are unusable by the only queries they exist
for, so a Low reported fixed is not, and there is now write cost for no read
benefit. And making the reset atomic introduced a lock-order inversion I was
able to turn into a real `DeadlockDetected`. Both are one-line fixes, and both
are the kind of thing that only shows up if you measure rather than read.

R1 High #2 is now effectively closed: at 500 anonymous requests per second the
session table settles at 0.25 GB against a 0.49 GB quota, where before it was
18 GB. Downgrading its residual from Medium to Low — the remaining gap is that
there is still no rate limit anywhere, so a large enough flood gets there
eventually, but it would have to exhaust the web tier first.

Safe to build on once the target fingerprint is widened. Nothing outstanding is
attacker-reachable.

---

## Fix review — 2026-07-26 (fixes for the two R1 highs)

Scope: the fix deltas only, on top of the R1 audit below —
`backend/verify.py` (`looks_like_address` length gate), `backend/app.py`
(chain validation + `_clean_token(address)` on both wallet routes, TTL sweeper
thread), `backend/store.py` (`sweep_expired`), `backend/t.py` (tests 24/25,
transport timeouts 10→30 s, `store.reset()` prologue).

Method: read every changed hunk, then attacked the fixed server on
127.0.0.1:8000. Re-fired the exact High #1 payloads; measured the base58
encoded-length distribution over 200,000 random 32-byte values plus the
extremes of the 32-byte space to test the new gate's bounds for false
rejections; ran a full EVM bind round trip and six real ed25519 keys as
regression; planted expired/live sessions at 1 h, 300 ms and microsecond-0
boundaries and ran the sweep against them; read `pg_constraint` for foreign
keys; measured the database collation's effect on every TEXT timestamp
comparison in the codebase; and traced `t.py`'s new prologue. The suite passes
25/25 twice consecutively per the coordinator; I did not re-run it, because
running it is itself one of my findings.

**Counts (this review): 0 critical / 1 high / 0 medium / 5 low.**

**Status of the two originals: High #1 RESOLVED. High #2 partially resolved —
the permanent/unrecoverable property is fixed, the reachable-peak property is
not; downgraded to Medium.** Evidence for both is recorded inline in the R1
section below, under the original headings.

---

### High (new) — `python backend/t.py` is now a one-command production wipe, and the guard that used to stop it is defeated by the two lines above the call — **RESOLVED**

**Resolution (re-verified 2026-07-26, second fix diff):** fixed the way it
needed to be fixed — the destructive path now interrogates the *target*, not
the caller. `store.reset()` (`store.py:395-423`) requires two independent
gates: `APP_ENV == 'dev'` **and** `disposable()`, which reads a
`registry_meta` marker out of the database in hand and requires it to name that
same database. `t.py:12-31` no longer sets `APP_ENV`; the human must pass it,
and on refusal the suite prints guidance and exits 2. `mark_disposable()` is
exposed only as a deliberate one-off command
(`APP_ENV=dev python backend/store.py mark-disposable`) and is called by
neither `app.py` nor `t.py`.

I enumerated the refusal paths against the live database, patching `_target`
and `_DISPOSABLE_KEY` in my own process so no real marker was touched:

```
APP_ENV unset                          -> refused: "store.reset() is dev-only…"
APP_ENV=production                     -> refused: "store.reset() is dev-only…"
APP_ENV=dev, marker absent             -> refused: "…is not marked disposable"
APP_ENV=dev, marker names another host -> refused: "the disposable marker names X,
                                                    but this connection reached Y"
```

The finding's actual claim was that a *routinely-run* file performed the
bypass, turning two ordinary acts into irreversible loss. That is gone: `t.py`
no longer sets `APP_ENV` and never marks anything, so pointing `backend/.env`
at production and running the suite now refuses instead of destroying —
production has never been marked, and no code path marks it as a side effect.
**High resolved.**

Two residuals, both recorded as new Lows/Mediums in the round-2 section above
rather than left implied: the marker's target fingerprint cannot tell two
Supabase projects apart (Medium), and `mark_disposable()` — the thing that
authorizes destruction — is itself still gated only on `APP_ENV`, granting a
permanent, non-revocable permission (Low).

Original finding retained below.

**Location:** `backend/t.py:17-21`, against `backend/store.py:320-332`.
**Confidence:** certain — mechanism confirmed by reading and by evaluating the
guard predicate under t.py's own prologue. I did not execute it, for obvious
reasons.
**Invariant broken:** the second of the two gates I credited as *verified safe*
in the R1 section below ("Two independent exact-match gates, both failing
closed"). That statement is no longer true, and the bypass now ships in the
repository as a copy-pasteable idiom with a comment endorsing it.

The new prologue runs at import, before any server contact, before any
argument parsing, as the first thing the suite does:

```
t.py:17  # the APP_ENV guard in store.reset() exists to stop production processes.
t.py:18  os.environ["APP_ENV"] = "dev"
t.py:19  sys.path.insert(0, HERE)
t.py:20  import store as st
t.py:21  st.reset()
```

and the guard it satisfies is:

```
store.py:325  if os.getenv("APP_ENV") != "dev":
store.py:326      raise RuntimeError("store.reset() is dev-only — refusing to drop tables")
```

Evaluated with the prologue applied: `os.getenv('APP_ENV') != 'dev'` → `False`,
so `reset()` proceeds and executes
`DROP TABLE IF EXISTS wallet_bindings, auth_nonces, sessions, identities CASCADE`
against whatever `SUPABASE_DB_URL` names. I confirmed `t.py` contains no
reference to `SUPABASE`, `current_database`, or any other check of *which*
database it is about to drop.

The reason this is a High and not a Low footgun is that every precondition is a
documented, recommended workflow, and they compose:

- `CLAUDE.md` ("Testing") gives `python backend/t.py` as the way to test.
- `CLAUDE.md` ("Running locally") and `DEPLOY.md` both tell the operator that
  `SUPABASE_DB_URL` normally comes from `backend/.env`.
- `DEPLOY.md:100-106`'s local-rehearsal step reads the connection string out of
  `backend/.env` with `grep`, i.e. the file is expected to hold a real one.

So the sequence "point `backend/.env` at the production project for an
afternoon of debugging, then run the test suite" — two independently reasonable
acts — irreversibly destroys the durable registry: every identity, every wallet
binding, every in-flight cooling timer, every live session, and any R2
Row-Level Security policy attached to the dropped tables. No confirmation, no
dry run, no target check, no backup step. This is precisely the data R1 exists
to protect, and the change that made the data worth protecting is the same
change that armed the wipe.

This is operator-triggered, not attacker-triggered, and I have ranked
everything else in this audit by exploitability — so I want the reasoning
visible rather than hidden behind the label. I am rating it High on blast
radius and on how ordinary the trigger is, and the coordinator should feel free
to re-rank it. What is not a judgement call is that it **regresses a control I
previously verified as holding**, so it must not be filed as pre-existing.

It also inherits Medium #5 below: the guard cannot see which database it is
pointed at. `t.py` cannot either. Anything that fixes one fixes both — a marker
row written by `init()` and checked by `reset()`, a `current_database()`
allowlist, or an explicit `ALLOW_DESTRUCTIVE_RESET=<dbname>` that must name the
target. A guard on the process's own mutable environment is not a guard against
a caller that sets that environment two lines earlier.

Separately, and much smaller: the fix is solving a real problem the right way
round (the suite genuinely was non-idempotent against durable storage — test 4's
first-time bind used to meet the previous run's rows). The reset itself is the
correct remedy. Only its blindness to the target is the finding.

---

### Low (new) — the TEXT timestamp comparison is *not* lexicographic under this database's collation; the sweep is safe for a different reason than its comment claims, and my own round-1 clearance of `promote_due` was wrong

**Location:** `backend/store.py:420-427` (the comment "all timestamps are
written by `iso(now()+delta)` as ISO-8601 UTC, which orders lexicographically",
and the two `expires_at < %s` predicates), `backend/store.py:607-613`
(`promote_due`'s `activates_at <= %s`).
**Confidence:** certain — measured against the live database.

The database is `en_US.UTF-8` (`datcollate`/`datctype`), the columns carry no
`COLLATE` override, and Postgres compares TEXT under the collation, not
byte-wise. It does not order these strings lexicographically. Measured:

```
'2026-07-26T12:00:00+00:00'        < '2026-07-26T12:00:00.500000+00:00'  -> False  (want True)
'2026-07-26T12:00:00.500000+00:00' < '2026-07-26T12:00:00+00:00'         -> True   (want False)
'2026-07-26T12:00:00.000001+00:00' < '2026-07-26T12:00:00+00:00'         -> True   (want False)
same comparisons COLLATE "C"                                             -> all correct
```

I mapped the blast radius rather than stopping at "it's wrong". Pairing a
timestamp against another at increasing distance, the mis-ordering is confined
to **sub-second** differences and disappears at one second and coarser, in both
directions — `+1 s`, `+10 s`, `+61 s`, `+10 min`, `+1 h`, `+72 h` all compare
correctly. Confirmed independently by the live sweep: a session 300 ms from
expiry was deleted 300 ms early, while a `+1 h` row was correctly kept.

Consequences, all benign, which is why this is a Low:

- `sweep_expired` may reclaim a row up to ~1 s early or late against TTLs of
  300 s and 12 h.
- `promote_due` may complete a **72-hour** cooling period up to ~1 s early. That
  is not a cooling-period bypass in any meaningful sense.
- The comparisons that actually make security decisions — "is this nonce
  expired?" (`consume_nonce`) and "is this session expired?" (`load_session`) —
  are done in Python via `parse()`, which is chronologically exact and
  unaffected. That is the reason the system is safe here, and it is not the
  reason the comment gives.

Two things follow. First, a correction to my own work: in the R1 section below I
cleared `promote_due`'s `activates_at <= now` by reasoning about byte ordering
(`+` is 0x2B, `.` is 0x2E). The bytes were right; the premise that Postgres
compares bytes was wrong. Same conclusion, wrong derivation — recording it so
the next run does not inherit a load-bearing argument that does not hold.
Second, the comment now asserts a property the database does not provide, so
the next person to add a timestamp comparison will trust it. The real fix is
`timestamptz` columns rather than TEXT; `COLLATE "C"` on the two columns is the
cheap interim.

Test 25 cannot catch any of this: it plants rows at ±1 hour, which is exactly
the range where the collation behaves.

---

### Low (new) — the sweep's effectiveness is `rate x TTL`, and an anonymous pre-auth row still gets the full 12-hour authenticated-session TTL

`backend/app.py:270-279` writes `oidc_state` into the session; the middleware
persists it with `SESSION_TTL_HOURS = 12` (`app.py:116`, `:179`). Re-verified on
the fixed server: an anonymous `GET /login` still produces a row with
`TTL=12:00:00` holding nothing but an `oidc_state` that is dead the moment
`/callback` runs, and useless after the OIDC round trip's natural lifetime of
about a minute. Since a sweep can only bound a table at arrival-rate times TTL,
this single constant is what keeps High #2's residual alive (see the arithmetic
under that finding). A short dedicated TTL for pre-auth rows — sixty seconds
would be generous — cuts the reachable steady state by a factor of ~720 for the
one row type an unauthenticated visitor can create. Cheapest available
mitigation by a wide margin.

---

### Low (new) — no index on `expires_at`, so every sweep sequentially scans exactly the table an attacker is growing

`backend/store.py:426-427`; confirmed against the live schema — `sessions` has
only `sessions_pkey (sid)` and `auth_nonces` only `auth_nonces_pkey (nonce)`.
Both DELETEs therefore seq-scan, every 600 s, in one transaction, over the two
tables whose size is the attacker's variable. Under the load that makes the
sweep matter this is millions of rows scanned per cycle and a large delete
holding many row locks. Contention stays low because live rows never match the
predicate, but the scan cost grows with the attack it is defending against —
the wrong direction. A plain btree on `expires_at` for each table makes the
sweep proportional to what it deletes.

---

### Low (new) — the sweeper is the only thing preventing unbounded growth and it hangs off a deprecated hook that fails silently

`backend/app.py:222-224` uses `@app.on_event("startup")`. Verified it still
fires on the pinned FastAPI 0.139.2, but it emits
`on_event is deprecated, use lifespan event handlers instead`. If it is ever
removed by a version bump, the thread simply never starts: no error, no log
line, no failed request, no test failure — the tables just quietly resume
growing forever, which is the exact condition this fix exists to prevent. Given
that the sweeper is now load-bearing for durability, it belongs on the
supported `lifespan` handler. Related: `_sweep_loop` swallows bare `Exception`
by design (correct — a dead sweeper is worse than a noisy one) but logs
nothing, so a sweeper failing every cycle for ten days is indistinguishable from
one working perfectly.

---

### Low (new) — `reset()` is not atomic: the DROP commits before `init()` recreates

`backend/store.py:327-332`. The `DROP TABLE … CASCADE` runs inside its own
`with conn()` block, which commits on exit; `init()` then opens a *separate*
transaction to recreate. Between the two the four tables do not exist, and any
concurrent statement gets `UndefinedTable`. The new sweeper is safe here — its
bare `except Exception: pass` covers it — but concurrent HTTP requests 500,
including the unauthenticated `/api/registry`. Dev-only and transient, and the
SQLite version had the same shape (unlink, then init). Worth one line only
because `reset()` now runs against a shared database that other processes are
actively querying, where before it ran against a local file. Wrapping both in
one transaction closes it.

---

### Verified safe (this fix diff, actively attacked)

- **The `32..44` gate cannot reject a legitimate Solana address.** Measured over
  200,000 random 32-byte values (lengths 42/43/44 only) plus the true extremes
  of the space (`\x00`*32 → 32 chars, `\xff`*32 → 44 chars) and 20,000 real
  ed25519 verify keys (43-44). `[32,44]` is exactly the achievable range.
- **`_clean_token(address)` cannot reject a legitimate address.** EVM is 42
  chars, Solana ≤44, neither contains NUL; the cap is 512. Confirmed live with
  six ed25519 addresses and a full EVM bind round trip returning `200 active`.
- **The sweep cannot delete anything load-bearing.** Live sessions and
  unexpired nonces survive (verified at +1 h). Consumed-but-referenced nonces
  are not a hazard: there is exactly one foreign key in the whole schema
  (`wallet_bindings_identity_id_fkey`), and `proof_nonce`/`proof_sig`/
  `proof_message` are copied into `wallet_bindings` as plain TEXT at
  `create_binding`, so deleting `auth_nonces` rows cannot orphan or cascade into
  verification history. A nonce becomes sweepable only after `consume_nonce`
  would already reject it as expired, so no usable nonce life is shortened.
- **The chain gate closes the last route into the decoder.** `wallet_bind` now
  rejects an unrecognized `chain` as its first statement, so the base58 branch
  is reachable only with `chain == "solana"`, which is then length-gated twice
  (512 via `_clean_token`, 44 via the shape check). The only other
  client-controlled `b58decode` is `verify_solana`'s signature argument, bounded
  to 512 bytes ≈ 0.1 ms.
- **Test 24 is a real test.** Its `elapsed < 6.0` assertion sits between the
  pre-fix cost (>10 s for the trio) and the post-fix cost, so it fails if the
  gate is removed; and the comment correctly explains why the payload is `'z'`
  and not `'1'` (leading `1`s are base58 zero bytes and decode in linear time —
  a `'1'`-based test would pass even with the bug present). Test 25 likewise
  asserts *exactly* which rows survive rather than just counting deletions.
- **The sweeper is safe against `/api/dev/reset` and `t.py`'s reset.** Its bare
  `except Exception: pass` covers both the `UndefinedTable` window described
  above and any pool error; the thread cannot die and take the mitigation with
  it. Multiple instances sweeping concurrently is harmless — the DELETEs are
  idempotent and touch only rows nothing else wants.
- **The R1 findings I cleared before still hold under the fix.** Re-checked that
  the fix diff does not touch `promote_due`'s savepoint logic, `consume_nonce`'s
  `FOR UPDATE`, the generated `address_norm` column, or any unique index. The
  new gates sit strictly in front of existing logic and change no stored value.

---

### Verdict

**New criticals: 0, new highs: 1.** Still not safe to build on, and the reason
has moved.

High #1 is properly dead: gated in three independent places, verified against
the original payloads across a 2000x size range with a flat response curve, and
verified not to reject any legitimate address — I went looking for a false
rejection in the corners of the 32-byte space and there isn't one. That is a
clean fix.

High #2 is the more honest story. The sweeper removes the property that made it
a High — growth is no longer permanent, and recovery no longer needs a human —
but a sweep bounds a table at arrival-rate times TTL, and the fix touched
neither term. Ten unauthenticated requests per second still parks the session
table within a third of the free-tier quota indefinitely. Medium now, and the
two remaining pieces are small: a short TTL for pre-auth rows, and any rate
limit at all.

Against that, the fix introduces a new High of a kind worth stating plainly:
`t.py` now sets `APP_ENV=dev` and calls `store.reset()` at import. The suite
genuinely needed a reset — durable storage made it non-idempotent, and that
diagnosis is right — but the implementation defeats the exact second guard I had
verified as holding one section below, and it does so in the one file a
developer runs most often, with no check of which database it is about to drop.
Two reasonable acts now compose into total irreversible loss of the registry.
Fix that before anything else in this diff, and fix it the same way Medium #5
needs fixing: make the destructive path verify the *target*, not the caller's
own environment variable.

---

## Diff review — 2026-07-26 (R1 keystone: SQLite → Supabase Postgres, _DB_LOCK dropped, real concurrency)

Scope: the uncommitted working tree vs HEAD only — `backend/store.py` (full
rewrite to psycopg3 + `ConnectionPool`, hand-parsed `_conninfo`, restricted
dotenv loader, advisory-lock `init()`, GENERATED `address_norm` + rebuilt
partial unique indexes, `FOR UPDATE` nonce consumption, row-locked
`cancel_pending`, `FOR UPDATE SKIP LOCKED` + savepoint `promote_due`,
`ON CONFLICT` upsert, APP_ENV guard on `reset()`), `backend/app.py`
(`_strip_nul`, `_clean_token`, `looks_like_address` pre-check on bind,
canonical address comparison, `/api/me` batched to one bindings query),
`backend/t.py` (psycopg errors, `%s` placeholders, tests 22/23),
`backend/requirements.txt`, `render.yaml`, `.dockerignore`, `CLAUDE.md`,
`DEPLOY.md`. Prior rounds cleared the crypto/binding/session core; I re-derived
only what the storage swap touches and what losing the process-global lock
exposes.

Method: read every changed hunk plus `verify.py` and `mock_esignet.py` for
reachability. Attacked the running dev server (127.0.0.1:8000, APP_ENV=dev,
working tree, live Supabase dev project) and queried the database directly via
`import store`. Everything below was reproduced, not reasoned about in the
abstract: measured durable-row growth from unauthenticated `/login`; measured
the base58 cost curve locally and over HTTP; raced 4-way concurrent nonce
replay; raced cancel against two concurrent global promoters for 12 rounds;
measured pool contention at 6/20/30 concurrent readers; probed NUL handling on
every text column the request path writes; verified the generated column
rejects direct writes; verified the `reset()` guard against five near-miss
APP_ENV values; verified `sslmode` negotiation and what `verify-ca`/`verify-full`
actually do against this endpoint. `backend/t.py` passed 23/23 before I started.
No code was modified. The only rows I deleted were the 24 `sessions` probe rows
my own growth measurement created.

**One measurement caveat, stated up front:** my client sits on a laptop with
~340 ms round-trip to the Supabase project, so absolute latencies below are
inflated relative to a Render→Supabase same-region deploy. The *contention
ratios* and the *quadratic curve* are environment-independent; the wall-clock
numbers are not, and I flag where that matters.

**Counts: 0 critical / 2 high / 4 medium / 6 low.**

---

### High — one authenticated request with a 1 MB `address` burns ~5 minutes of GIL-held CPU; `_clean_token` caps every field except the one that is parsed — **RESOLVED**

**Resolution (re-verified 2026-07-26, fix diff):** three independent gates now
stand in front of the decoder, and I re-fired the exact payloads that worked
before. `verify.py:96-106` gates `32 <= len(address) <= 44` *before*
`b58decode`; `app.py:420-421` rejects any `chain` outside `('evm','solana')` as
the first statement of `wallet_bind`; `app.py:398` and `app.py:425` apply
`_clean_token` to `address` on both routes. Measured against the fixed server:

```
1 MB address, chain=solana    -> 400 "malformed address"            991 ms
1 MB address, chain=anything  -> 400 "chain must be evm or solana"   632 ms
64 KB address (was 2235 ms)   -> 400 "malformed address"            910 ms
513-char address              -> 400 "malformed address"            875 ms
45-char address               -> 400 "does not look like a valid…"   686 ms
1 MB signature                -> 400 "malformed signature"          860 ms
```

Flat across a 2000x range of payload size — the residual ~600-990 ms is the
session-load/save round trip to Supabase, not decode. The quadratic term is
gone. No regression: 6 real ed25519 verify keys (43-44 chars) accepted, and a
full EVM round trip with a checksummed 42-char address and 132-char signature
returned `200 {"status":"active"}`.

The `32..44` bound is tight, not lossy — I checked it rather than trusting the
comment. Over 200,000 random 32-byte values the encoded length is only ever 42
(2x), 43, or 44; the extremes of the 32-byte space are `\x00`*32 → 32 chars
(the true minimum, since each leading zero byte contributes exactly one `1`) and
`\xff`*32 → 44 chars (the true maximum). 20,000 real ed25519 verify keys were
all 43-44. So `[32,44]` is exactly the achievable range: it cannot reject a
legitimate Solana address. `_clean_token`'s 512-byte cap is likewise
unreachable for legitimate input (EVM 42, Solana ≤44).

The last remaining client-controlled `b58decode` is `verify_solana`'s signature
argument, and it is bounded by `_clean_token` to 512 bytes — ~0.1 ms on the
measured curve. No unbounded decode path survives.

Original finding retained below.

**Location:** `backend/app.py:393` (the `looks_like_address` pre-check this diff
*adds* to the bind path), `backend/app.py:355-364` (`_clean_token` — caps
`nonce` and `signature` at 512 bytes, never `address`), `backend/app.py:391-394`
(`req.chain` is never validated against `('evm','solana')` on this route, unlike
`wallet_nonce` at `:370`), `backend/verify.py:96-102`
(`len(base58.b58decode(address)) == 32`).
**Confidence:** certain — measured locally and reproduced over HTTP.
**Invariant broken:** CLAUDE.md's DoS posture ("expensive unauthenticated
operations", "no rate limits"). The registry has no other single-request
amplifier of this size.

`base58.b58decode` builds a Python bignum one digit at a time, which is
quadratic in input length. `looks_like_address` hands it the raw client string
with no length bound, and pydantic imposes none:

```
   2000 chars ->       1.5 ms
   4000 chars ->       5.6 ms   x3.7 per 2x input
   8000 chars ->      22.0 ms   x3.9 per 2x input
  16000 chars ->      87.7 ms   x4.0 per 2x input
  32000 chars ->     347.6 ms   x4.0 per 2x input
  64000 chars ->    1411.5 ms   x4.1 per 2x input
```

Cleanly quadratic. Extrapolating: a 1 MB request body is ~345 seconds of pure
CPU on one request. Reproduced end to end against the running server:

```
POST /api/wallet/bind {"chain":"anything","address":"z"*16000,...} -> 400 in  871 ms
POST /api/wallet/bind {"chain":"anything","address":"z"*64000,...} -> 400 in 2235 ms
```

`wallet_bind` never checks `req.chain`, so any value other than `"evm"` routes
straight into the base58 branch — `"chain":"anything"` above is what I sent.
Because `wallet_bind` is a sync `def`, it runs in Starlette's threadpool and the
bignum loop holds the GIL, so it starves the whole single process, not just one
worker. Measured: while one 64 KB request ran, an innocent concurrent
`GET /api/me` went from a ~1 ms baseline to **293 ms**.

The auth gate does hold — anonymous callers get 401 in 52 ms, confirmed. But
`render.yaml:14-15` ships `DEMO_MODE=1` as the committed default, and in demo
mode any internet visitor obtains a session in three unauthenticated requests
(`/login` → `/authorize/confirm` → `/callback`). So the practical precondition
is three HTTP requests, and ~40 concurrent 1 MB POSTs pin the process
indefinitely.

What makes this a finding about *this diff* rather than an inherited one: the
diff introduces `_clean_token`, whose entire stated purpose is to "reject the
shapes that cannot be a real nonce or signature before they reach storage… an
oversized value is only ever an attempt to write junk into a durable table" —
and it caps the two fields that were already bounded by their own format checks
while leaving uncapped the one field that feeds an unbounded parser. The same
diff then adds a *second* call site for that parser at `:393`. The hardening and
the widening landed together.

---

### High — R1 deleted the only thing that was reclaiming the unbounded tables, and DEPLOY.md advertises the deletion as the feature — **PARTIALLY RESOLVED, downgraded to Medium**

**Resolution (re-verified 2026-07-26, fix diff):** `store.sweep_expired()`
(`store.py:413-428`) deletes TTL-dead rows from both tables, driven by a daemon
thread started at FastAPI startup that runs on boot and every 600 s
(`app.py:208-224`). Verified working, including the boundary cases test 25 does
not reach: expired-by-1h, expired-by-0.3s and expired-with-microsecond-0 rows
were all deleted; a live +1h row survived; the authenticated session driving my
probe survived. Deleting nonce rows cannot orphan anything — I checked
`pg_constraint` directly and there is exactly one foreign key in the schema
(`wallet_bindings_identity_id_fkey` → `identities`); `proof_nonce`/`proof_sig`/
`proof_message` are copied into `wallet_bindings` as plain TEXT, so verification
history is independent of `auth_nonces`. And a nonce is only ever deletable once
`consume_nonce` would already have rejected it as expired, so the sweep cannot
shorten any nonce's usable life.

**What this fixes is the property that made it a High, and I want to be precise
about that:** the growth was previously *permanent and unrecoverable* — nothing
in the system ever reclaimed a row, and unlike the SQLite era no redeploy or
restart helped. That is genuinely gone. Damage now self-heals within the TTL of
the last row written.

**What it does not fix is the peak.** A sweep bounds a table at
`arrival rate x TTL`, and neither factor was touched: there is still no rate
limit anywhere in the process, and `/login` still mints a row with the full
12-hour session TTL for an unauthenticated visitor whose `oidc_state` is useful
for about sixty seconds — re-verified on the fixed server (`data={'oidc_state':
…}`, `TTL=12:00:00`). The arithmetic at ~910 bytes/row:

```
  10 anonymous /login req/s ->    432,000 rows = 0.37 GB
 100 anonymous /login req/s ->  4,320,000 rows = 3.66 GB
 500 anonymous /login req/s -> 21,600,000 rows = 18.31 GB
        (Supabase free tier quota: 0.49 GB — read-only above it)
```

Ten requests per second — trivially sustainable, well under anything that looks
like an attack — parks the table within a third of the quota indefinitely. So
the outage is still reachable; it is now transient rather than permanent, and
recovery no longer requires a human. Downgrading to **Medium**, tracked with the
two cheap follow-ups in the new Low findings above (short TTL for pre-auth rows;
index on `expires_at`).

Original finding retained below.

**Location:** `backend/app.py:270-279` (`/login` writes `oidc_state` into the
session with no authentication), `backend/app.py:167-185` (the middleware mints
a sid and persists a row whenever the session is non-empty),
`backend/store.py:396-405` (`save_session` upsert), `backend/store.py:385-393`
(the *only* expiry path — lazy, and only when that exact sid is presented
again), `backend/store.py:415-423` (`issue_nonce`; no sweep of `auth_nonces`
exists anywhere in the codebase — I grepped, there is no `DELETE FROM
auth_nonces`), `DEPLOY.md:79-89`.
**Confidence:** certain — measured.
**Invariant broken:** CLAUDE.md's DoS posture ("unbounded tables"). Secondary:
the R1 availability claim itself — quota exhaustion on Supabase flips the
project read-only, and unlike the SQLite era no redeploy or restart recovers it.

A prior run (2026-07-24) rated the `sessions` growth a **Medium**. It was a
Medium because the storage was a file on an ephemeral disk that Render wiped on
every redeploy and every free-tier spin-down — DEPLOY.md said so explicitly, and
the old text called that reset "acceptable — arguably convenient". This diff
removes that reclamation and replaces the paragraph with "**Data now survives
redeploys, restarts and free-tier spin-down**". The garbage now survives too,
and nothing else collects it. Same code, strictly worse consequence: escalating
to High.

Measured on the live database:

```
25 anonymous GET /login  ->  sessions rows 32 -> 57   (delta = exactly 25)
row content: {"oidc_state": "..."}   ~910 bytes/row   12h TTL that nothing enforces
auth_nonces: 251 rows, 246 already expired, 180 already consumed, ~1044 bytes/row
```

246 of 251 nonce rows are dead weight that no code path will ever reclaim. No
rate limiting exists anywhere in the process (grepped: no `slowapi`, no limiter,
no throttle). The cheapest attack needs no session at all: `GET /login` is one
unauthenticated request with no body and writes one permanent row. At ~910 B/row
a Supabase free-tier 500 MB quota is ~576,000 rows. `auth_nonces` needs a
session, which DEMO_MODE hands out for free, and costs ~1044 B/row.

The two tables also feed the availability finding below: every row is a row
`promote_due`'s scans and the session middleware's lookups have to step over.

---

### Medium — a nonce is not bound to the identity that requested it, so a stored proof can attest to a different person than the row it proves

**Location:** `backend/store.py:415-455` (`auth_nonces` has no `identity_id`
column; `consume_nonce` matches on nonce + address + chain only),
`backend/app.py:367-385` (issue), `backend/app.py:388-434` (bind).
**Confidence:** certain — reproduced live against two different Fayda identities.
**Invariant broken:** not non-negotiable #2 as written (the server does reload
the server-stored message and verifies against it — that part is sound), but the
product claim in CLAUDE.md line 9: "Stores only cryptographic proof that a
verified person controls an address." The stored proof and the row can name
different people.

The signed message embeds `Identity: <display_name>` precisely so the wallet
owner can read who they are binding to before signing. Nothing checks that the
session presenting the nonce at bind time is the session the nonce was issued
to. Reproduced:

```
identity A = Meseret Alemu (50576721)   identity B = Hiwot Girma (2ac599f9)
A requests nonce for addr X -> message says "Identity: Meseret Alemu"
A signs it.  B (different Fayda identity, different session) submits it:
  POST /api/wallet/bind -> 200 {"status":"active"}

persisted row on Hiwot Girma:
  identity_id  : 2ac599f9  (Hiwot Girma)
  proof_message: "Identity: Meseret Alemu"    <-- attests the wrong person
  status       : active
```

This does not break the sybil constraint (`address_claimed_by_other` is checked
against the *binding* identity, and I could not get two live claims on one
address by any route). The address-control proof is still cryptographically
sound — B really does control X. What breaks is the evidentiary value: the
registry's durable artifact now says a named verified person consented to a
binding they did not make. The precondition is two Fayda sessions, which is
free in DEMO_MODE and is exactly the sybil-test scenario the personas exist for.

Pre-existing (the nonce never had an identity column), but R1 is what makes the
mis-attesting artifact permanent, and `t.py` has no test for it.

Secondary note on the same message: `identity_label` is the display name, which
is not unique. Two residents with the same name produce byte-identical proof
text modulo nonce, so binding the nonce to the identity id is the only fix that
actually closes this.

---

### Medium — `sslmode=require` encrypts without authenticating; the comment claims a protection libpq does not provide, and `verify-full` is not currently reachable

**Location:** `backend/store.py:180-194`, specifically the comment at `:181-184`
and `kw.setdefault("sslmode", "require")` at `:193`.
**Confidence:** certain — libpq's documented semantics, plus measured behaviour
against this endpoint.
**Invariant broken:** the credential-handling posture the diff sets for itself.

The comment reads: "default `sslmode=require`: 'prefer' would fall back to
PLAINTEXT if a middlebox strips TLS, sending the credential and all registry PII
in the clear." That is half right. `require` does block the passive downgrade.
It performs **no certificate and no hostname verification** — libpq accepts any
certificate the peer presents. An attacker with a network position (hostile
egress, DNS or BGP redirection, a compromised sidecar) presents a self-signed
cert, terminates TLS, relays SCRAM to the real server, and reads and rewrites
every query: the connection credential, every `fin_hmac`, every wallet binding,
and the `sessions` JSONB — which holds the kebele/woreda claims the whole
server-side-session design exists to protect. Rewriting results also defeats the
sybil check, since `address_claimed_by_other` believes whatever comes back.

Measured against this endpoint, values withheld:

```
effective TLS settings: {'sslmode': 'require', 'sslrootcert': None, 'sslcert': None,
                         'sslkey': None, 'sslsni': None, 'channel_binding': None}
sslmode=require      -> CONNECTED
sslmode=verify-ca    -> OperationalError: SSL error (public CA bundle rejects it)
sslmode=verify-full  -> OperationalError: SSL error (public CA bundle rejects it)
```

Worth stating plainly because it changes the remediation: this is *not* a
one-line default change. Supabase's pooler presents a Supabase-issued CA, so
reaching `verify-full` means shipping their root certificate with the image and
pointing `sslrootcert` at it. Until that happens the credential path is
encrypted but unauthenticated, and the comment overstates what is in place.

---

### Medium — `reset()`'s guard reads the process's APP_ENV; it cannot see which database it is pointed at, and the comment claims a guarantee it does not provide

**Location:** `backend/store.py:320-332`, especially the comment at `:322-324`
("a second guard here means no future code path can drop production tables even
by mistake") and `os.getenv("APP_ENV") != "dev"` at `:325`.
**Confidence:** certain — structural; the function has no knowledge of the
target database.
**Invariant strained:** CLAUDE.md "What done means": "Dev surface unreachable
when APP_ENV is not dev." That is satisfied. The claim in the code comment is
not.

The guard itself is well built and I could not defeat it. Verified: `'Dev'`,
`'DEV'`, `'dev '`, `'production'`, `''` and unset all refuse; the route is
additionally inside `if DEV_MODE:` and calls `current(request)` first. Two
independent exact-match gates, both failing closed.

What the guard cannot do is check *where* it is dropping tables. `DROP TABLE …
wallet_bindings, auth_nonces, sessions, identities CASCADE` executes against
whatever `SUPABASE_DB_URL` names. The setup described in this very task —
"a dev server, APP_ENV=dev, connected to the real Supabase dev project" — is the
shape of the hazard: one authenticated POST to `/api/dev/reset` from a laptop
drops four tables in a shared durable database. Under SQLite the blast radius
was a local file that was going to be wiped on the next redeploy anyway. R1
changed the blast radius by three orders of magnitude and the guard did not
change with it. It also takes R2's Row-Level Security policies with it, since
those attach to the dropped tables.

A guard that matched the new blast radius would key on the database (a marker
row, a `current_database()` allowlist, a required `ALLOW_DESTRUCTIVE_RESET`
naming the target), not on the process's own env var.

---

### Medium — the read path saturates a 12-connection pool at ~30 concurrent readers, and the failure lands *after* the response has started

**Location:** `backend/store.py:220-245` (`max_size=12`,
`check=ConnectionPool.check_connection` — a full round trip on every checkout —
`timeout=30`), `backend/app.py:452-457` (`/api/me` takes three sequential
checkouts: `promote_due`, `get_identity`, `bindings_of`),
`backend/app.py:437-440` (`/api/registry` is unauthenticated and runs a *global*
`promote_due()` plus an unpaginated `registry()`), `backend/app.py:167-185`
(`store.save_session` runs inside the ASGI send wrapper, after
`http.response.start`).
**Confidence:** certain for the contention (measured); likely for the
torn-connection failure mode (structural, and the diff's own docstring
describes it).
**Invariant strained:** DoS posture.

Measured against the running server:

```
authenticated GET /api/me, idle baseline           1611 ms
 6 anonymous /api/registry floodors -> /api/me      1756 - 4394 ms
20 anonymous /api/registry floodors -> /api/me      6000 - 6880 ms
30 concurrent authenticated /api/me for 25 s:
   p50 22312 ms   p95 28290 ms   max 28977 ms   throughput 2.0 req/s   (all 200)
```

p95 lands within 1.7 s of the 30 s pool timeout. Re-stating my caveat: the
absolute numbers are inflated by laptop→Supabase RTT (a bare pool checkout plus
`SELECT 1` measured 373 ms here). The structure is not: `/api/me` is three
checkouts deep, each checkout pays a `check_connection` round trip, and the
ceiling is 12 connections. The `/api/me` batching in this diff removed round
trips *inside* one store call while leaving three separate checkouts in place,
so it recovers less than the comment at `:454-456` suggests.

The part that matters when the ceiling is crossed: `store.save_session` is
called from `send_wrapper` after `http.response.start` has been assembled and
before `await send(message)`. A `PoolTimeout` there does not produce a 5xx — it
tears the connection with no HTTP response at all. I observed exactly that
symptom once during probing (`httpx.ReadError: Connection reset by peer` with no
status line). The diff's own `_strip_nul` docstring names this hazard precisely
("it would raise inside the session save — which happens in the ASGI send
wrapper, after the response has started, so the connection is torn and the login
silently fails") and then fixes only the NUL trigger, leaving the far more
likely trigger — pool exhaustion against a remote managed database — in place.

`/api/registry` is the amplifier: unauthenticated, no pagination, returns every
identity with `fin_hmac` (58 identities / 13.7 KB today, unbounded tomorrow),
and holds its pool connection across a global `promote_due()` whose transaction
spans every due pending row.

---

### Low — the NUL boundary is incomplete: three paths still hand raw client/IdP text to Postgres

`_strip_nul` (`backend/app.py:231-248`) is applied only inside `safe_claims`,
which populates `request.session["claims"]`. It does cover the session-save path
completely — I checked every other key that reaches the session (`oidc_state` is
`token_urlsafe`, `identity_id` is a uuid). Three writes bypass it:

- `backend/app.py:314-315` — `display_name=claims.get("name")` and
  `birthdate=claims.get("birthdate")` go to the `identities` INSERT unstripped.
  Confirmed the failure: `psycopg.DataError: PostgreSQL text fields cannot
  contain NUL (0x00) bytes`. Needs a nonconforming IdP, so low, but it is the
  exact hazard the helper was written for and it sits on a durable write.
- `backend/app.py:372-384` — `req.address` is neither NUL-checked nor
  length-checked before `address_claimed_by_other`/`issue_nonce`.
  `"0x" + "\x00"*40` satisfies `looks_like_address` (starts with `0x`, length
  42). Reproduced: `POST /api/wallet/nonce -> 500 Internal Server Error`.
  No data impact, no partial write, but an unhandled 500 any authenticated
  caller can trigger with two JSON fields.

---

### Low — `wallet_bind` never validates `req.chain`

`backend/app.py:389-394`. `wallet_nonce` checks `req.chain not in ("evm",
"solana")` at `:370`; `wallet_bind` does not. Today it fails closed by accident
— an unknown chain finds no matching nonce and 400s at `consume_nonce`, and the
table's `CHECK (chain IN ('evm','solana'))` backstops the INSERT. But "safe
because an unrelated lookup happens to miss" is the kind of guarantee that stops
holding when someone reorders the function, and it is what routes the base58
payload in the first High into the quadratic branch.

---

### Low — `promote_due` catches only `UniqueViolation`; a deadlock or serialization failure 500s an unauthenticated endpoint

`backend/store.py:641-656`. The savepoint handler catches
`psycopg.errors.UniqueViolation` and `_NotPending`. `DeadlockDetected` and
`SerializationFailure` propagate out of the loop and out of `with conn()`,
which is correct-by-accident (the whole thing is one transaction, so it rolls
back cleanly with no partial state) but surfaces as a 500 on `/api/registry`
and `/api/me`. I raced two concurrent global promoters against a cancel for 12
rounds and produced no deadlock and no exception, so this is theoretical today.
Recording it because `ORDER BY id` was chosen specifically to avoid deadlocks
and the handler does not cover the case it is guarding against.

---

### Low — `_conninfo` unquotes unconditionally; `_load_dotenv` handles neither quotes nor `export`

`backend/store.py:159-194` and `:140-156`. The parser is genuinely better than
`urllib.parse` for this job — I confirmed it handles `/`, `?`, `@` and `:` inside
the password correctly, which is the stated reason it exists. Two residual
sharp edges, both failing closed but with misleading errors:

- `unquote(user)` / `unquote(password)` run unconditionally, so a password
  containing a literal `%41` is silently rewritten to `A`. That is precisely the
  "mangled password shows up only as a confusing auth failure" the docstring
  says the function exists to prevent.
- `_load_dotenv` does not strip surrounding quotes (`SUPABASE_DB_URL="postgres://…"`
  → `RuntimeError: must be a postgresql:// URL`) and does not handle a leading
  `export ` (key becomes `export SUPABASE_DB_URL`, misses the allowlist, and the
  app reports the variable as unset). Both are startup-time and loud enough to
  diagnose, just not from the message.

---

### Low — the OIDC `nonce` is minted, sent, and never verified

`backend/app.py:273` generates a `nonce`, puts it in the authorize URL, and
never stores it. There is no ID token in this flow — the app authenticates
purely on `code` → `access_token` → `userinfo` — so nothing is currently broken.
Flagging it for B1: when real Fayda credentials arrive and an `id_token` comes
back, that nonce must be persisted at `/login` and checked against the token's
claim, or the replay protection the parameter exists for is decorative.

---

### Low — pre-existing findings from earlier runs, unchanged but now costlier

Neither is introduced by this diff; both change character under R1 and neither
has a test:

- **Logout is not atomic** (prior run, 2026-07-24). `save_session` is still an
  upsert (`store.py:396-405`) and `delete_session` a plain DELETE (`:408-410`);
  a request in flight when `/logout` runs still re-inserts the row. Unchanged.
- **Every authenticated request rewrites its session row** (prior run). Still
  true at `app.py:179`, and each rewrite is now a remote round trip rather than
  a local file write, which is part of why `/api/me` costs three checkouts.

---

### Verified safe (actively attacked, held)

These are the things I tried hardest to break and could not. Next run should
spend its budget elsewhere.

- **The sybil constraint is now enforced by the database in a way application
  code cannot escape.** `address_norm` is `is_generated: ALWAYS` with expression
  `CASE WHEN chain='evm' THEN lower(address) ELSE address END`, and Postgres
  rejects a direct write: `GeneratedAlways: cannot insert a non-DEFAULT value
  into column "address_norm"`. All four partial unique indexes are present on
  the live database and keyed correctly (`ux_active_chain_address` and
  `ux_pending_chain_address` on `(chain, address_norm)`). I could not produce
  two live claims on one address by any route: case-variant races, 4-way
  concurrent replay, and cross-identity pending all resolved to exactly one live
  row. This is the strongest part of the diff — moving the canonical form into
  the schema means no future code path can fork a row on case.
- **Nonce single-use holds under real concurrency.** `t.py` test 7 only tests
  *serial* replay, which the old global lock made trivial. I fired 4 threads at
  one nonce through a `threading.Barrier`, 5 rounds: every round returned
  `[200, 400, 400, 400]` with exactly 1 live binding row. `SELECT … FOR UPDATE`
  plus the `consumed` re-check inside one transaction is doing its job — the
  losers block, then re-evaluate under READ COMMITTED and see `consumed=1`.
- **The cooling period survives a harder race than test 23 runs.** Test 23 races
  cancel against one promoter. I raced cancel against **two** concurrent global
  promoters, 12 rounds: zero broken end-states, zero exceptions. Every round
  ended with exactly one active wallet, and the two legal outcomes were the only
  ones observed (cancel wins → replacement `cancelled` + incumbent `active`;
  promote wins → replacement `active` + incumbent `archived`). No resurrection
  of a cancelled row, no identity left with zero active wallets. The `FOR UPDATE`
  + `AND status='pending'` belt-and-braces and the savepoint rollback of the
  incumbent archival are both load-bearing and both correct.
- **`init()`'s dupe-cancel UPDATE cannot cancel a row it shouldn't.** Its
  partition key `(chain, address_norm, status)` is *identical* to the two partial
  unique indexes' keys, so on an index-consistent database the `rn > 1` set is
  provably empty — verified empirically on the live database: **0 rows it would
  cancel right now**. It only ever bites during the one-time migration, and there
  it produces exactly the outcome the index would have produced. The advisory
  xact lock correctly serializes concurrent boots, and the stale-index detection
  (`indexdef NOT LIKE '%address_norm%'`) is the right predicate.
- **The `reset()` guard is exact-match and fails closed on every near miss.**
  `'Dev'`, `'DEV'`, `'dev '`, `'production'`, `''`, unset — all refused. Two
  independent gates (route registration under `if DEV_MODE:` plus the in-function
  check) plus `current(request)` first. My finding above is about blast radius,
  not about this guard leaking.
- **The credential does not leak into responses, the repo, or the image.**
  `backend/.env` is untracked and matched by `.gitignore:6`; no `.env` has ever
  been committed on any branch (checked all refs). `.dockerignore` now carries
  `**/.env` and `**/.env.*`, which do match `backend/.env` and
  `frontend/.env.local` under Docker's matcher, and the Dockerfile's
  `COPY backend/ backend/` therefore cannot bake it in. FastAPI's default handler
  returns a bare `Internal Server Error` body with no exception detail —
  confirmed by forcing a live psycopg failure. libpq error text includes host and
  port but scrubs the password, and `psycopg_pool` logs `self.name`, not the
  conninfo. `render.yaml` sets `sync: false`, so the value is never in the
  blueprint.
- **The dotenv allowlist actually holds.** `_DOTENV_ALLOWED` is a
  `frozenset({"SUPABASE_DB_URL"})` and the check is
  `if k in _DOTENV_ALLOWED and k not in os.environ`. A `.env` that reaches a
  server cannot flip `APP_ENV`, plant `SESSION_SECRET`/`FIN_PEPPER`, or override
  a real env var. This is the right design and it is implemented correctly.
- **Raw FIN.** Re-derived under the new storage. `sub` is hashed at
  `app.py:212` before anything persists it; `SAFE_CLAIMS` excludes `sub`,
  `phone`, `picture`; `display_name`/`birthdate` are the only claim-derived
  columns and neither is `sub`. Nothing in `store.py` writes a raw FIN, no
  logging statement exists in either file, and tracebacks do not print locals.
  `t.py` 3b/3c still pin the response-body and cookie cases and pass.
- **Server-stored message verification (non-negotiable #2).** `consume_nonce`
  returns the stored `message` and `wallet_bind` passes *that* to `vf.verify`;
  the client's copy is never read. Unchanged by this diff and still correct — the
  cross-identity finding above is about *whose name is in* the stored message,
  not about which message is verified.
- **`/api/me`'s batching is semantically equivalent.** `one(status, chain)`
  slices `history()` (ordered `requested_at DESC`) instead of querying. The
  partial unique indexes guarantee at most one `active` and one `pending` per
  `(identity, chain)`, so "first match" and "the row" are the same row. No
  behaviour change, and `promote_due` still runs before the read.
- **`upsert_identity`'s `ON CONFLICT` handles the concurrent-first-login race.**
  Read-then-insert with `ON CONFLICT (fin_hmac) DO UPDATE … RETURNING *` means
  the loser blocks on the winner's uncommitted row, then lands on it rather than
  raising. Correct fix for the case the comment names.
- **`SET search_path TO public` in `configure` is applied per connection** and
  the pool runs it on every new connection, so `reset()`'s DROP cannot resolve
  into Supabase's `auth` schema. (Note for the operator: this depends on a
  *session*-mode pooler string, which `DEPLOY.md` correctly specifies.)

---

### Verdict

**New criticals: 0, new highs: 2.** Not yet safe to build on — but the reason is
availability and operational blast radius, not correctness.

The correctness core of R1 is good, and I want to be clear about that because it
is the part that was hardest to get right. Losing `_DB_LOCK` did not break a
single invariant I could reach: the sybil constraint is stronger than it was
(the generated column makes it unforgeable from application code), nonce
single-use survives concurrent replay, and the cancel-versus-promote race
holds under twice the pressure `t.py` applies. Tests 22 and 23 are real tests.

What is not ready is everything around the data. Two High findings, both of
which are the same mistake in different clothes: a change that made storage
durable did not revisit the assumptions that depended on it being disposable.
The unbounded tables were survivable when a redeploy wiped them, and the diff
deletes that mitigation while documenting the deletion as a feature. `reset()`'s
guard was sufficient when it dropped a local file, and now it drops a shared
database it cannot identify. The quadratic-parser DoS is the odd one out —
genuinely introduced here, by a hardening helper that capped every field except
the one that gets parsed.

Fix the two Highs and the `reset()` blast radius before this takes real traffic.
The `sslmode` and nonce-identity findings can follow; both need design decisions
(ship Supabase's CA; add `identity_id` to `auth_nonces`) rather than patches.

---

## Diff review — 2026-07-24 (Render/Docker deploy: Secure cookie, SPA catch-all, DEMO_MODE, /config.js)

Scope: the uncommitted deploy deltas only — `backend/app.py` (Secure cookie on
set+delete, DEMO_MODE, SPA static serving + catch-all, `/config.js`, origin
derivation from `RENDER_EXTERNAL_URL`/`PORT`), `backend/verify.py` (env-derived
URI/DOMAIN + `expires_at` message line), `backend/t.py` (tests 19/20),
`frontend/vite.config.js`, `frontend/index.html`, `frontend/src/wallet/index.jsx`,
and the new `Dockerfile`, `.dockerignore`, `render.yaml`, `DEPLOY.md`. Prior
rounds cleared the crypto/binding/session core; I re-derived only these deltas
and attacked each one live.

Method: read every changed hunk and the four new files. Ran the suite on a fresh
DB (`APP_ENV=dev python app.py` + `python t.py`): **ALL 20 CHECKS PASSED**. Stood
up a production DEMO instance (`APP_ENV=production DEMO_MODE=1` + secrets, dist
present) and a plain-production instance, then attacked: path traversal
(`../`, `%2e%2e`, double-encoded, backslash, nested, against both the catch-all
and the `/assets` mount), API-route shadowing, `Host`/`X-Forwarded-Host` header
influence on origin derivation, `/config.js` injection, the full persona→cookie→
`/api/me`→logout round trip (sid sent manually, since a Secure cookie won't ride
an http jar), the secrets guard under DEMO_MODE, and the mock `/authorize`
reflection. Killed :8000/:10000/:10001 and removed the test DB after.

**Counts: 0 critical · 0 high · 1 medium (now RESOLVED) · 2 low.**

### Medium — `render.yaml` ships `DEMO_MODE=1` by default, publishing the mock IdP's reflected XSS (and open redirect) to the public internet — **RESOLVED**

**Resolution (re-verified 2026-07-24):** `backend/mock_esignet.py` now
`html.escape(..., quote=True)`s all four reflected sinks — `redirect_uri`,
`state`, `nonce` in the hidden-input attributes (`:151-155, :168-170`) and
`scope` in the footer (`:244`) — and validates `redirect_uri` via
`_valid_redirect` (`:103-118`) at BOTH the GET `/authorize` (`:154`) and the POST
`/authorize/confirm` (`:254-256`) handlers, rejecting anything whose path is not
exactly `/callback` or whose scheme is not `('', 'http', 'https')`. Re-verified
empirically on a running instance, not just via the test: an XSS payload in
`state`/`scope`/`redirect_uri` comes back with **0 live `<script>` and 5 escaped
`&lt;script&gt;`**; `redirect_uri=https://evil.example.com/phish` → **400 at both
handlers**; `javascript:alert(1)` → 400; `/callback/../evil` → 400. Full suite
**21/21 on a fresh DB** (test 21 pins the escaping and the foreign-path
rejection). The reflected-XSS surface is closed. Original finding retained below
for the record.

**Residual (low, inconsequential in the demo): the redirect check is
path-only, so `https://evil.example.com/callback` and protocol-relative
`//evil.example.com/callback` still validate** — I confirmed `authorize_confirm`
303s the `code` to `https://evil.example.com/callback?code=...&state=...`. This is
a restricted open redirect (target path must be exactly `/callback`), and it does
**not** matter here: the leaked authorization `code` is unexchangeable without the
`private_key_jwt` client assertion, which is signed with a server-held key
generated at startup and never leaves the process, and the `code` maps only to a
mock persona that anyone can select via `/login` anyway — so there is no code
theft of value and no privilege gain, and there is no XSS (the redirect is a
`Location` header, not reflected HTML). Worth one line only because a **real**
Fayda deployment must match the full registered `redirect_uri` (host **and**
path), not just the path — this mock's path-only check would be insufficient once
the codes it mints have real value. Not a live break in the mock demo.

### Medium — `render.yaml` ships `DEMO_MODE=1` by default, publishing the mock IdP's reflected XSS (and open redirect) to the public internet — original finding

**Location:** `render.yaml:16-18` (`DEMO_MODE: "1"`), reflection at
`backend/mock_esignet.py:139-142` (hidden-input `value="..."` for
`redirect_uri`/`state`/`nonce`) and `:216-217` (`scope` into text); open redirect
at `backend/mock_esignet.py:221-230` (`authorize_confirm` 303s to the
client-supplied `redirect_uri`); mount gate at `backend/app.py:204-205`.
**Confidence:** certain (reproduced live on the DEMO instance).
**Invariant strained:** not a CLAUDE.md non-negotiable, but the deploy brief's
"blast radius if it ships" — the mock is dev surface, and `DEMO_MODE` is exactly
the switch that ships part of it.

Prior rounds rated this mock `/authorize` reflected XSS a **dev-only Low**
("cannot ship — the mock router mounts only under `DEV_MODE`"). This diff changes
that premise. The mount is now `if DEV_MODE or DEMO_MODE` (`app.py:204`), and
`render.yaml` sets `DEMO_MODE: "1"` as a committed default, so **every Blueprint
deploy that follows `DEPLOY.md` serves the mock IdP on its real public HTTPS
origin** — the same origin as the wallet-connecting SPA.

Reproduced against the running DEMO instance (unauthenticated):

```
GET /authorize?client_id=fayda-wallet-demo&response_type=code
    &redirect_uri="><script>alert(document.domain)</script>&state=x&nonce=n
->  ...name="redirect_uri" value=""><script>alert(document.domain)</script>">
```

The injected `"><script>` breaks out of the attribute and executes same-origin.
`client_id=fayda-wallet-demo` and `response_type=code` are the only gates
(`mock_esignet.py:130-133`); both are the documented public defaults, visible in
the `/login` redirect. So the link is attacker-craftable and needs no session.

Blast radius, stated honestly, is what keeps this a medium not a high: the deploy
is by explicit design a **throwaway mock demo** — the identities are shared public
personas, the "FIN" is a mock constant (no real FIN ever reaches this origin), the
session cookie is `HttpOnly` (the script cannot read it), the DB resets every
redeploy, and `/api/dev/*` is *not* reachable in DEMO (confirmed — reset/
fast-forward/test-wallet all 404, and the secrets guard still refuses to start
without `SESSION_SECRET`/`FIN_PEPPER`). The realistic worst case is arbitrary JS
in a visitor's browser on the genuine registry domain: phishing UI, driving the
victim's own authenticated `/api/*` calls, or prompting the victim's connected
wallet for an unexpected signature/transaction (user-gated by the wallet prompt;
`personal_sign` proves control, it does not move funds). The paired open redirect
(`authorize_confirm` → arbitrary `redirect_uri` with a valid `code`+`state`) is
the same dev surface now public; the `code` maps only to a mock persona, so its
value is low. **This becomes critical the instant the demo framing is copied
toward a real login page or the origin is treated as more than a throwaway** —
escape `redirect_uri`/`state`/`nonce`/`scope` before that ever happens. Fix
direction (not applied): HTML-escape the reflected params in the mock authorize
page regardless of gating; and if the public demo does not actually need the mock
mounted, reconsider shipping `DEMO_MODE=1` by default.

### Low — `.dockerignore` excludes only `frontend/.env.local`, not `backend/.env` or a root `.env`

**Location:** `.dockerignore` (pattern list).
**Confidence:** certain (dockerignore emulation) — but no such file exists today
and the backend loads no dotenv, so it is latent, not live.
`**/registry.db*` and `frontend/.env.local` are covered (verified: both are
excluded from the build context, so `registry.db`/`.env.local` stay out of the
image, as the brief requires). But a `backend/.env` or a repo-root `.env` would
**not** be matched and would be copied in by `COPY backend/ backend/`. Today this
is inert: no such file exists, and `app.py` reads secrets from real env vars
(`os.getenv`), not a dotenv file, so even a stray `.env` would not be loaded.
Flagging only as hardening — broaden to `**/.env*` (with `!frontend/.env.example`
if that must ship) so a future `.env` cannot be baked into a layer. Not a bug in
this diff.

### Low/info — `/api/me` advertises `demo`, `dev`, and `public_origin` to unauthenticated callers

**Location:** `backend/app.py:415-416`.
The unauthenticated branch now returns `demo`, `dev`, and `public_origin`. This is
intended: the SPA uses `public_origin` to detect a `PUBLIC_URL` misconfiguration
and `demo`/`dev` to gate affordances. `public_origin` is deployment-controlled
config (env-only — see verified-safe), `dev` is `false` in every production
posture, and `demo` merely says "this is the mock-persona demo," which the login
screen already announces. No security decision hinges on any of them. On record;
not a bug.

### Verified safe (actively attacked, held)

- **Secure cookie, both paths, dev unchanged.** In a production posture the
  `Set-Cookie` on the login-rotation set path (`app.py:182-184`) AND the logout
  delete path (`app.py:188-192`) both carry `Secure`, alongside `HttpOnly`,
  `SameSite=Lax`, `Max-Age=0` on delete. Verified end to end on the DEMO instance
  with a manual sid: `/login` set → `Secure`; post-callback rotate → `Secure` and
  the sid changed (fixation rotation intact); `/logout` delete → `Secure`+`Max-Age=0`
  and the old sid no longer authenticates. `SameSite=Lax` still lets the top-level
  `/callback` navigation carry the cookie (the round trip completed). In dev
  (`DEV_MODE` true) neither path appends `Secure`, so an http localhost jar still
  works and `t.py`'s single-origin flow is unaffected. The opaque-sid + HMAC +
  server-side design is untouched — only the attribute string changed.
- **No API route is shadowed by the SPA catch-all.** The catch-all
  (`app.py:563`) is registered last; every real route — `/login`, `/callback`,
  `/logout`, all `/api/*`, `/config.js`, the `/assets` mount, and the mock router
  when mounted — is registered earlier and wins by order. Confirmed live: unknown
  `/api/foo` → 404 JSON (`{"detail":"not found"}`), not the HTML shell; unknown
  GET page → 200 index.html; `/config.js` → the JS, not the shell; DEMO `/authorize`
  → 200 mock page; plain-prod `/authorize` → 404. A non-GET/HEAD to any unmatched
  path → 404 (not 405), matching the pre-SPA behaviour the comment claims.
- **Path traversal cannot escape `dist`.** `../backend/app.py`, `../../etc/passwd`,
  `%2e%2e/...`, double-encoded `%252e%252e`, backslash, and nested `foo/../../...`
  all returned **index.html (200), never the target file's bytes** — the
  `resolve()` + `is_relative_to(DIST.resolve())` guard rejects the escape and falls
  through to the shell. The `/assets` StaticFiles mount 404s traversal outright
  (Starlette's own check). No file outside `dist` was served by any vector tried.
- **Origin derivation is env-only; no request can influence it.** `PUBLIC`
  (`app.py:51-53`) and `BASE` (`:48`), and `verify.py`'s `URI`/`DOMAIN`
  (`verify.py:24-30`), read only `PUBLIC_URL`/`RENDER_EXTERNAL_URL`/`BASE_URL`/`PORT`
  from the environment. Spoofing `Host: evil.attacker.com` (and adding
  `X-Forwarded-Host`) changed neither `public_origin` in `/api/me` nor the `/login`
  redirect `Location` — both stayed the configured origin. The signed message's
  stated URI is display-only anyway: verification always runs against the message
  reloaded from `consume_nonce`, never a rebuilt one, so URI/DOMAIN/`expires_at`
  cannot alter a verification outcome.
- **`/config.js` has no injection path.** The value is emitted via `json.dumps`,
  which produces a correctly-escaped JS string literal (quotes, backslashes,
  newlines, and non-ASCII incl. U+2028/2029 all escaped). It is served as an
  **external** script (`<script src="/config.js">`), so a `</script>` in the value
  cannot break HTML parsing. `PRIVY_APP_ID` is deployment-controlled (env, not
  attacker input) and is a documented public identifier; `render.yaml` sets it
  `sync: false` (manual), so no generated secret lands there.
- **DEMO_MODE does not reach the destructive dev surface and does not weaken the
  guards.** `/api/dev/reset`, `/api/dev/fast-forward`, `/api/dev/test-wallet` are
  gated by `if DEV_MODE:` alone (`app.py:461`) — all three 404 in DEMO (verified,
  and pinned by new test 20). The secrets guard (`app.py:90-98`) is keyed on
  `not DEV_MODE`, so DEMO still refuses to start without `SESSION_SECRET`/
  `FIN_PEPPER` (verified: `RuntimeError: refusing to start`). H1/H2/H3 remain
  closed under DEMO.
- **Provenance persists (test 19 backs it).** `create_binding` now names
  `proof_method` in both the column list and `VALUES` (`store.py:322-329`),
  `consume_nonce` returns the server-recorded `issued_via` (`store.py:249`), and
  `wallet_bind` passes it through (`app.py:390`). The prior round's Medium (silent
  default to `'wallet'`) is resolved, and test 19 asserts the persisted value.
- **Dockerfile / render.yaml / DEPLOY.md match the code.** Multi-stage build
  (Node build → python-slim runtime, no Node in runtime); `CMD uvicorn app:app
  --host 0.0.0.0 --port ${PORT:-10000}` with `BASE` derived from the same `PORT`,
  so the OIDC self-calls match the listen port; `healthCheckPath: /api/me` returns
  JSON with `demo: true` (verified); `PUBLIC_URL` left unset so the origin derives
  from `RENDER_EXTERNAL_URL` (verified: DEMO `/login` → `https://demo.example.com/
  authorize`). `SESSION_SECRET`/`FIN_PEPPER` `generateValue`, `PRIVY_APP_ID`
  `sync:false`. Consistent.
- **t.py green on a fresh DB — 20/20**, including the new provenance (19) and
  DEMO-mode gating + Secure-cookie + `RENDER_EXTERNAL_URL` derivation (20). No raw
  FIN in the prod server log or any `/api/me` body across the DEMO round trip; the
  claims echoed are only the whitelist (`name`, `birthdate`, `gender`,
  `residenceStatus`, `address`).

### Verdict

Safe to build on — **yes**, with respect to these deploy deltas. The Secure-cookie
change is correct on both set and delete and leaves dev untouched; the SPA
catch-all shadows no API route and its traversal guard holds against every vector
tried; origin derivation is strictly env-only; `/config.js` cannot inject; and
DEMO_MODE neither reaches the destructive dev endpoints nor weakens the secrets
guard or the FIN whitelist. The one substantive item — the mock IdP's reflected
XSS / open redirect, now exposed on a real public origin because `render.yaml`
ships `DEMO_MODE=1` by default — has been **fixed and re-verified in this pass**:
all four reflected params are HTML-escaped and `redirect_uri` is constrained to
`/callback` at both handlers (21/21, plus direct probes showing the payload
escaped and foreign paths 400ing). The only residual is a path-only redirect check
that still permits `<any-host>/callback`; it is inconsequential in the mock demo
(the leaked code is unexchangeable without the server-held client-assertion key
and maps only to a public persona) but must become a full host+path match if real
Fayda credentials ever replace the mock. Pre-existing mediums (unbounded
`sessions`/`auth_nonces`, write-on-read under the global lock, non-atomic logout,
M4 migration hazard) remain open and untouched by this diff.

New criticals: 0, new highs: 0.

---

## Diff review — 2026-07-24 (Privy React/Vite frontend rebuild + backend provenance deltas)

Scope: the uncommitted working tree — the frontend rebuilt as React + Vite +
Tailwind with a Privy wallet connector (`frontend/src/**`, all new), plus five
backend deltas (`verify.py` env-derived DOMAIN/URI + `expires_at`; `store.py`
`issued_via`/`proof_method`; `app.py` provenance plumbing + `public_origin`;
`mock_esignet.py` cosmetic label). Prior rounds cleared the backend core; I
re-derived only the deltas and independently attacked the Privy seam, the
origin split, the bind byte-path, and the provenance plumbing.

Method: read every changed backend hunk and every hand-written frontend source
file; grepped `src/` for off-origin sinks, `@privy` imports, and any storage of
identity data; traced the personal_sign byte-path against `encode_defunct`;
read `App.jsx sign()` for the cancel guard. Live: killed the stale :8000
server, deleted `backend/registry.db` (schema changed), started `APP_ENV=dev
python backend/app.py` with **PUBLIC_URL unset**, ran `python backend/t.py`:
**ALL 18 CHECKS PASSED**. Then reproduced the one real finding empirically by
inspecting `proof_method` against each binding's originating nonce.

**Counts: 0 critical · 0 high · 1 medium · 2 low.**

### Medium — `proof_method` is never persisted; every binding is silently recorded as `'wallet'`, defeating the exact anti-masquerade purpose of this diff — **RESOLVED**
**Resolution (re-verified 2026-07-24):** the INSERT in `create_binding`
(`backend/store.py:321-327`) now names `proof_method` in both the column list
and the `VALUES` clause; the root cause was a whitespace-mismatched patch that
had silently failed to update the SQL. `backend/t.py` gained test 19 asserting
the **persisted** value. Re-verified independently of the test: a fresh run on a
recreated DB passes **19/19**, and a direct read of `registry.db` shows the 3
bindings whose nonce `issued_via='dev-test-key'` now persist
`proof_method='dev-test-key'` while real-wallet nonces persist `'wallet'` — the
audit trail now distinguishes them. Original finding retained below for the record.

**Location:** `backend/store.py:294-342` (`create_binding` INSERT), schema
`store.py:45`
**Confidence:** certain (measured)
**Invariant broken:** the stated purpose of the store.py/app.py delta —
*"Recorded server-side at issue time so a test-key binding can never masquerade
as a real wallet attestation in the audit trail"* (`store.py:80-82`).

`create_binding` gained a `proof_method` parameter, threads
`issued_via` through from `consume_nonce`, and puts `"proof_method":
proof_method` into the `row` dict — but the `INSERT INTO wallet_bindings (…)`
column list (`store.py:321-325`) was **not** updated to include the column, and
neither was the `VALUES (…)` list. sqlite3 named-parameter binding silently
ignores the extra `row` key, so the column always falls back to its schema
`DEFAULT 'wallet'`. Every binding — including dev-test-key ones — records
`proof_method='wallet'`. The server-derived provenance is computed correctly
and then dropped on the floor.

Reproduced live after the fresh t.py run: the first three bindings were produced
by nonces whose `issued_via='dev-test-key'`, yet all three persisted
`proof_method='wallet'` (verified by joining `wallet_bindings.proof_nonce` to
`auth_nonces.issued_via`). Every row in the table read `proof_method='wallet'`
regardless of origin. A test-key binding is therefore indistinguishable from a
real wallet attestation in the audit trail — precisely the masquerade the delta
was written to prevent.

Scope of impact, stated honestly: this breaks a **diff-local** goal, not a
CLAUDE.md non-negotiable. The one property that IS sound is that provenance is
server-derived, not client-claimed — the client never sends `proof_method`;
`wallet_bind` passes the server-recorded `issued_via` (verified). And in
production the dev-test-key path does not exist (`DEV_MODE` off → route
unregistered), so all real bindings genuinely originate from wallets and
`'wallet'` is coincidentally correct — there is **no production data-integrity
consequence and no attack**. What makes it a medium rather than a low: it is a
security-relevant safeguard that silently does nothing, it fails without error
(the bind still returns 200), and — against the CLAUDE.md convention *"New
invariants get a test in t.py; a test that cannot fail is not a test"* — the new
provenance invariant ships with **no test**, which is exactly why a broken
INSERT reached this audit. An audit trail that cannot tell a real attestation
from a throwaway is a false assurance. Fix direction (not applied): add
`proof_method` to both the column list and the `VALUES` clause, and assert in
t.py that a `/api/dev/test-wallet` binding stores `proof_method='dev-test-key'`.

### Low — Privy's SDK runs same-origin and can read the DOM-rendered claims (neighbourhood PII + `fin_hmac`); inherent third-party exposure, no app-introduced sink
**Location:** `frontend/src/wallet/index.jsx:36-52`, `components/IdentityRecord.jsx:63-70`
**Confidence:** certain (that the surface exists); the leak is latent, not observed
The Privy provider is a first-party React component; its bundle executes in the
main page context, same-origin with the SPA. `IdentityRecord` renders the full
`me.claims` blob (name, birthdate, `residenceStatus`, `address.{kebele, woreda,
region, zone}` — neighbourhood-level location) and `fin_hmac` into the DOM. Any
same-origin script, Privy's included, can in principle read that DOM; Privy also
loads cross-origin iframes/config from its own hosts. Two mitigations make this a
low, not a high: (1) the **raw FIN never reaches the browser** — worst-case DOM
scraping yields only the whitelisted claims (already the owner's own data) plus
the peppered HMAC, so non-negotiable #1 is intact; (2) the app introduces **no
sink of its own** — it passes Privy only `appId` + static config, never identity
data, and the HttpOnly `session` cookie is unreadable to any script (confirmed:
the only `localStorage` write is the theme; the only `fetch` is `api.js` on
relative paths; the only `@privy` import is the seam module). This is the
inherent cost of loading a third-party connector on a page that also displays
PII, not a bug in this diff. On record so a future hardening pass can consider
rendering the neighbourhood claims lazily / behind the connector, or isolating
Privy, if the PII sensitivity warrants it.

### Low — mock `/authorize` reflected XSS persists (unchanged, dev-only)
**Location:** `backend/mock_esignet.py` authorize page
**Confidence:** certain (dev-only)
The delta to `mock_esignet.py` is a one-word label change; the prior-round
reflected-XSS in the authorize page (unescaped `state`/`nonce`/`redirect_uri`/
`scope`) is untouched and still present. The whole mock router mounts only under
`DEV_MODE` (t.py test 13 confirms 404 in production), so it cannot ship, and the
Vite proxy still raises its blast radius to the SPA origin in a dev run. No
change from the prior record; re-flagged only because the file was in this diff.

### Verified safe (actively attacked, held)

- **The bind byte-path cannot be diverted.** `signEvm` hex-encodes the UTF-8
  bytes of the server message and `personal_sign`s them (EIP-191); the backend
  `encode_defunct(text=message)` prefixes the identical UTF-8 bytes. More
  decisively: `wallet_bind` verifies against the message it **reloaded from
  `consume_nonce`**, never the client's copy — so even a frontend that signed
  different bytes would simply fail verification. Non-negotiable #2 holds
  regardless of frontend behaviour. The crypto in `verify.py` (secp256k1
  `recover_message`, ed25519 `VerifyKey.verify`) is byte-identical to prior
  rounds (confirmed by diff) — only DOMAIN/URI derivation, `expires_at`, and
  copy changed.
- **The client cannot claim binding provenance.** `wallet_bind` passes the
  server-recorded `issued_via` from `consume_nonce` as `proof_method`; no client
  field feeds it. A dev-test-key nonce can never be bound as `'wallet'` by client
  request. (It is never bound as `'dev-test-key'` either — see the Medium — but
  the *client-can't-claim-it* property is intact.)
- **No off-origin exfiltration; nothing identity-bearing reaches Privy or any
  third party.** Only `@privy-io` import is `src/wallet/index.jsx`; the only
  network sink is `fetch` on relative paths in `api.js`; the only `localStorage`
  write is `theme`; no `sessionStorage`/`window.name`/query-param/`document.cookie`
  identity write anywhere in `src/`. Privy receives `appId` + static config only.
- **`PRIVY_CONFIGURED` placeholder detection is sound enough, and a hostile
  `VITE_PRIVY_APP_ID` cannot inject.** `.env.example` ships empty → `''` → not
  configured → null connector (designed setup notice). The regex rejects
  `your…`/`<…>` placeholders; real Privy ids (random alphanumeric) pass. The id
  is baked at build as a JS string literal and passed as a React prop
  (`appId={…}`) — no HTML interpolation, no injection. A malicious value is
  deployment-controlled (not external-attacker-controlled) and at worst points
  Privy at another Privy app, touching wallet connection only, never identity/FIN.
- **The origin split adds no spoofing/phishing surface.** `public_origin`
  (`/api/me` unauth, verified `= "http://127.0.0.1:8000"` with PUBLIC_URL unset)
  is deployment-controlled config, echoed by `OriginMismatch` through React
  (auto-escaped — no XSS), and shown **only when unauthenticated**; no security
  decision hinges on it. The verify.py message DOMAIN/URI derive from the same
  deployment env, so the signed message's stated origin matches the browser
  origin — a phishing-reduction, not a new surface.
- **The cancel generation guard prevents a bind after abandonment.** In
  `App.jsx sign()`, `gen = attestGen.current` is captured before the wallet
  prompt; `closeAttest()` bumps `attestGen.current`; the post-`signEvm` check
  `if (attestGen.current !== gen) return` fires before `/api/wallet/bind` is
  called. The nonce is single-use and TTL-bound, so abandoning is safe. (Even
  without the guard this would bind only the user's own validly-signed wallet —
  not a security issue.)
- **No newline/label injection into the signed message via `display_name`.** The
  only user-influenced inputs to `build_message` are `address` (strictly
  format-validated; a non-hex/oversized value can never reach an active binding
  because recovery won't match the claimed address) and `identity_label`
  (`display_name` from the Fayda `name` claim — IdP-sourced, not user-settable in
  this trust model). Even a newline-bearing name only alters the requester's own
  signing message; it cannot cross bindings, break the sybil/nonce constraints,
  or change the recovered-signer check. Worth sanitizing as defense-in-depth; not
  a live break.
- **t.py green on a fresh schema-changed DB** — 18/18 including the FIN/claims
  fixation asserts (3b/3c), sybil race (17), and dev-surface gating (13/14). No
  raw FIN in the server log or any response body.

### Verdict
Safe to build on — **yes**, with respect to this diff. The frontend rebuild
introduces no off-origin sink, no embedded-wallet custody, and no path that
hands the session cookie, claims, or FIN-derived data to Privy or any third
party; the origin split is fail-safe and escape-free; the bind byte-path is
irrelevant to soundness because the server verifies its own stored message. The
single real defect is a **silently broken safeguard** — `proof_method` is never
written, so this diff's own anti-masquerade audit-trail feature does nothing —
but it breaks no CLAUDE.md non-negotiable and has no production exploitability
(the only non-`wallet` source, the dev endpoint, cannot exist in production).
Fix the INSERT and add the missing test before relying on the provenance field.
Pre-existing mediums (unbounded `sessions`/`auth_nonces`, write-on-read under the
global lock, non-atomic logout, M4 migration hazard) remain open and untouched.

New criticals: 0, new highs: 0.

---

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
