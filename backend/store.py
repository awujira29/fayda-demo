"""
Postgres (Supabase) storage layer.

The two partial unique indexes below are the whole point of this demo:
  - one ACTIVE wallet per (identity, chain)
  - one ACTIVE identity per (chain, address)

The second is the sybil constraint. Without it, one wallet could be claimed
by two different Fayda identities, and the "one verified person, one wallet"
guarantee collapses.

R1 (Supabase keystone): data lives in managed Postgres, not a file on the
container's ephemeral disk — it survives deploy, restart, and scale-out, and
the sybil unique indexes hold across every app instance because they live in
the one shared database. Postgres is also what makes R2's Row-Level Security
possible at all. The connection string comes ONLY from SUPABASE_DB_URL (env
or backend/.env, which is gitignored); it is never hardcoded here.
"""

import atexit
import os
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import unquote

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json
from psycopg_pool import ConnectionPool

# EVM hex is case-insensitive — the EIP-55 mixed case is a display checksum,
# not part of the identifier — while Solana base58 IS case-sensitive. The
# unique indexes compare exact strings, so without one canonical form per chain
# '0xAbC…' and '0xabc…' are two rows to Postgres and two identities can hold
# one wallet. Deriving the canonical form as a GENERATED column means the
# database computes it: no code path, present or future, can write a row that
# escapes the sybil index, and `address` keeps its checksummed spelling for
# display.
ADDRESS_NORM = ("CASE WHEN chain = 'evm' THEN lower(address) ELSE address END")

SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS identities (
    id            TEXT PRIMARY KEY,
    fin_hmac      TEXT NOT NULL UNIQUE,   -- HMAC-SHA256(pepper, FIN). Raw FIN is never stored.
    display_name  TEXT NOT NULL,
    birthdate     TEXT,
    verified_at   TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet_bindings (
    id            TEXT PRIMARY KEY,
    identity_id   TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    chain         TEXT NOT NULL CHECK (chain IN ('evm', 'solana')),
    address       TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active','pending','archived','cancelled')),
    proof_nonce   TEXT NOT NULL,
    proof_sig     TEXT NOT NULL,
    proof_message TEXT NOT NULL,
    proof_method  TEXT NOT NULL DEFAULT 'wallet',
    requested_at  TEXT NOT NULL,
    activates_at  TEXT,
    activated_at  TEXT,
    archived_at   TEXT
);

CREATE TABLE IF NOT EXISTS auth_nonces (
    nonce       TEXT PRIMARY KEY,
    address     TEXT NOT NULL,
    chain       TEXT NOT NULL,
    message     TEXT NOT NULL,   -- exact text issued; never trust the client's copy
    expires_at  TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    -- how the proof will be produced: 'wallet' or 'dev-test-key'. Recorded
    -- server-side at issue time so a test-key binding can never masquerade
    -- as a real wallet attestation in the audit trail.
    issued_via  TEXT NOT NULL DEFAULT 'wallet'
);

-- Session data stays server-side. The claims now include address.kebele and
-- address.woreda — neighbourhood-level location — which must never sit in a
-- signed-but-unencrypted cookie any cookie holder can decode. The browser
-- gets only the opaque sid.
CREATE TABLE IF NOT EXISTS sessions (
    sid         TEXT PRIMARY KEY,
    data        JSONB NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

-- R2 return-login. A passkey is registered only by an already Fayda-verified
-- session and is bound to that identity, so it re-establishes an identity
-- Fayda already proved — it never mints a new one. Only the PUBLIC key is
-- here; the private key never leaves the authenticator, which is what makes
-- this phishing-resistant.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,        -- base64url, from the authenticator
    identity_id   TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    public_key    TEXT NOT NULL,           -- base64url COSE key
    -- Authenticators that implement it increment this per assertion. A value
    -- that fails to advance is the documented signal of a cloned credential.
    sign_count    BIGINT NOT NULL DEFAULT 0,
    label         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);

-- R3. Who may look at other people's records. Membership is granted out of
-- band (backend/store.py grant-operator) and by no HTTP route: an endpoint
-- that can make someone an operator is an endpoint that can be abused into
-- making an attacker one.
CREATE TABLE IF NOT EXISTS operators (
    identity_id TEXT PRIMARY KEY REFERENCES identities(id) ON DELETE CASCADE,
    granted_at  TEXT NOT NULL,
    granted_by  TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    -- Revocation is a tombstone, not a DELETE. Hard-deleting the row left the
    -- log full of entries by an actor with no recorded authority to make them
    -- — a reviewer could no longer tell whether the lookups were legitimate
    -- at the time.
    revoked_at  TEXT
);

-- R3. Every operator look at another person's record, recorded before the data
-- is returned. Binding a national identity to financial history is a
-- surveillance capability; the log is what makes it accountable, and it is
-- append-only at the DATABASE (see the trigger in SCHEMA_RLS) rather than by
-- convention, so a compromised app cannot quietly erase its own tracks.
CREATE TABLE IF NOT EXISTS access_log (
    id            TEXT PRIMARY KEY,
    at            TEXT NOT NULL,
    actor_id      TEXT NOT NULL,     -- the operator, not FK-bound: the row must
                                     -- survive the actor's identity being deleted
    subject_id    TEXT,              -- whose record; NULL for non-subject actions
    action        TEXT NOT NULL,
    reason        TEXT NOT NULL,     -- why. Required at the API boundary.
    detail        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ix_access_log_subject ON access_log (subject_id);
CREATE INDEX IF NOT EXISTS ix_access_log_actor ON access_log (actor_id);

-- Properties of THIS database, as opposed to the process talking to it. The
-- disposable marker (see reset) lives here because a guard that reads the
-- caller's own environment is not a guard: the caller sets the environment.
CREATE TABLE IF NOT EXISTS registry_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL,
    set_at  TEXT NOT NULL
);
"""

# Created after the canonical-address column exists (see init).
SCHEMA_INDEXES = """
-- One ACTIVE wallet per identity per chain.
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_identity_chain
    ON wallet_bindings (identity_id, chain) WHERE status = 'active';

-- One ACTIVE identity per address per chain. This is the sybil constraint.
-- Keyed on the canonical address so a differently-cased spelling of one
-- wallet cannot be a second row.
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_chain_address
    ON wallet_bindings (chain, address_norm) WHERE status = 'active';

-- Only one pending replacement in flight per identity per chain.
CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_identity_chain
    ON wallet_bindings (identity_id, chain) WHERE status = 'pending';

-- One PENDING claim per address per chain, across identities. The app-level
-- sybil check covers pending rows but is check-then-insert; two identities
-- racing that window could each park a pending row on the same address, and
-- the loser would then hit ux_active_chain_address inside promote_due on every
-- read. Close the window at the DB layer, like the active tier.
CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_chain_address
    ON wallet_bindings (chain, address_norm) WHERE status = 'pending';

-- The TTL sweep deletes by expires_at on exactly the two tables unauthenticated
-- traffic grows. Without these it seq-scans the attacker's own variable every
-- cycle: the defence gets more expensive the more it is needed.
--
-- COLLATE "C" here is not decoration: it must MATCH the sweep's predicate. An
-- index in the default collation is unusable by a `COLLATE "C"` comparison —
-- verified with EXPLAIN, which fell back to a sequential scan — so the two
-- fixes would have silently cancelled each other out.
CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions (expires_at COLLATE "C");
CREATE INDEX IF NOT EXISTS ix_auth_nonces_expires ON auth_nonces (expires_at COLLATE "C");
"""

# R2. The application connects as `postgres`, which carries rolbypassrls — every
# policy would be ignored, so RLS written against that role is theatre. Instead
# the identity-scoped queries switch to APP_ROLE for the duration of one
# transaction (see user_conn). It is NOBYPASSRLS and owns nothing, so the
# policies below actually bind, and the row filter is the database's, not a
# WHERE clause someone can forget to write.
APP_ROLE = "fayda_app"

SCHEMA_RLS = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
        CREATE ROLE {APP_ROLE} NOLOGIN NOBYPASSRLS;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public TO {APP_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE
    ON identities, wallet_bindings, webauthn_credentials TO {APP_ROLE};

ALTER TABLE identities           ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallet_bindings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS p_identities_own  ON identities;
DROP POLICY IF EXISTS p_bindings_own    ON wallet_bindings;
DROP POLICY IF EXISTS p_credentials_own ON webauthn_credentials;

-- nullif(..., '') is what makes this fail closed, and it is not decoration.
-- current_setting(x, true) returns NULL only on a connection that has never
-- set x; once a pooled connection has carried a transaction-scoped value, it
-- comes back as the EMPTY STRING instead. A bare comparison then reads
-- `id = ''`, which is a perfectly ordinary predicate: an unbound transaction
-- could insert a row with an empty id and every other unbound transaction
-- would read and write it. Mapping '' to NULL makes an unbound transaction
-- match nothing, on both the read and the write side.
CREATE POLICY p_identities_own ON identities
    FOR ALL TO {APP_ROLE}
    USING      (id = nullif(current_setting('app.identity_id', true), ''))
    WITH CHECK (id = nullif(current_setting('app.identity_id', true), ''));

CREATE POLICY p_bindings_own ON wallet_bindings
    FOR ALL TO {APP_ROLE}
    USING      (identity_id = nullif(current_setting('app.identity_id', true), ''))
    WITH CHECK (identity_id = nullif(current_setting('app.identity_id', true), ''));

CREATE POLICY p_credentials_own ON webauthn_credentials
    FOR ALL TO {APP_ROLE}
    USING      (identity_id = nullif(current_setting('app.identity_id', true), ''))
    WITH CHECK (identity_id = nullif(current_setting('app.identity_id', true), ''));

-- R3: the access log is append-only, enforced by the database.
--
-- A trigger rather than only a GRANT, because the application connects as the
-- table's owner: revoking UPDATE and DELETE from {APP_ROLE} does nothing about
-- the connection that actually runs most statements. This raises for every
-- caller, owner included. It is not absolute — whoever can ALTER the table can
-- disable it — but it converts "we promise not to rewrite the audit trail"
-- into something that has to be deliberately switched off first.
CREATE OR REPLACE FUNCTION access_log_append_only() RETURNS trigger AS $fn$
BEGIN
    RAISE EXCEPTION 'access_log is append-only; % is not permitted', TG_OP;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_access_log_append_only ON access_log;
CREATE TRIGGER trg_access_log_append_only
    BEFORE UPDATE OR DELETE ON access_log
    FOR EACH ROW EXECUTE FUNCTION access_log_append_only();

-- TRUNCATE does not fire row triggers, so the row-level guard above left the
-- single most effective way to erase the whole log wide open. This one is
-- statement-level and catches it.
DROP TRIGGER IF EXISTS trg_access_log_no_truncate ON access_log;
CREATE TRIGGER trg_access_log_no_truncate
    BEFORE TRUNCATE ON access_log
    FOR EACH STATEMENT EXECUTE FUNCTION access_log_append_only();

-- ENABLE ALWAYS, not the default ENABLE: a plain trigger is skipped whenever
-- session_replication_role is 'replica', which any superuser-ish session can
-- set for itself — turning both guards off with one statement and no DDL.
ALTER TABLE access_log ENABLE ALWAYS TRIGGER trg_access_log_append_only;
ALTER TABLE access_log ENABLE ALWAYS TRIGGER trg_access_log_no_truncate;

-- The reviewer's ordering column, so a growing log does not turn every read
-- into a full scan and sort.
-- Matches the paging ORDER BY exactly, tie-break included, so a growing log
-- does not turn every read into a full scan and sort.
CREATE INDEX IF NOT EXISTS ix_access_log_at
    ON access_log (at COLLATE "C" DESC, id DESC);

GRANT SELECT, INSERT ON access_log TO {APP_ROLE};
REVOKE UPDATE, DELETE ON access_log FROM {APP_ROLE};
GRANT SELECT ON operators TO {APP_ROLE};

-- A person can see who looked at their record. The surveillance capability R4
-- builds is one-directional by nature; this is the smallest thing that makes
-- it observable by the person being surveilled.
ALTER TABLE access_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_access_log_subject ON access_log;
CREATE POLICY p_access_log_subject ON access_log
    FOR SELECT TO {APP_ROLE}
    USING (subject_id = nullif(current_setting('app.identity_id', true), ''));
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


# Only this key may be loaded from the dotenv file. A .env that reaches a
# server must never be able to flip APP_ENV to dev (arming the whole dev
# surface) or plant SESSION_SECRET/FIN_PEPPER/PRIVY_APP_ID behind the
# operator's back — those come from the real environment or not at all.
_DOTENV_ALLOWED = frozenset({"SUPABASE_DB_URL"})


def _load_dotenv() -> None:
    """
    Minimal loader for backend/.env (gitignored) so local dev and t.py find
    SUPABASE_DB_URL without exporting it. Real env vars always win. No comment
    stripping mid-line: a DB password may legitimately contain '#'.
    """
    p = Path(__file__).parent / ".env"
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k in _DOTENV_ALLOWED and k not in os.environ:
            os.environ[k] = v


def _conninfo() -> str:
    """
    Parse SUPABASE_DB_URL by hand instead of handing it to libpq's URI parser:
    a password containing raw '#' or '?' breaks both urllib.parse and libpq
    URI splitting, and a mangled password shows up only as a confusing auth
    failure. Percent-escapes are honoured so a properly-encoded URL works too.
    """
    _load_dotenv()
    url = os.getenv("SUPABASE_DB_URL")
    if not url:
        raise RuntimeError(
            "SUPABASE_DB_URL must be set (env or backend/.env) — R1 moved "
            "storage to Supabase Postgres; there is no SQLite fallback"
        )
    scheme, _, rest = url.partition("://")
    if scheme not in ("postgres", "postgresql"):
        raise RuntimeError("SUPABASE_DB_URL must be a postgresql:// URL")
    userinfo, _, hostpart = rest.rpartition("@")
    user, _, password = userinfo.partition(":")
    hostport, _, path = hostpart.partition("/")
    host, _, port = hostport.partition(":")
    dbname, _, query = path.partition("?")
    # Honour explicit URL query params (a deliberate sslmode=verify-full must
    # not be silently discarded), but default sslmode=require: 'prefer' would
    # fall back to PLAINTEXT if a middlebox strips TLS, sending the credential
    # and all registry PII in the clear.
    kw: dict = {
        "host": host, "port": int(port or 5432), "dbname": dbname or "postgres",
        "user": unquote(user), "password": unquote(password),
    }
    for p in query.split("&"):
        if "=" in p:
            k, _, v = p.partition("=")
            kw[k] = unquote(v)
    kw.setdefault("sslmode", "require")
    return psycopg.conninfo.make_conninfo(**kw)


# The old process-global _DB_LOCK is gone: it existed to serialize SQLite
# open/close churn that deadlocked inside the OS sqlite library. Postgres has
# real concurrency — the pool below hands out independent connections and the
# unique indexes arbitrate races server-side. The only lock left guards lazy
# pool creation, never queries.
_POOL: ConnectionPool | None = None
_POOL_LOCK = threading.Lock()


def _configure(c: psycopg.Connection) -> None:
    # Supabase ships its own auth.identities / auth.sessions tables. Every
    # statement here is schema-unqualified, so pin the search path to public —
    # a surprise search_path must never let reset()'s DROP or any query
    # resolve to Supabase's auth schema.
    c.execute("SET search_path TO public")
    c.commit()


def _pool() -> ConnectionPool:
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                _POOL = ConnectionPool(
                    _conninfo(),
                    configure=_configure,
                    min_size=1,
                    # Every store call takes a checkout, and each checkout
                    # costs a remote round trip to a managed database — a
                    # ceiling of 4 made concurrent readers queue for tens of
                    # seconds. Still bounded: Supabase's session-mode pooler
                    # holds one server session per open client connection, and
                    # several processes (app, tests) may share the project.
                    max_size=12,
                    # Recycle connections the platform pooler may have dropped
                    # while they sat idle, instead of discovering it mid-request.
                    max_idle=120.0,
                    # prepare_threshold=None: /api/dev/reset drops and
                    # recreates tables, which would invalidate auto-prepared
                    # statements on other pooled connections ("cached plan
                    # must not change result type").
                    kwargs={"row_factory": dict_row, "prepare_threshold": None},
                    # Revalidate pooled connections so an idle disconnect by
                    # the platform pooler surfaces as a fresh connection, not
                    # a failed request.
                    check=ConnectionPool.check_connection,
                    timeout=30,
                    open=True,
                )
                # Close worker threads before interpreter teardown; without
                # this, short-lived processes (t.py) exit with a noisy
                # PythonFinalizationError from the pool's finalizer.
                atexit.register(_POOL.close)
    return _POOL


@contextmanager
def conn():
    # pool.connection() commits on clean exit and rolls back on exception —
    # the same semantics the SQLite context manager had.
    with _pool().connection() as c:
        yield c


@contextmanager
def user_conn(identity_id: str):
    """
    A connection that can only see ONE identity's rows, enforced by Postgres.

    Everything inside runs as APP_ROLE (NOBYPASSRLS) with app.identity_id bound
    to this identity, so the policies filter every statement — including one
    that forgets its WHERE clause, which is the failure this exists to make
    impossible. Both settings are transaction-scoped (SET LOCAL / set_config
    is_local=true), so they are gone when the pooled connection is handed to
    the next request; a leaked role or identity across requests would be worse
    than no RLS at all.

    Not for cross-identity work: the sybil check must see other identities'
    claims, and promotion runs registry-wide. Those keep conn() deliberately.
    """
    if not identity_id:
        raise ValueError("user_conn requires an identity")
    with _pool().connection() as c:
        # Bind the identity BEFORE dropping privilege: order matters only for
        # clarity here, but it keeps the sequence readable as "who am I, then
        # become restricted".
        c.execute("SELECT set_config('app.identity_id', %s, true)", (identity_id,))
        c.execute(f"SET LOCAL ROLE {APP_ROLE}")
        yield c


def normalize_address(chain: str, address: str) -> str:
    """
    The canonical form of an address, mirroring the ADDRESS_NORM generated
    column. Used wherever application code compares two addresses, so the app
    and the sybil indexes agree on what "the same wallet" means. EVM hex is
    case-insensitive; Solana base58 is not and passes through untouched.
    """
    return address.lower() if chain == "evm" else address


def _create_schema(c: psycopg.Connection) -> None:
    """
    The whole schema, on a caller-supplied connection so init() and reset()
    can each run it inside their own single transaction.
    """
    # Serialize concurrent boots: two instances racing CREATE ... IF NOT
    # EXISTS can still collide inside Postgres' catalog. Transaction-scoped,
    # so it releases at commit.
    c.execute("SELECT pg_advisory_xact_lock(727401)")
    c.execute(SCHEMA_TABLES)

    # Canonical-address column, then the indexes that depend on it. Adding
    # it separately (rather than in the CREATE TABLE) is what lets a
    # database created before this change migrate in place.
    c.execute(
        "ALTER TABLE wallet_bindings ADD COLUMN IF NOT EXISTS address_norm "
        f"TEXT GENERATED ALWAYS AS ({ADDRESS_NORM}) STORED"
    )

    # A database written before the canonical column existed may already
    # hold two live rows that differ only in case — exactly what the new
    # index forbids. Creating it would then raise inside init() at import
    # time and the app would refuse to boot, turning a data problem into a
    # hard outage. Resolve first: keep the oldest claim per (chain,
    # canonical address, tier) and cancel the rest, which is the same
    # outcome the index would have produced had it existed.
    c.execute(
        """WITH dupes AS (
               SELECT id, ROW_NUMBER() OVER (
                   PARTITION BY chain, address_norm, status
                   ORDER BY requested_at) AS rn
               FROM wallet_bindings
               WHERE status IN ('active','pending'))
           UPDATE wallet_bindings SET status='cancelled', archived_at=%s
           WHERE id IN (SELECT id FROM dupes WHERE rn > 1)""",
        (iso(now()),),
    )

    # Replace any address-keyed index left from before the canonical column.
    # Same names, so nothing else in the code or the docs has to know.
    for name in ("ux_active_chain_address", "ux_pending_chain_address"):
        stale = c.execute(
            "SELECT 1 FROM pg_indexes WHERE schemaname='public' "
            "AND indexname=%s AND indexdef NOT LIKE %s",
            (name, "%address_norm%"),
        ).fetchone()
        if stale:
            c.execute(f"DROP INDEX {name}")

    # CREATE TABLE IF NOT EXISTS adds nothing to a table that already exists,
    # so a column introduced after the first deploy has to be added explicitly
    # — exactly as address_norm is above. Without this, a database created
    # before revocation existed keeps the old shape and every operator route
    # 500s on UndefinedColumn: fail-closed, but silent until the moment
    # somebody needs compliance access.
    c.execute("ALTER TABLE operators ADD COLUMN IF NOT EXISTS revoked_at TEXT")

    # Same migration for the TTL indexes: an earlier cut created them in the
    # default collation, which the sweep's COLLATE "C" predicate cannot use.
    # CREATE INDEX IF NOT EXISTS would leave the useless one in place.
    for name in ("ix_sessions_expires", "ix_auth_nonces_expires"):
        stale = c.execute(
            "SELECT 1 FROM pg_indexes WHERE schemaname='public' "
            "AND indexname=%s AND indexdef NOT LIKE %s",
            (name, '%COLLATE "C"%'),
        ).fetchone()
        if stale:
            c.execute(f"DROP INDEX {name}")

    c.execute(SCHEMA_INDEXES)
    c.execute(SCHEMA_RLS)

    # SET ROLE needs membership in the target role. Issued separately, with the
    # connected role's real name quoted as an identifier: `GRANT ... TO
    # CURRENT_USER` is accepted by the parser but terminates the connection on
    # Supabase's pooler, and the failure looks like a dropped TLS session
    # rather than a rejected statement.
    me = c.execute("SELECT current_user AS u").fetchone()["u"]
    c.execute(
        psycopg.sql.SQL("GRANT {role} TO {me}").format(
            role=psycopg.sql.Identifier(APP_ROLE),
            me=psycopg.sql.Identifier(me),
        )
    )


def init():
    with conn() as c:
        _create_schema(c)


_DISPOSABLE_KEY = "disposable_registry"


def _target(c: psycopg.Connection) -> str:
    """
    Which database this connection actually reached, as attested by the SERVER.

    Not host:port/dbname. Behind Supabase's session pooler every project in a
    region answers on the same hostname and database name, so that fingerprint
    is byte-identical for the dev and production projects — it would have
    happily transferred a dev grant to production, the exact case this exists
    to stop. And the host is echoed conninfo: caller-supplied config, not
    something the server told us.

    system_identifier is generated at initdb, is unique per cluster, is not
    carried by pg_dump, and comes from the server. A dev dump restored onto a
    production cluster therefore arrives carrying a marker that no longer
    matches, and the grant does not travel with the data.
    """
    row = c.execute(
        "SELECT system_identifier FROM pg_control_system()"
    ).fetchone()
    return f"pg{row['system_identifier']}/{c.info.dbname}"


def mark_disposable() -> str:
    """
    Declare THIS database throwaway, so reset() may drop it. A deliberate,
    explicit act against one specific database — never a side effect of
    running the app or the tests. Run once per dev database:

        APP_ENV=dev python backend/store.py mark-disposable
    """
    if os.getenv("APP_ENV") != "dev":
        raise RuntimeError("refusing to mark a database disposable outside dev")
    with conn() as c:
        target = _target(c)
        # A database holding real identities is not a throwaway. This is the
        # one command that can authorize destruction, so it refuses the shape
        # of a mistake — aiming it at a populated registry — rather than
        # trusting that whoever typed it checked which .env was loaded.
        n = c.execute("SELECT count(*) AS n FROM identities").fetchone()["n"]
        if n and os.getenv("MARK_DISPOSABLE_ANYWAY") != "1":
            raise RuntimeError(
                f"{target} holds {n} identities — refusing to mark a populated "
                f"registry disposable. If this really is throwaway data, set "
                f"MARK_DISPOSABLE_ANYWAY=1."
            )
        c.execute(
            """INSERT INTO registry_meta (key, value, set_at) VALUES (%s,%s,%s)
               ON CONFLICT (key) DO UPDATE SET value = excluded.value,
                                               set_at = excluded.set_at""",
            (_DISPOSABLE_KEY, target, iso(now())),
        )
    return target


def disposable() -> tuple[bool, str]:
    """
    Whether the database in hand has declared itself throwaway. The marker
    records the target it was written for and must still match, so a dump of a
    dev database restored onto a production host does not carry permission to
    wipe it along with the data.
    """
    with conn() as c:
        target = _target(c)
        try:
            row = c.execute(
                "SELECT value FROM registry_meta WHERE key = %s", (_DISPOSABLE_KEY,)
            ).fetchone()
        except psycopg.errors.UndefinedTable:
            # Never initialised. Report it as "not disposable" so callers get
            # the guidance path rather than a raw driver traceback.
            return False, f"{target} has no registry schema yet"
    if not row:
        return False, f"{target} is not marked disposable"
    if row["value"] != target:
        return False, (f"the disposable marker names {row['value']}, "
                       f"but this connection reached {target}")
    return True, target


def reset():
    """DEV ONLY (reached via /api/dev/reset). Drops and recreates the schema."""
    # Two independent gates, and — this is the point — the second one asks the
    # TARGET, not the caller. APP_ENV alone was not a guard: any caller can set
    # it, and the test suite did exactly that two lines before calling this,
    # turning `python backend/t.py` into a one-command wipe of whatever
    # SUPABASE_DB_URL happened to name. A production database has never been
    # marked disposable, so it now refuses no matter what the caller's
    # environment claims.
    if os.getenv("APP_ENV") != "dev":
        raise RuntimeError("store.reset() is dev-only — refusing to drop tables")
    ok, why = disposable()
    if not ok:
        raise RuntimeError(
            f"refusing to drop tables: {why}. If this really is a throwaway "
            f"database, run: APP_ENV=dev python backend/store.py mark-disposable"
        )
    with conn() as c:
        # Take the advisory lock BEFORE the DROP. _create_schema acquires it
        # first and then touches tables; dropping first and acquiring second
        # inverts that order against a concurrently booting instance, which is
        # a genuine deadlock (reproduced). One lock order everywhere.
        c.execute("SELECT pg_advisory_xact_lock(727401)")
        # Drop and recreate in ONE transaction: committing the DROP separately
        # left a window where the tables did not exist and every concurrent
        # request 500'd. Harmless against a local file; not against a shared
        # database other processes are querying. registry_meta is deliberately
        # not dropped — it holds no registry data, and dropping it would
        # discard the marker that authorized this.
        # webauthn_credentials is in the list because CASCADE would drop its
        # foreign key to identities and CREATE TABLE IF NOT EXISTS would never
        # add it back — leaving orphaned passkeys, permanently unreferenced,
        # for identities the wipe claims to have erased. Reset must not quietly
        # weaken the schema it recreates.
        c.execute(
            "DROP TABLE IF EXISTS wallet_bindings, auth_nonces, sessions, "
            "webauthn_credentials, access_log, operators, identities CASCADE"
        )
        _create_schema(c)


# ---------------------------------------------------------------- identities

def upsert_identity(fin_hmac: str, display_name: str, birthdate: str) -> dict:
    """Called after a successful Fayda authentication."""
    with conn() as c:
        row = c.execute(
            "SELECT * FROM identities WHERE fin_hmac = %s", (fin_hmac,)
        ).fetchone()
        if row:
            c.execute(
                "UPDATE identities SET last_seen_at = %s WHERE id = %s",
                (iso(now()), row["id"]),
            )
            return dict(row)

        ident = {
            "id": str(uuid.uuid4()),
            "fin_hmac": fin_hmac,
            "display_name": display_name,
            "birthdate": birthdate,
            "verified_at": iso(now()),
            "last_seen_at": iso(now()),
        }
        # ON CONFLICT, not a bare INSERT: this is check-then-insert, and two
        # concurrent first logins of one identity (a double-clicked login, or
        # two demo visitors picking the same persona) would otherwise make the
        # loser's INSERT violate identities_fin_hmac_key and 500 the OIDC
        # callback. The loser must land on the winner's row, not an error.
        row = c.execute(
            """INSERT INTO identities (id, fin_hmac, display_name, birthdate,
                                       verified_at, last_seen_at)
               VALUES (%(id)s, %(fin_hmac)s, %(display_name)s, %(birthdate)s,
                       %(verified_at)s, %(last_seen_at)s)
               ON CONFLICT (fin_hmac) DO UPDATE SET last_seen_at = excluded.last_seen_at
               RETURNING *""",
            ident,
        ).fetchone()
        return dict(row)


def get_identity(identity_id: str) -> dict | None:
    # RLS-scoped: the policy alone would restrict this to the one row, and the
    # WHERE clause is kept as the belt to its braces.
    with user_conn(identity_id) as c:
        row = c.execute(
            "SELECT * FROM identities WHERE id = %s", (identity_id,)
        ).fetchone()
        return dict(row) if row else None


# ----------------------------------------------------------------- sessions

def load_session(sid: str) -> dict | None:
    with conn() as c:
        row = c.execute("SELECT * FROM sessions WHERE sid = %s", (sid,)).fetchone()
        if not row:
            return None
        if parse(row["expires_at"]) < now():
            c.execute("DELETE FROM sessions WHERE sid = %s", (sid,))
            return None
        return row["data"]


def save_session(sid: str, data: dict, ttl_hours: float) -> None:
    with conn() as c:
        c.execute(
            """INSERT INTO sessions (sid, data, created_at, expires_at)
               VALUES (%s,%s,%s,%s)
               ON CONFLICT(sid) DO UPDATE SET
                   data = excluded.data, expires_at = excluded.expires_at""",
            (sid, Json(data), iso(now()),
             iso(now() + timedelta(hours=ttl_hours))),
        )


def delete_session(sid: str) -> None:
    with conn() as c:
        c.execute("DELETE FROM sessions WHERE sid = %s", (sid,))


def delete_sessions_for_credential(credential_id: str) -> int:
    """
    End every session that a given passkey established.

    Revocation that only blocks the NEXT sign-in is not an escape hatch: an
    attacker who registered a passkey on a compromised session is already
    signed in, and would keep that session for the rest of its TTL after the
    owner revoked. Privileged by necessity — sessions are keyed by sid, and the
    row being deleted belongs to the attacker, not to the caller.
    """
    with conn() as c:
        return c.execute(
            "DELETE FROM sessions WHERE data->>'passkey_credential_id' = %s",
            (credential_id,),
        ).rowcount


def sweep_expired() -> tuple[int, int]:
    """
    Reclaim TTL-dead rows from the two tables that grow with traffic. R1 made
    storage durable — nothing resets the database anymore — and both tables
    are attacker-growable without credentials (every /login persists a session
    row; expired rows were only ever swept lazily, on a load of that exact
    sid, which an anonymous row never gets). Without this, an unauthenticated
    loop grows the database forever.

    COLLATE "C" is load-bearing. These timestamps are TEXT, and this database's
    default collation (en_US.UTF-8) does NOT order ISO-8601 strings
    chronologically — it ignores punctuation weight, so
    '…12:00:00+00:00' < '…12:00:00.500000+00:00' is false. The error is
    sub-second and would be harmless here, but the next comparison added
    against these columns might not be; C collation is plain byte order, under
    which fixed-width ISO-8601 UTC does sort chronologically.
    """
    with conn() as c:
        cutoff = iso(now())
        s = c.execute(
            'DELETE FROM sessions WHERE expires_at COLLATE "C" < %s', (cutoff,)
        ).rowcount
        n = c.execute(
            'DELETE FROM auth_nonces WHERE expires_at COLLATE "C" < %s', (cutoff,)
        ).rowcount
    return s, n


# --------------------------------------------------- operators + audit (R3)

def is_operator(identity_id: str) -> bool:
    with conn() as c:
        return bool(c.execute(
            "SELECT 1 FROM operators WHERE identity_id = %s AND revoked_at IS NULL",
            (identity_id,),
        ).fetchone())


def _log_stmt(c: psycopg.Connection, actor_id: str, action: str, reason: str,
              subject_id: str | None = None, detail: str = "") -> None:
    """log_access on a caller's connection, so the entry and the change it
    describes commit or roll back together."""
    c.execute(
        """INSERT INTO access_log (id, at, actor_id, subject_id, action, reason, detail)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (str(uuid.uuid4()), iso(now()), actor_id, subject_id, action, reason, detail),
    )


def grant_operator(identity_id: str, granted_by: str, note: str = "") -> None:
    """Deliberately not reachable over HTTP. See the operators table comment."""
    # Grant and log in ONE transaction. Elsewhere the log is written first and
    # allowed to fail the read, because the danger is data escaping unlogged.
    # A privilege change is the mirror case — logging a grant that then failed
    # would be its own kind of false record — so atomicity, not ordering, is
    # what makes this honest.
    with conn() as c:
        c.execute(
            """INSERT INTO operators (identity_id, granted_at, granted_by, note,
                                      revoked_at)
               VALUES (%s,%s,%s,%s,NULL)
               ON CONFLICT (identity_id) DO UPDATE
                   SET revoked_at = NULL, granted_at = excluded.granted_at,
                       granted_by = excluded.granted_by, note = excluded.note""",
            (identity_id, iso(now()), granted_by, note),
        )
        # Who was given the power to read other people's records, and when,
        # belongs in the same trail as the lookups they then make. Without it a
        # reviewer sees the accesses but not the authority behind them.
        _log_stmt(c, granted_by, "grant_operator",
                  note or "operator role granted", identity_id)


def revoke_operator(identity_id: str, revoked_by: str = "cli") -> bool:
    with conn() as c:
        n = c.execute(
            "UPDATE operators SET revoked_at = %s "
            "WHERE identity_id = %s AND revoked_at IS NULL",
            (iso(now()), identity_id),
        ).rowcount
        if n:
            _log_stmt(c, revoked_by, "revoke_operator",
                      "operator role revoked", identity_id)
    return n == 1


def cli_actor() -> str:
    """
    Identify the human behind a CLI grant. actor_id holds identity UUIDs
    everywhere else; a bare "cli" left "who did this" unanswerable, which is
    the one question the log exists for.
    """
    import getpass
    import socket
    try:
        return f"cli:{getpass.getuser()}@{socket.gethostname()}"[:200]
    except Exception:
        return "cli:unknown"


def log_access(actor_id: str, action: str, reason: str,
               subject_id: str | None = None, detail: str = "") -> str:
    """
    Record one access. Raises on failure, and callers must let it — a lookup
    that returns data without leaving a log entry is precisely what R3 exists
    to prevent, so failing the request is the correct outcome.
    """
    entry_id = str(uuid.uuid4())
    with conn() as c:
        c.execute(
            """INSERT INTO access_log (id, at, actor_id, subject_id, action, reason, detail)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (entry_id, iso(now()), actor_id, subject_id, action, reason, detail),
        )
    return entry_id


# A page size, not a ceiling on what exists. An unpaginated LIMIT meant an
# actor could bury an entry simply by generating more: the row stayed in the
# table but fell off the only view anyone reads, which is eviction from the
# audit trail in every sense that matters. Both readers below page with a
# cursor and report the true total.
LOG_PAGE = 200

# The cursor is (at, id), not at alone. Timestamps are not unique — one search
# writes an entry per result in a tight loop — and a strict `at < cursor` would
# skip every row sharing the last row's timestamp, silently dropping entries
# from the only view anyone reads. That is the same eviction the pagination was
# added to prevent, just with a smaller window. id breaks the tie.
_CURSOR_SEP = "|"


def _cursor_of(row: dict) -> str:
    return f"{row['at']}{_CURSOR_SEP}{row['id']}"


class BadCursor(ValueError):
    """A paging cursor that cannot be parsed. Surfaced as a 400."""


def _cursor_parts(before: str | None) -> tuple[str, str] | None:
    if not before:
        return None
    at, sep, ident = before.partition(_CURSOR_SEP)
    if not (sep and at and ident):
        # Silently falling back to page 1 turns a truncated cursor into an
        # infinite loop on the head of the log — the reader believes they are
        # paging while the older entries stay unreachable. Say so instead.
        raise BadCursor("malformed paging cursor")
    return at, ident


# ORDER BY and the WHERE clause must agree on the tie-break, or paging can
# revisit or skip rows.
_ORDER = 'ORDER BY at COLLATE "C" DESC, id DESC'
_KEYSET = ('(at COLLATE "C" < %s OR (at COLLATE "C" = %s AND id < %s))')


def access_log_all(limit: int = LOG_PAGE, before: str | None = None) -> dict:
    """
    The operator view of the log. Privileged: it spans every subject. Returns
    the page plus the total, so truncation is visible rather than silent.
    """
    limit = max(1, min(int(limit), 1000))
    cur = _cursor_parts(before)
    with conn() as c:
        total = c.execute("SELECT count(*) AS n FROM access_log").fetchone()["n"]
        if cur:
            rows = c.execute(
                f"SELECT * FROM access_log WHERE {_KEYSET} {_ORDER} LIMIT %s",
                (cur[0], cur[0], cur[1], limit)).fetchall()
        else:
            rows = c.execute(
                f"SELECT * FROM access_log {_ORDER} LIMIT %s", (limit,)).fetchall()
        entries = [dict(r) for r in rows]
    return {"entries": entries, "total": total,
            "next_before": _cursor_of(entries[-1]) if len(entries) == limit else None}


def access_log_about(subject_id: str, limit: int = LOG_PAGE,
                     before: str | None = None) -> dict:
    """
    What a person can see about who looked at them. RLS-scoped, so the policy
    — not the WHERE clause — is what limits it to their own rows.
    """
    limit = max(1, min(int(limit), 1000))
    cur = _cursor_parts(before)
    with user_conn(subject_id) as c:
        total = c.execute("SELECT count(*) AS n FROM access_log").fetchone()["n"]
        # detail included: without it a person could see THAT one of their
        # wallets was traced on-chain but never WHICH — the single fact that
        # makes the entry actionable to them. id is selected so the caller can
        # page, and stripped from what is returned.
        cols = "id, at, actor_id, action, reason, detail"
        if cur:
            rows = c.execute(
                f"SELECT {cols} FROM access_log WHERE {_KEYSET} {_ORDER} LIMIT %s",
                (cur[0], cur[0], cur[1], limit)).fetchall()
        else:
            rows = c.execute(
                f"SELECT {cols} FROM access_log {_ORDER} LIMIT %s", (limit,)).fetchall()
        entries = [dict(r) for r in rows]
    nxt = _cursor_of(entries[-1]) if len(entries) == limit else None
    for e in entries:
        e.pop("id", None)
    return {"entries": entries, "total": total, "next_before": nxt}


def identity_timeline(identity_id: str) -> list[dict]:
    """
    Every in-app event for one identity, newest first (R4).

    Derived from the rows themselves rather than kept as a separate event
    table: each binding's timestamps ARE its history, so a timeline built from
    them cannot drift out of sync with the bindings it describes. Privileged —
    the caller is an operator and must have logged the access.
    """
    events: list[dict] = []
    with conn() as c:
        ident = c.execute(
            "SELECT display_name, verified_at, last_seen_at FROM identities "
            "WHERE id = %s", (identity_id,)
        ).fetchone()
        if not ident:
            return []
        events.append({"at": ident["verified_at"], "kind": "identity_verified",
                       "detail": "Fayda verification established this identity",
                       "chain": None, "address": None})
        rows = c.execute(
            """SELECT chain, address, status, proof_method, requested_at,
                      activates_at, activated_at, archived_at
               FROM wallet_bindings WHERE identity_id = %s""",
            (identity_id,),
        ).fetchall()

    for b in rows:
        where = {"chain": b["chain"], "address": b["address"]}
        # A first binding activates immediately; a replacement is requested,
        # cools, then either activates or is cancelled. Emitting requested and
        # activated separately would double-count the immediate case.
        immediate = b["activated_at"] and b["activated_at"] == b["requested_at"]
        events.append({
            "at": b["requested_at"],
            "kind": "wallet_bound" if immediate else "replacement_requested",
            "detail": ("bound immediately (no incumbent)" if immediate else
                       f"replacement requested, cooling until {b['activates_at']}"),
            "proof_method": b["proof_method"], **where})
        if b["activated_at"] and not immediate:
            events.append({"at": b["activated_at"], "kind": "replacement_activated",
                           "detail": "cooling period elapsed", **where})
        if b["archived_at"]:
            events.append({
                "at": b["archived_at"],
                "kind": "binding_cancelled" if b["status"] == "cancelled"
                        else "binding_archived",
                "detail": ("cancelled during the cooling period"
                           if b["status"] == "cancelled"
                           else "replaced by a newer binding"), **where})

    events.sort(key=lambda e: e["at"] or "", reverse=True)
    return events


def registry_ids() -> list[str]:
    """
    The identity ids the registry listing discloses, so each of those people
    gets an access-log entry. Kept separate from registry() because the ids
    are for the log, not for the response body.
    """
    with conn() as c:
        return [r["id"] for r in c.execute(
            """SELECT i.id FROM identities i
               WHERE EXISTS (SELECT 1 FROM wallet_bindings b
                             WHERE b.identity_id = i.id AND b.status = 'active')"""
        ).fetchall()]


def find_identities(query: str, limit: int = 25) -> list[dict]:
    """
    Operator search. Privileged by definition — this is the cross-user lookup
    R3 gates. Callers must have logged the access first.
    """
    with conn() as c:
        # No birthdate and no fin_hmac: picking the right record needs a name
        # and a date of first verification. Search is the discovery step, and
        # it should hand back the least that lets an operator choose which
        # record to open — the full record is one audited click away.
        rows = c.execute(
            """SELECT id, display_name, verified_at
               FROM identities WHERE display_name ILIKE %s
               ORDER BY verified_at DESC LIMIT %s""",
            (f"%{query}%", limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_identity_privileged(identity_id: str) -> dict | None:
    """
    Existence check that does not run under RLS — for the CLI, which has no
    session and therefore no identity to scope to.
    """
    with conn() as c:
        row = c.execute(
            "SELECT * FROM identities WHERE id = %s", (identity_id,)
        ).fetchone()
        return dict(row) if row else None


def identity_full(identity_id: str) -> dict | None:
    """
    One person's record, for an operator. Privileged; log before calling.

    Explicit columns, not SELECT *: fin_hmac is deliberately absent. registry()
    withholds it because it is a stable pseudonymous key for correlating a
    person across records, and that reasoning does not stop applying because
    the reader is an operator — nothing in a compliance review needs it, and a
    * would have quietly re-added it (and any future column) to this response.
    Proof signatures are omitted for the same reason: bulky, and not what a
    reviewer is looking at.
    """
    with conn() as c:
        row = c.execute(
            """SELECT id, display_name, birthdate, verified_at, last_seen_at
               FROM identities WHERE id = %s""", (identity_id,)
        ).fetchone()
        if not row:
            return None
        rec = dict(row)
        rec["bindings"] = [dict(b) for b in c.execute(
            """SELECT id, chain, address, status, proof_method, requested_at,
                      activates_at, activated_at, archived_at
               FROM wallet_bindings WHERE identity_id = %s
               ORDER BY requested_at DESC""", (identity_id,)).fetchall()]
        return rec


# ------------------------------------------------------------- webauthn (R2)

def add_credential(identity_id: str, credential_id: str, public_key: str,
                   sign_count: int, label: str = "") -> None:
    with user_conn(identity_id) as c:
        c.execute(
            """INSERT INTO webauthn_credentials
                   (credential_id, identity_id, public_key, sign_count, label, created_at)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (credential_id, identity_id, public_key, sign_count, label, iso(now())),
        )


def credentials_of(identity_id: str) -> list[dict]:
    with user_conn(identity_id) as c:
        rows = c.execute(
            "SELECT credential_id, label, created_at, last_used_at "
            "FROM webauthn_credentials ORDER BY created_at",
        ).fetchall()
        return [dict(r) for r in rows]


def delete_credential(identity_id: str, credential_id: str) -> bool:
    """
    Revoke one passkey. RLS-scoped, so the row policy — not the WHERE clause —
    is what stops one identity deleting another's credential.
    """
    with user_conn(identity_id) as c:
        return c.execute(
            "DELETE FROM webauthn_credentials WHERE credential_id = %s",
            (credential_id,),
        ).rowcount == 1


def credential_by_id(credential_id: str) -> dict | None:
    """
    Privileged on purpose: a return-login has no session yet, so there is no
    identity to scope to — resolving the credential is how the identity is
    discovered. Keyed by the authenticator's own credential id, which is
    unguessable and proves nothing on its own; the signature check is what
    authenticates.
    """
    with conn() as c:
        row = c.execute(
            "SELECT * FROM webauthn_credentials WHERE credential_id = %s",
            (credential_id,),
        ).fetchone()
        return dict(row) if row else None


def touch_credential(credential_id: str, sign_count: int) -> None:
    with conn() as c:
        c.execute(
            "UPDATE webauthn_credentials SET sign_count = %s, last_used_at = %s "
            "WHERE credential_id = %s",
            (sign_count, iso(now()), credential_id),
        )


# ------------------------------------------------------------------- nonces

def issue_nonce(nonce: str, address: str, chain: str, message: str,
                ttl_seconds: int, issued_via: str = "wallet") -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO auth_nonces (nonce, address, chain, message, expires_at, issued_via) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (nonce, address, chain, message,
             iso(now() + timedelta(seconds=ttl_seconds)), issued_via),
        )


def consume_nonce(nonce: str, address: str, chain: str) -> tuple[bool, str, str, str]:
    """
    Single use, bound to the address and chain it was issued for.
    Returns the exact message that was issued, so the caller verifies the
    signature against server state rather than anything the client sent —
    plus the server-recorded issued_via, so binding provenance cannot be
    claimed by the client.
    """
    with conn() as c:
        # FOR UPDATE + the consumed check inside one transaction: two racing
        # binds presenting the same nonce serialize here, and the loser sees
        # consumed=1. SQLite got this for free from its single-writer model;
        # real concurrency has to ask for the row lock.
        row = c.execute(
            "SELECT * FROM auth_nonces WHERE nonce = %s FOR UPDATE", (nonce,)
        ).fetchone()
        if not row:
            return False, "unknown nonce", "", ""
        if row["consumed"]:
            return False, "nonce already used", "", ""
        if parse(row["expires_at"]) < now():
            return False, "nonce expired", "", ""
        # Compare in the canonical form, not blanket .lower(): base58 is
        # case-sensitive, so lowercasing a Solana address would treat two
        # different public keys as one.
        if (normalize_address(chain, row["address"]) != normalize_address(chain, address)
                or row["chain"] != chain):
            return False, "nonce was issued for a different address or chain", "", ""
        c.execute("UPDATE auth_nonces SET consumed = 1 WHERE nonce = %s", (nonce,))
        return True, "", row["message"], row["issued_via"]


# ------------------------------------------------------------------ bindings

class BindingConflict(Exception):
    """A bind lost a race to a unique index. The message is safe for the client."""


class _NotPending(Exception):
    """Internal: a promotion candidate stopped being pending under us."""


def active_binding(identity_id: str, chain: str) -> dict | None:
    with user_conn(identity_id) as c:
        row = c.execute(
            """SELECT * FROM wallet_bindings
               WHERE identity_id = %s AND chain = %s AND status = 'active'""",
            (identity_id, chain),
        ).fetchone()
        return dict(row) if row else None


def pending_binding(identity_id: str, chain: str) -> dict | None:
    with user_conn(identity_id) as c:
        row = c.execute(
            """SELECT * FROM wallet_bindings
               WHERE identity_id = %s AND chain = %s AND status = 'pending'""",
            (identity_id, chain),
        ).fetchone()
        return dict(row) if row else None


def address_claimed_by_other(chain: str, address: str, identity_id: str) -> bool:
    """
    The sybil check, enforced in code as well as by the index. Compares the
    canonical address so this check and the unique indexes agree on what "the
    same address" means — a mismatch there is how a case-variant race slips
    past both.
    """
    with conn() as c:
        row = c.execute(
            """SELECT identity_id FROM wallet_bindings
               WHERE chain = %s AND address_norm = %s
                 AND status IN ('active','pending')""",
            (chain, normalize_address(chain, address)),
        ).fetchone()
        return bool(row) and row["identity_id"] != identity_id


def create_binding(identity_id, chain, address, nonce, sig, message,
                   cooling_hours: int, proof_method: str = "wallet") -> dict:
    """
    First binding for a chain activates immediately.
    A replacement goes pending for `cooling_hours`; the incumbent stays active
    until the new one activates, so there is no gap in service.
    """
    incumbent = active_binding(identity_id, chain)
    t = now()
    # The INSERT below runs RLS-scoped, so WITH CHECK refuses a row whose
    # identity_id is anyone else's — a binding cannot be written on another
    # person's behalf even if application code passed the wrong id.
    row = {
        "id": str(uuid.uuid4()),
        "identity_id": identity_id,
        "chain": chain,
        # Stored as the wallet spelled it (EIP-55 checksum is a typo-catching
        # display feature worth keeping). Uniqueness is enforced on the
        # database-generated address_norm, so case cannot fork a row.
        "address": address,
        "proof_nonce": nonce,
        "proof_sig": sig,
        "proof_message": message,
        "proof_method": proof_method,
        "requested_at": iso(t),
        "status": "active" if incumbent is None else "pending",
        "activates_at": None if incumbent is None else iso(t + timedelta(hours=cooling_hours)),
        "activated_at": iso(t) if incumbent is None else None,
        "archived_at": None,
    }
    with user_conn(identity_id) as c:
        try:
            c.execute(
                """INSERT INTO wallet_bindings
                   (id, identity_id, chain, address, status, proof_nonce, proof_sig,
                    proof_message, proof_method, requested_at, activates_at,
                    activated_at, archived_at)
                   VALUES (%(id)s,%(identity_id)s,%(chain)s,%(address)s,%(status)s,
                           %(proof_nonce)s,%(proof_sig)s,%(proof_message)s,
                           %(proof_method)s,%(requested_at)s,%(activates_at)s,
                           %(activated_at)s,%(archived_at)s)""",
                row,
            )
        except psycopg.errors.UniqueViolation as e:
            # The app-level checks are check-then-insert; a concurrent bind can
            # land between them and this INSERT. The unique indexes hold the
            # invariant — this only translates the loss into a client-safe
            # message instead of a 500. Postgres names the violated index in
            # diag.constraint_name: a *_chain_address index means another
            # identity claimed this wallet; *_identity_chain means this
            # identity double-submitted.
            name = (e.diag.constraint_name or "")
            if name.endswith("_chain_address"):
                raise BindingConflict(
                    "this wallet is already bound to a different Fayda identity"
                ) from e
            raise BindingConflict(
                "a binding on this chain is already active or pending — reload and retry"
            ) from e
    return row


def cancel_pending(identity_id: str, chain: str) -> bool:
    """The escape hatch. If an attacker initiates a swap, the real user kills it here."""
    with user_conn(identity_id) as c:
        # Read and write in ONE transaction, holding the row lock: promote_due
        # runs on every read (including the unauthenticated /api/registry) and
        # takes the same lock, so cancel either happens entirely before a
        # promotion or entirely after it. Under the old SQLite global lock this
        # atomicity was free; with real concurrency an unguarded
        # read-then-write let a concurrent promotion resurrect the cancelled
        # row and activate an attacker's swap — the precise failure the cooling
        # period exists to prevent.
        p = c.execute(
            """SELECT id FROM wallet_bindings
               WHERE identity_id = %s AND chain = %s AND status = 'pending'
               FOR UPDATE""",
            (identity_id, chain),
        ).fetchone()
        if not p:
            return False
        # AND status='pending' so the UPDATE is a no-op if the row stopped
        # being pending after the lock was granted.
        n = c.execute(
            "UPDATE wallet_bindings SET status='cancelled', archived_at=%s "
            "WHERE id=%s AND status='pending'",
            (iso(now()), p["id"]),
        ).rowcount
    return n == 1


def promote_due(identity_id: str | None = None) -> int:
    """
    Activate pending bindings whose cooling period has elapsed, archiving the
    incumbent in the same transaction. In production this is a scheduled job.
    """
    promoted = 0
    with conn() as c:
        # Lock the candidate rows and re-read them under the lock. Without
        # this, a cancel committed between the SELECT and the UPDATE was
        # overwritten by the stale snapshot below and the cancelled row went
        # active. ORDER BY id keeps two concurrent promoters taking locks in
        # the same sequence, so they queue instead of deadlocking; SKIP LOCKED
        # leaves rows another promoter already holds to that promoter rather
        # than blocking a read behind it.
        # COLLATE "C": activates_at is TEXT and this database's default
        # collation does not order ISO-8601 chronologically below one second
        # (see sweep_expired). Byte order does. The row is re-checked in Python
        # below regardless, so this is defence in depth, not the only guard.
        q = ('SELECT * FROM wallet_bindings WHERE status=\'pending\''
             ' AND activates_at COLLATE "C" <= %s')
        args: tuple = (iso(now()),)
        if identity_id:
            q += " AND identity_id = %s"
            args = (iso(now()), identity_id)
        q += " ORDER BY id FOR UPDATE SKIP LOCKED"
        for p in c.execute(q, args).fetchall():
            if parse(p["activates_at"]) > now():
                continue
            # Savepoint per promotion: a pending row that raced past the app
            # checks can still collide with ux_active_chain_address here (its
            # address went active for another identity while it cooled). This
            # runs on every /api/me and /api/registry read, so an uncaught
            # IntegrityError would 500 every read forever. Roll back just this
            # promotion — keeping the loser's incumbent active — and cancel the
            # conflicting row so it never retries. ROLLBACK TO also clears the
            # aborted-transaction state Postgres enters on the failed INSERT.
            c.execute("SAVEPOINT promote_one")
            try:
                c.execute(
                    """UPDATE wallet_bindings SET status='archived', archived_at=%s
                       WHERE identity_id=%s AND chain=%s AND status='active'""",
                    (iso(now()), p["identity_id"], p["chain"]),
                )
                # AND status='pending': belt to the row lock's braces. If this
                # row stopped being pending, promote nothing — a cancelled
                # binding must never come back to life.
                if c.execute(
                    "UPDATE wallet_bindings SET status='active', activated_at=%s "
                    "WHERE id=%s AND status='pending'",
                    (iso(now()), p["id"]),
                ).rowcount != 1:
                    raise _NotPending
            except psycopg.errors.UniqueViolation:
                # Undo this promotion only — the loser's incumbent stays
                # active — then cancel the conflicting row so it cannot
                # re-detonate on the next read.
                c.execute("ROLLBACK TO promote_one")
                c.execute(
                    "UPDATE wallet_bindings SET status='cancelled', archived_at=%s "
                    "WHERE id=%s AND status='pending'",
                    (iso(now()), p["id"]),
                )
                c.execute("RELEASE promote_one")
            except _NotPending:
                # Undo the incumbent archival: the replacement it was making
                # room for is no longer promotable.
                c.execute("ROLLBACK TO promote_one")
                c.execute("RELEASE promote_one")
            else:
                # RELEASE only on the success path: ROLLBACK TO would undo the
                # promotion this iteration just made.
                c.execute("RELEASE promote_one")
                promoted += 1
    return promoted


def force_due(identity_id: str, chain: str) -> bool:
    """DEV ONLY. Backdates activates_at so the cooling period can be demonstrated."""
    p = pending_binding(identity_id, chain)
    if not p:
        return False
    with conn() as c:
        c.execute(
            "UPDATE wallet_bindings SET activates_at=%s WHERE id=%s",
            (iso(now() - timedelta(seconds=1)), p["id"]),
        )
    return True


def bindings_of(identity_id: str) -> list[dict]:
    """
    Every binding for an identity, newest first — one query the caller slices
    into active/pending/history. /api/me needs all three; asking separately
    cost five pool checkouts, and a checkout on a managed database is a
    network round trip, not a function call.
    """
    return history(identity_id)


def history(identity_id: str) -> list[dict]:
    with user_conn(identity_id) as c:
        rows = c.execute(
            """SELECT * FROM wallet_bindings WHERE identity_id = %s
               ORDER BY requested_at DESC""",
            (identity_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def registry() -> list[dict]:
    """
    The signed-in view of the registry: who is verified and which wallets they
    hold. fin_hmac is deliberately absent — it cannot re-derive the FIN, but it
    is a stable pseudonymous key that lets any reader correlate one person
    across every row, and this list is now read by other users rather than by a
    demo inspector. Operators reach the fuller view through R3's audited path.
    """
    with conn() as c:
        rows = c.execute(
            """SELECT i.display_name, i.verified_at,
                      (SELECT address FROM wallet_bindings b
                        WHERE b.identity_id=i.id AND b.chain='evm' AND b.status='active') AS evm,
                      (SELECT address FROM wallet_bindings b
                        WHERE b.identity_id=i.id AND b.chain='solana' AND b.status='active') AS solana
               FROM identities i
               -- Only people who actually hold a binding. An identity with no
               -- wallet contributes nothing a reader can use while still
               -- disclosing that this person completed Fayda verification here
               -- — the sensitive half of the row without the useful half.
               WHERE EXISTS (SELECT 1 FROM wallet_bindings b
                             WHERE b.identity_id = i.id AND b.status = 'active')
               ORDER BY i.verified_at DESC"""
        ).fetchall()
        # No internal id either: it is the RLS scoping key and the join key for
        # every per-identity table, so it does not belong in a list handed to
        # other users. The registry answers "is this wallet claimed, and by
        # whom", which needs neither.
        return [dict(r) for r in rows]


if __name__ == "__main__":
    import sys

    # The only supported way to authorize reset() against a database. Deliberate,
    # explicit, and aimed at one target — never a side effect of running the app
    # or the test suite.
    if sys.argv[1:2] == ["grant-operator"]:
        # Operator membership is granted here and nowhere else — no HTTP route
        # creates operators, because a route that grants privilege is a route
        # that can be tricked into granting it.
        if len(sys.argv) < 3:
            print("usage: python backend/store.py grant-operator <identity_id> [note]")
            sys.exit(2)
        target = sys.argv[2]
        init()
        if not get_identity_privileged(target):
            print(f"refused: no identity {target}")
            sys.exit(1)
        grant_operator(target, granted_by=cli_actor(), note=" ".join(sys.argv[3:]))
        print(f"granted operator: {target}")
        print("Every lookup this identity makes is written to access_log.")
    elif sys.argv[1:2] == ["revoke-operator"]:
        if len(sys.argv) < 3:
            print("usage: python backend/store.py revoke-operator <identity_id>")
            sys.exit(2)
        init()
        print("revoked" if revoke_operator(sys.argv[2], revoked_by=cli_actor())
              else "was not an operator")
    elif sys.argv[1:2] == ["mark-disposable"]:
        init()
        try:
            target = mark_disposable()
        except RuntimeError as e:
            # A refusal is an expected outcome of this command, not a crash.
            print(f"refused: {e}")
            sys.exit(1)
        print(f"marked disposable: {target}")
        print("store.reset() and /api/dev/reset may now drop this database's tables.")
    else:
        print("usage: python backend/store.py <command>\n"
              "  grant-operator <identity_id> [note]   grant compliance access\n"
              "  revoke-operator <identity_id>         remove it\n"
              "  mark-disposable                       (APP_ENV=dev) allow reset()")
        sys.exit(2)
