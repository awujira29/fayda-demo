"""
SQLite storage layer.

The two partial unique indexes below are the whole point of this demo:
  - one ACTIVE wallet per (identity, chain)
  - one ACTIVE identity per (chain, address)

The second is the sybil constraint. Without it, one wallet could be claimed
by two different Fayda identities, and the "one verified person, one wallet"
guarantee collapses.
"""

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent / "registry.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

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
    requested_at  TEXT NOT NULL,
    activates_at  TEXT,
    activated_at  TEXT,
    archived_at   TEXT
);

-- One ACTIVE wallet per identity per chain.
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_identity_chain
    ON wallet_bindings (identity_id, chain) WHERE status = 'active';

-- One ACTIVE identity per address per chain. This is the sybil constraint.
CREATE UNIQUE INDEX IF NOT EXISTS ux_active_chain_address
    ON wallet_bindings (chain, address) WHERE status = 'active';

-- Only one pending replacement in flight per identity per chain.
CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_identity_chain
    ON wallet_bindings (identity_id, chain) WHERE status = 'pending';

-- One PENDING claim per address per chain, across identities. The app-level
-- sybil check covers pending rows but is check-then-insert; two identities
-- racing that window could each park a pending row on the same address, and
-- the loser would then hit ux_active_chain_address inside promote_due on every
-- read. Close the window at the DB layer, like the active tier.
CREATE UNIQUE INDEX IF NOT EXISTS ux_pending_chain_address
    ON wallet_bindings (chain, address) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS auth_nonces (
    nonce       TEXT PRIMARY KEY,
    address     TEXT NOT NULL,
    chain       TEXT NOT NULL,
    message     TEXT NOT NULL,   -- exact text issued; never trust the client's copy
    expires_at  TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0
);
"""


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)


def reset():
    if DB_PATH.exists():
        DB_PATH.unlink()
    for suffix in ("-wal", "-shm"):
        p = Path(str(DB_PATH) + suffix)
        if p.exists():
            p.unlink()
    init()


# ---------------------------------------------------------------- identities

def upsert_identity(fin_hmac: str, display_name: str, birthdate: str) -> dict:
    """Called after a successful Fayda authentication."""
    with conn() as c:
        row = c.execute(
            "SELECT * FROM identities WHERE fin_hmac = ?", (fin_hmac,)
        ).fetchone()
        if row:
            c.execute(
                "UPDATE identities SET last_seen_at = ? WHERE id = ?",
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
        c.execute(
            """INSERT INTO identities (id, fin_hmac, display_name, birthdate,
                                       verified_at, last_seen_at)
               VALUES (:id, :fin_hmac, :display_name, :birthdate,
                       :verified_at, :last_seen_at)""",
            ident,
        )
        return ident


def get_identity(identity_id: str) -> dict | None:
    with conn() as c:
        row = c.execute(
            "SELECT * FROM identities WHERE id = ?", (identity_id,)
        ).fetchone()
        return dict(row) if row else None


# ------------------------------------------------------------------- nonces

def issue_nonce(nonce: str, address: str, chain: str, message: str,
                ttl_seconds: int) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO auth_nonces (nonce, address, chain, message, expires_at) "
            "VALUES (?,?,?,?,?)",
            (nonce, address, chain, message,
             iso(now() + timedelta(seconds=ttl_seconds))),
        )


def consume_nonce(nonce: str, address: str, chain: str) -> tuple[bool, str, str]:
    """
    Single use, bound to the address and chain it was issued for.
    Returns the exact message that was issued, so the caller verifies the
    signature against server state rather than anything the client sent.
    """
    with conn() as c:
        row = c.execute(
            "SELECT * FROM auth_nonces WHERE nonce = ?", (nonce,)
        ).fetchone()
        if not row:
            return False, "unknown nonce", ""
        if row["consumed"]:
            return False, "nonce already used", ""
        if parse(row["expires_at"]) < now():
            return False, "nonce expired", ""
        if row["address"].lower() != address.lower() or row["chain"] != chain:
            return False, "nonce was issued for a different address or chain", ""
        c.execute("UPDATE auth_nonces SET consumed = 1 WHERE nonce = ?", (nonce,))
        return True, "", row["message"]


# ------------------------------------------------------------------ bindings

def active_binding(identity_id: str, chain: str) -> dict | None:
    with conn() as c:
        row = c.execute(
            """SELECT * FROM wallet_bindings
               WHERE identity_id = ? AND chain = ? AND status = 'active'""",
            (identity_id, chain),
        ).fetchone()
        return dict(row) if row else None


def pending_binding(identity_id: str, chain: str) -> dict | None:
    with conn() as c:
        row = c.execute(
            """SELECT * FROM wallet_bindings
               WHERE identity_id = ? AND chain = ? AND status = 'pending'""",
            (identity_id, chain),
        ).fetchone()
        return dict(row) if row else None


def address_claimed_by_other(chain: str, address: str, identity_id: str) -> bool:
    """The sybil check, enforced in code as well as by the index."""
    with conn() as c:
        row = c.execute(
            """SELECT identity_id FROM wallet_bindings
               WHERE chain = ? AND LOWER(address) = LOWER(?)
                 AND status IN ('active','pending')""",
            (chain, address),
        ).fetchone()
        return bool(row) and row["identity_id"] != identity_id


def create_binding(identity_id, chain, address, nonce, sig, message,
                   cooling_hours: int) -> dict:
    """
    First binding for a chain activates immediately.
    A replacement goes pending for `cooling_hours`; the incumbent stays active
    until the new one activates, so there is no gap in service.
    """
    incumbent = active_binding(identity_id, chain)
    t = now()
    row = {
        "id": str(uuid.uuid4()),
        "identity_id": identity_id,
        "chain": chain,
        "address": address,
        "proof_nonce": nonce,
        "proof_sig": sig,
        "proof_message": message,
        "requested_at": iso(t),
        "status": "active" if incumbent is None else "pending",
        "activates_at": None if incumbent is None else iso(t + timedelta(hours=cooling_hours)),
        "activated_at": iso(t) if incumbent is None else None,
        "archived_at": None,
    }
    with conn() as c:
        c.execute(
            """INSERT INTO wallet_bindings
               (id, identity_id, chain, address, status, proof_nonce, proof_sig,
                proof_message, requested_at, activates_at, activated_at, archived_at)
               VALUES (:id,:identity_id,:chain,:address,:status,:proof_nonce,:proof_sig,
                       :proof_message,:requested_at,:activates_at,:activated_at,:archived_at)""",
            row,
        )
    return row


def cancel_pending(identity_id: str, chain: str) -> bool:
    """The escape hatch. If an attacker initiates a swap, the real user kills it here."""
    p = pending_binding(identity_id, chain)
    if not p:
        return False
    with conn() as c:
        c.execute(
            "UPDATE wallet_bindings SET status='cancelled', archived_at=? WHERE id=?",
            (iso(now()), p["id"]),
        )
    return True


def promote_due(identity_id: str | None = None) -> int:
    """
    Activate pending bindings whose cooling period has elapsed, archiving the
    incumbent in the same transaction. In production this is a scheduled job.
    """
    promoted = 0
    with conn() as c:
        q = "SELECT * FROM wallet_bindings WHERE status='pending'"
        args: tuple = ()
        if identity_id:
            q += " AND identity_id = ?"
            args = (identity_id,)
        for p in c.execute(q, args).fetchall():
            if parse(p["activates_at"]) > now():
                continue
            # Savepoint per promotion: a pending row that raced past the app
            # checks can still collide with ux_active_chain_address here (its
            # address went active for another identity while it cooled). This
            # runs on every /api/me and /api/registry read, so an uncaught
            # IntegrityError would 500 every read forever. Roll back just this
            # promotion — keeping the loser's incumbent active — and cancel the
            # conflicting row so it never retries.
            c.execute("SAVEPOINT promote_one")
            try:
                c.execute(
                    """UPDATE wallet_bindings SET status='archived', archived_at=?
                       WHERE identity_id=? AND chain=? AND status='active'""",
                    (iso(now()), p["identity_id"], p["chain"]),
                )
                c.execute(
                    "UPDATE wallet_bindings SET status='active', activated_at=? WHERE id=?",
                    (iso(now()), p["id"]),
                )
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK TO promote_one")
                c.execute(
                    "UPDATE wallet_bindings SET status='cancelled', archived_at=? WHERE id=?",
                    (iso(now()), p["id"]),
                )
            else:
                promoted += 1
            finally:
                c.execute("RELEASE promote_one")
    return promoted


def force_due(identity_id: str, chain: str) -> bool:
    """DEV ONLY. Backdates activates_at so the cooling period can be demonstrated."""
    p = pending_binding(identity_id, chain)
    if not p:
        return False
    with conn() as c:
        c.execute(
            "UPDATE wallet_bindings SET activates_at=? WHERE id=?",
            (iso(now() - timedelta(seconds=1)), p["id"]),
        )
    return True


def history(identity_id: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            """SELECT * FROM wallet_bindings WHERE identity_id = ?
               ORDER BY requested_at DESC""",
            (identity_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def registry() -> list[dict]:
    """Everything, for the inspector panel."""
    with conn() as c:
        rows = c.execute(
            """SELECT i.id, i.display_name, i.fin_hmac, i.verified_at,
                      (SELECT address FROM wallet_bindings b
                        WHERE b.identity_id=i.id AND b.chain='evm' AND b.status='active') AS evm,
                      (SELECT address FROM wallet_bindings b
                        WHERE b.identity_id=i.id AND b.chain='solana' AND b.status='active') AS solana
               FROM identities i ORDER BY i.verified_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]
