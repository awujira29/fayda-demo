"""
Read-only on-chain transaction lookup (R4).

Public blockchain data, fetched from an explorer API for a wallet the registry
already knows is bound. Four rules shape everything here:

  1. **Never source of truth.** On-chain data is public and refetchable, so it
     is cached in memory with a TTL and never written to the database. A cache
     that outlives the process cannot be mistaken for a record.
  2. **Never fabricate.** With no provider configured the answer is "not
     configured", not an empty list and certainly not sample data — an operator
     reading a compliance screen must be able to tell "no transactions" from
     "we did not look".
  3. **Never block on it.** Every call is timeout-bounded and every failure is
     a status, not an exception; the caller shows the in-app timeline first and
     asks for this separately.
  4. **Never write.** No key material, no RPC that can send anything. The only
     verb is read.

Provider is configured by env (CHAIN_EXPLORER_URL / CHAIN_EXPLORER_KEY). The
one for Solana is not wired: the registry does not yet accept Solana
connections, and guessing at an API we have not exercised would be the same
dishonesty as fabricating the data.
"""

import json
import os
import threading
import time
from urllib.parse import parse_qsl

import httpx


def _clean(v, limit: int) -> str:
    """
    Provider strings are third-party input reaching an operator's screen and
    the JSON response. Bound the length and drop NUL, which is unrepresentable
    in Postgres text should any of this ever be quoted into a log detail.
    """
    return str(v if v is not None else "").replace("\x00", "")[:limit]

# Explorer endpoint in the Etherscan-compatible shape (module=account&
# action=txlist). Unset means unconfigured, which is a reported state.
EXPLORER_URL = os.getenv("CHAIN_EXPLORER_URL", "").strip()
EXPLORER_KEY = os.getenv("CHAIN_EXPLORER_KEY", "").strip()

def _int_env(name: str, default: int) -> int:
    """
    A malformed tuning value must not stop the app booting. chain.py is
    imported unconditionally by app.py, so an unparseable CHAIN_CACHE_TTL was a
    hard-down for the whole registry over an optional cache setting.
    """
    try:
        v = int(os.getenv(name, "").strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


CACHE_TTL_SECONDS = _int_env("CHAIN_CACHE_TTL", 300)
# Per-operation, and NOT sufficient on its own — see _read_bounded.
REQUEST_TIMEOUT_SECONDS = 8
# Absolute wall-clock budget for one lookup, connect through last byte. This
# is what actually bounds a worker thread.
TOTAL_BUDGET_SECONDS = 12
# 25 rows of transaction JSON is a few kilobytes; a megabyte is generous and
# still stops a provider making the server buffer hundreds of them.
MAX_RESPONSE_BYTES = 1_000_000
MAX_TX = 25

# address -> (fetched_at, payload). In memory only, and deliberately so: see
# rule 1. Bounded so a long-lived process cannot accumulate without limit.
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 512


def configured() -> bool:
    return bool(EXPLORER_URL)


def _cache_get(key: str) -> dict | None:
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if not hit:
            return None
        fetched_at, payload = hit
        if time.time() - fetched_at > CACHE_TTL_SECONDS:
            _CACHE.pop(key, None)
            return None
        return payload


def _cache_put(key: str, payload: dict) -> None:
    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            # Drop the oldest rather than grow without bound. This is a cache;
            # losing an entry costs one refetch of public data.
            oldest = min(_CACHE, key=lambda k: _CACHE[k][0])
            _CACHE.pop(oldest, None)
        _CACHE[key] = (time.time(), payload)


class _TooLarge(Exception):
    """The provider answered, but with more than we are willing to read."""


def _read_bounded(client: httpx.Client, url: str, params: dict,
                  deadline: float) -> tuple[int, bytes]:
    """
    Stream the response, enforcing a WALL-CLOCK deadline and a byte cap.

    httpx timeouts are per-operation: a provider that sends one byte just
    inside the read timeout, forever, never trips them. These endpoints are
    sync, so each such request pins a worker thread — enough of them and the
    whole service stops answering, including /login. The deadline below is
    absolute, and the cap stops a hostile or broken provider making us
    materialise hundreds of megabytes to return 25 rows.
    """
    chunks, total = [], 0
    with client.stream("GET", url, params=params) as r:
        for chunk in r.iter_bytes():
            if time.monotonic() > deadline:
                raise TimeoutError("explorer exceeded the total time budget")
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                # A distinct type, so the status says the provider WAS reached
                # and sent too much — "unreachable" would be a false report.
                raise _TooLarge("explorer response exceeded the size cap")
            chunks.append(chunk)
        return r.status_code, b"".join(chunks)


def _fetch(chain: str, address: str) -> dict:
    """One provider call. Returns a status payload; never raises."""
    if chain != "evm":
        return {"status": "unsupported_chain",
                "detail": f"no explorer is wired for {chain}", "transactions": []}
    if not configured():
        return {"status": "not_configured",
                "detail": "CHAIN_EXPLORER_URL is unset — no lookup was attempted",
                "transactions": []}

    # Preserve any query already on the configured URL. httpx's params=
    # REPLACES the query string, which silently dropped things like Etherscan
    # V2's ?chainid=1 — and the panel would then report another chain's
    # history as a successful answer for this one.
    base, _, existing = EXPLORER_URL.partition("?")
    params: dict = dict(parse_qsl(existing)) if existing else {}
    params.update({"module": "account", "action": "txlist", "address": address,
                   "startblock": 0, "endblock": 99999999, "page": 1,
                   "offset": MAX_TX, "sort": "desc"})
    if EXPLORER_KEY:
        params["apikey"] = EXPLORER_KEY

    # Everything that touches the provider or its output is inside one try:
    # parsing used to sit outside it, so a top-level JSON list or null came
    # back as an AttributeError and a 500 — after the access-log row had
    # already been written.
    try:
        deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
        timeout = httpx.Timeout(connect=4.0, read=REQUEST_TIMEOUT_SECONDS,
                                write=4.0, pool=2.0)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            status, raw = _read_bounded(client, base, params, deadline)
        if status != 200:
            return {"status": "provider_error",
                    "detail": f"explorer returned HTTP {status}",
                    "transactions": []}
        body = json.loads(raw)
        if not isinstance(body, dict):
            return {"status": "provider_error",
                    "detail": "explorer returned an unexpected shape",
                    "transactions": []}
        # Etherscan answers "0" with an empty result for an address with no
        # transactions, which is a legitimate answer, not an error.
        result = body.get("result")
        if not isinstance(result, list):
            return {"status": "provider_error",
                    "detail": str(body.get("message") or body.get("result"))[:200],
                    "transactions": []}
        lower = address.lower()
        txs = []
        for t in result[:MAX_TX]:
            if not isinstance(t, dict):
                # Silently skipping unreadable entries would report "ok, 0
                # transactions" for a response we could not actually parse —
                # the exact confusion between "none" and "we did not look"
                # that rule 2 exists to prevent.
                return {"status": "provider_error",
                        "detail": "explorer returned malformed transaction entries",
                        "transactions": []}
            frm = str(t.get("from", ""))
            txs.append({
                "hash": _clean(t.get("hash"), 80),
                "timestamp": _clean(t.get("timeStamp"), 20),
                "direction": "out" if frm.lower() == lower else "in",
                "counterparty": _clean(t.get("to") if frm.lower() == lower else frm, 64),
                "value_wei": _clean(t.get("value"), 40),
            })
        return {"status": "ok", "detail": "", "transactions": txs}
    except _TooLarge:
        return {"status": "provider_error",
                "detail": "explorer response exceeded the size cap",
                "transactions": []}
    except Exception as e:
        # A slow, broken or hostile explorer degrades the panel; it must never
        # break the request or leak a stack trace to an operator screen.
        return {"status": "provider_unreachable",
                "detail": type(e).__name__, "transactions": []}


def transactions(chain: str, address: str) -> dict:
    """
    Cached, read-only transaction history for one address.

    The payload always carries a `status` and a `cached` flag so a caller can
    render "we could not reach the explorer" differently from "this wallet has
    never transacted" — a distinction a compliance screen must not blur.
    """
    # Canonicalise per chain, exactly as the registry's sybil indexes do. A
    # blanket .lower() collapsed two DIFFERENT Solana public keys onto one
    # cache entry — base58 is case-sensitive — and the second caller was served
    # the first address's history, marked `cached: true`. On a compliance
    # screen that is one person's transactions shown under another's name.
    key = f"{chain}:{address.lower() if chain == 'evm' else address}"
    hit = _cache_get(key)
    if hit is not None:
        return {**hit, "cached": True}
    payload = _fetch(chain, address)
    # Only successful answers are cached. Caching a failure would hide a
    # recovered provider for the rest of the TTL.
    if payload["status"] == "ok":
        _cache_put(key, payload)
    return {**payload, "cached": False}


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
