"""
Rate limiting (R6).

Every audit round said the same thing: nothing anywhere had any. That is what
made several findings worse than they had to be — the unbounded session table,
the access log's count(*) on a route any session can poll, the quadratic decode
before it was gated, and the outbound amplification at the IdP once R5 is live.
A limiter does not fix those individually; it bounds all of them at once.

Deliberately in-process, and honest about what that means: with N app
instances the effective limit is N x the configured rate. A shared counter
belongs in Redis, and there is no Redis here. Putting it in Postgres would add
a write to the hot path of every request — spending the exact resource the
limiter exists to protect. So this bounds a single instance well, and the
docstring says so rather than implying a cluster-wide guarantee.

Buckets are keyed by client IP and route class. IP is a weak identity behind a
proxy, which is why the trusted-header behaviour is explicit below rather than
inherited from whatever X-Forwarded-For happens to say.
"""

import ipaddress
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class Rule:
    """A token bucket: `burst` requests immediately, refilling at `per_second`."""
    per_second: float
    burst: int
    name: str = ""


# Tiers, cheapest to most expensive. The numbers are deliberately generous for
# a human and restrictive for a loop — the goal is to stop a script, not to
# make the UI feel slow.
RULES: dict[str, Rule] = {
    # Anonymous session-minting. /login writes a row per hit.
    #
    # A burst of 10 was too tight: one complete sign-in spends four tokens
    # (/login, /authorize, /authorize/confirm, /callback), so behind a shared
    # NAT address the third visitor was refused. Nothing about the source
    # address distinguishes a household from an attacker, so the allowance has
    # to fit several real people arriving together; the refill rate is what
    # actually bounds a sustained loop.
    "login": Rule(per_second=1.0, burst=40, name="login"),
    # Cryptographic work and durable writes.
    "bind": Rule(per_second=1.0, burst=15, name="bind"),
    # Anything reaching a third party or scanning a growing table.
    "expensive": Rule(per_second=0.5, burst=10, name="expensive"),
    # Ordinary reads. Loose enough that normal polling never notices.
    "read": Rule(per_second=10.0, burst=120, name="read"),
}

# Route prefix -> tier. Longest prefix wins, so a specific rule can sit under a
# general one.
ROUTES: list[tuple[str, str]] = [
    ("/login", "login"),
    ("/callback", "login"),
    ("/authorize", "login"),
    ("/api/passkey/login", "login"),
    ("/api/passkey/register", "bind"),
    # Revocation writes and kills sessions; it does not belong in the loose
    # read tier just because it was the one passkey route nobody listed.
    ("/api/passkey/revoke", "bind"),
    ("/api/wallet/", "bind"),
    ("/api/operator/", "expensive"),
    ("/api/registry", "expensive"),
    ("/api/me/access-log", "expensive"),
    ("/api/dev/", "bind"),
    # The OIDC token/userinfo surface. The app's own loopback self-calls are
    # exempt (see _is_self_call); a REMOTE caller hitting it is not doing
    # anything a browser flow does, and it was falling through to the loose
    # read tier.
    ("/v1/", "login"),
]

# Trust a forwarded client IP only when the platform is known to set it. On
# Render the app sits behind their proxy and the socket peer is always the
# proxy, so without this every visitor shares one bucket. Off by default: a
# spoofable header as the limiter key is worse than no limiter, because it
# gives an attacker a fresh bucket per request.
TRUST_FORWARDED = os.getenv("TRUST_PROXY_HEADERS", "").lower() in ("1", "true", "yes")

# On by default; a deployment has to opt OUT. The end-to-end suite drives
# deliberate bursts (racing binds, ten-round loops) that a limiter would
# correctly refuse, so it disables this for the server it drives and spawns a
# separate instance with limiting ON to test the limiter itself. Anything that
# can be turned off in production should default to on, and this does.
ENABLED = os.getenv("RATE_LIMIT", "on").lower() not in ("off", "0", "false", "no")

# How many proxies sit in front of this process. One on Render. Used to count
# X-Forwarded-For from the right; see client_key.
try:
    TRUSTED_HOPS = max(1, int(os.getenv("TRUSTED_PROXY_HOPS", "1")))
except ValueError:
    TRUSTED_HOPS = 1


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# The app calls its own OIDC endpoints server-to-server during a login (token
# exchange, userinfo), and limiting those would make a deployment throttle its
# own sign-in flow.
#
# Narrow on BOTH axes deliberately: the caller must be loopback AND the path
# must be the self-call surface. Exempting loopback wholesale would leave
# anything sharing the host — another container, a compromised sidecar, a
# reverse proxy terminating on 127.0.0.1 — completely unlimited, which is a
# much larger hole than the one being closed. No browser flow touches /v1/.
SELF_CALL_PREFIX = "/v1/"


def _is_self_call(path: str, key: str) -> bool:
    if not path.startswith(SELF_CALL_PREFIX):
        return False
    try:
        return ipaddress.ip_address(key).is_loopback
    except ValueError:
        return False

_LOCK = threading.Lock()
# Insertion-ordered, and every touch re-inserts at the end, so the front is the
# least recently used and eviction is O(1).
_BUCKETS: "OrderedDict[tuple[str, str], tuple[float, float]]" = OrderedDict()
_MAX_BUCKETS = 20_000


def tier_for(path: str) -> str:
    best, best_len = "read", -1
    for prefix, tier in ROUTES:
        if path.startswith(prefix) and len(prefix) > best_len:
            best, best_len = tier, len(prefix)
    return best


def client_key(scope) -> str:
    """
    The bucket key. Getting this wrong is worse than having no limiter: a
    caller-chosen key means a fresh bucket per request.

    X-Forwarded-For is a list that each proxy APPENDS to, so the left-most
    entry is whatever the original caller sent — fully attacker-controlled.
    Reading it from the left made the limiter a no-op wherever
    TRUST_PROXY_HEADERS was set, which render.yaml sets for production
    (measured: 60/60 spoofed requests allowed, versus a refusal at 13
    unspoofed), and additionally let an attacker drain a named victim's bucket.
    Count from the RIGHT instead: with `hops` trusted proxies in front, the
    entry that many from the end is the address the outermost trusted proxy
    actually observed, and everything to its left is unverifiable.
    """
    if TRUST_FORWARDED:
        # ALL the headers, joined — not just the first one. A request may carry
        # several X-Forwarded-For headers, and per RFC 7230 that is equivalent
        # to one comma-joined value in order. Reading only the first and
        # stopping left position 0 attacker-controlled whenever the proxy emits
        # its own header rather than appending to the caller's: 70 requests
        # claiming 127.0.0.1 in a leading header drew 0 refusals where an
        # honest client drew 30.
        values = [v.decode("latin-1") for (n, v) in scope.get("headers", [])
                  if n == b"x-forwarded-for"]
        if values:
            parts = [p.strip() for p in ",".join(values).split(",") if p.strip()]
            if len(parts) >= TRUSTED_HOPS:
                candidate = parts[-TRUSTED_HOPS][:64]
                if _is_ip(candidate):
                    return candidate
            # Too few entries, or not an address: the header is not saying what
            # a trusted proxy would say, so use the peer rather than trust it.
    return peer_of(scope)


def peer_of(scope) -> str:
    """The socket peer — never caller-influenced, whatever the headers say."""
    peer = scope.get("client")
    return peer[0] if peer else "unknown"


def check(path: str, key: str, now: float | None = None,
          peer: str | None = None) -> tuple[bool, Rule, float]:
    """
    Returns (allowed, rule, retry_after_seconds). Pure token bucket, so a
    caller that stays under the rate is never refused however long it runs.
    """
    now = time.monotonic() if now is None else now
    tier = tier_for(path)
    rule = RULES[tier]
    # The server's calls to its own OIDC endpoints are not user traffic. Judged
    # on the SOCKET PEER, never on `key`: key can be header-derived, so testing
    # it would hand the exemption to anyone who wrote 127.0.0.1 into
    # X-Forwarded-For. Defaults to key only when no peer was supplied, which is
    # the direct-call path in tests.
    if _is_self_call(path, peer if peer is not None else key):
        return True, rule, 0.0
    bucket_key = (key, tier)
    with _LOCK:
        if len(_BUCKETS) >= _MAX_BUCKETS and bucket_key not in _BUCKETS:
            # The bucket table is itself attacker-growable — one entry per
            # source address. Evict in O(1) from the front of an insertion-
            # ordered dict, which is LRU because every touch below moves the
            # key to the end. Scanning for the oldest with min() was O(n) on
            # every new key once full: a lock held for ~0.8ms at 20k entries,
            # i.e. a denial of service inside the denial-of-service defence.
            _BUCKETS.popitem(last=False)
        tokens, last = _BUCKETS.pop(bucket_key, (float(rule.burst), now))
        tokens = min(float(rule.burst), tokens + (now - last) * rule.per_second)
        if tokens < 1.0:
            _BUCKETS[bucket_key] = (tokens, now)
            return False, rule, max(1.0, (1.0 - tokens) / rule.per_second)
        _BUCKETS[bucket_key] = (tokens - 1.0, now)
        return True, rule, 0.0


def reset() -> None:
    """Test seam."""
    with _LOCK:
        _BUCKETS.clear()
