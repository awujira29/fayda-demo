"""
Fayda identity to self-custodied wallet registry.

Internal proof of concept. The Fayda side is a real OIDC client pointed at a
local mock provider — swapping to production is an env var change, not a rewrite.
"""

import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timezone

import base58
import httpx
import jwt
import nacl.signing
import uvicorn
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.datastructures import Headers, MutableHeaders

import mock_esignet
import store
import verify as vf

# --------------------------------------------------------------------- config

# Two base URLs, split on who talks to them. BASE is where THIS process is
# reachable for server-to-server calls (token exchange, userinfo). PUBLIC is
# the origin the BROWSER must stay on for the whole OIDC dance: the session
# cookie is set during /callback, and if the browser ever touches the backend
# origin directly, the cookie lands there and every later API call from the
# frontend origin is unauthenticated. In two-process dev, PUBLIC is the Vite
# server (http://localhost:5173), which proxies /authorize and /callback here.
# Defaults keep the single-process case (t.py, no frontend) working: both
# collapse to the same origin.
BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000")
PUBLIC = os.getenv("PUBLIC_URL", BASE)
CLIENT_ID = os.getenv("FAYDA_CLIENT_ID", "fayda-wallet-demo")
AUTHORIZE_URL = os.getenv("FAYDA_AUTHORIZE_URL", f"{PUBLIC}/authorize")
TOKEN_URL = os.getenv("FAYDA_TOKEN_URL", f"{BASE}/v1/esignet/oauth/v2/token")
USERINFO_URL = os.getenv("FAYDA_USERINFO_URL", f"{BASE}/v1/esignet/oidc/userinfo")
REDIRECT_URI = f"{PUBLIC}/callback"

COOLING_HOURS = int(os.getenv("COOLING_HOURS", "72"))
NONCE_TTL = 300

# The dev surface (mock IdP, /api/dev/*) exists ONLY when APP_ENV is exactly
# "dev". The default is "production" so a deploy that never sets the variable
# fails closed — the dev surface is simply not registered. Any value other than
# the exact string "dev" (a typo, an empty string, "prod", unset) is production.
# Positive-match-or-deny, defaulting to deny: we never blocklist known-prod
# values, and we never leave the dev surface open on a forgotten env var. Local
# use is an explicit opt-in: `APP_ENV=dev python app.py`.
APP_ENV = os.getenv("APP_ENV", "production")
DEV_MODE = APP_ENV == "dev"

# Session-id signing key and FIN pepper must survive restarts. If the secret
# changes, every session cookie's HMAC stops verifying (users logged out; the
# server-side session rows survive but become unreachable). If the pepper
# changes — worse — every FIN re-hashes to a new value, so upsert_identity can
# no longer find the existing row and mints a duplicate identity, while the
# still-live sybil index blocks the user from re-binding their own wallet. In
# production both MUST be pinned from a secret manager, so we refuse to start
# without them.
SESSION_SECRET = os.getenv("SESSION_SECRET")
_PEPPER_HEX = os.getenv("FIN_PEPPER")

if not DEV_MODE:
    _missing = [name for name, val in
                (("SESSION_SECRET", SESSION_SECRET), ("FIN_PEPPER", _PEPPER_HEX))
                if not val]
    if _missing:
        raise RuntimeError(
            "refusing to start: " + ", ".join(_missing) +
            " must be set from a secret manager when APP_ENV != dev"
        )

# Dev-only fallback so the demo runs with zero setup. NEVER reached in production
# because the guard above hard-stops a non-dev start with these unset.
#
# PEPPER ROTATION: the pepper is not rotatable in place. Rotating it re-hashes
# every FIN, orphaning all existing identity rows (they are keyed by fin_hmac)
# and locking each user out of re-binding their own wallet via the sybil index.
# Changing it requires a migration that re-derives fin_hmac for every row under
# the new pepper — treat it as permanent for the life of the database.
SESSION_SECRET = SESSION_SECRET or secrets.token_hex(32)
FIN_PEPPER = (_PEPPER_HEX or secrets.token_bytes(32).hex()).encode()

CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = mock_esignet.generate_client_keypair()
mock_esignet.CLIENT_PUBLIC_KEY = CLIENT_PUBLIC_KEY
mock_esignet.TOKEN_ENDPOINT = TOKEN_URL
mock_esignet.EXPECTED_CLIENT_ID = CLIENT_ID

SESSION_TTL_HOURS = 12


def _sign_sid(sid: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), sid.encode(), hashlib.sha256).hexdigest()


class ServerSideSessionMiddleware:
    """
    Sessions live in the database; the cookie carries only an opaque random id
    plus an HMAC over it.

    Starlette's SessionMiddleware signs but does not encrypt: everything in the
    session is client-readable base64. The claims now include address.kebele
    and address.woreda — neighbourhood-level location for a real person — which
    must never be decodable from a cookie. The official fayda-auth-python
    library keeps sessions in Redis for the same reason; SQLite fills that role
    here without a new dependency. The 256-bit random sid is the capability;
    the HMAC only lets forged or truncated ids be rejected without a DB hit.
    """
    COOKIE = "session"

    def __init__(self, app):
        self.app = app

    def _sid_from_cookie(self, header: str) -> str | None:
        token = ""
        for part in header.split(";"):
            k, _, v = part.strip().partition("=")
            if k == self.COOKIE:
                token = v
        if not token or "." not in token:
            return None
        sid, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign_sid(sid)):
            return None
        return sid

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        sid = self._sid_from_cookie(Headers(scope=scope).get("cookie", ""))
        session = store.load_session(sid) if sid else None
        if session is None:
            sid = None
            session = {}
        scope["session"] = session

        async def send_wrapper(message):
            nonlocal sid
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                # Session fixation: a pre-auth sid planted in a victim's
                # browser must not survive authentication. A handler that
                # elevates the session (login callback) requests rotation; the
                # old row dies and a fresh sid is minted below.
                if session.pop("__rotate__", None) and sid is not None:
                    store.delete_session(sid)
                    sid = None
                if session:
                    if sid is None:
                        sid = secrets.token_urlsafe(32)
                    store.save_session(sid, session, SESSION_TTL_HOURS)
                    headers.append(
                        "set-cookie",
                        f"{self.COOKIE}={sid}.{_sign_sid(sid)}; Path=/; HttpOnly; "
                        f"SameSite=Lax; Max-Age={SESSION_TTL_HOURS * 3600}",
                    )
                elif sid is not None:
                    store.delete_session(sid)
                    headers.append(
                        "set-cookie",
                        f"{self.COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                    )
                    sid = None
            await send(message)

        await self.app(scope, receive, send_wrapper)


app = FastAPI(title="Fayda wallet registry")
app.add_middleware(ServerSideSessionMiddleware)

# The mock IdP is part of the dev surface — it must not exist in production.
if DEV_MODE:
    app.include_router(mock_esignet.router)

store.init()


def hash_fin(fin: str) -> str:
    """Never store the raw FIN. HMAC with a server-side pepper, not a bare hash."""
    return hmac.new(FIN_PEPPER, fin.encode(), hashlib.sha256).hexdigest()


# Non-negotiable #1: the raw FIN never reaches the browser. In the confirmed
# schema (github.com/National-ID-Program-Ethiopia/fayda-auth-python) the FIN
# travels only in `sub`. We whitelist rather than blocklist so a newly-added
# sensitive claim is dropped by default. Deliberately excluded: `sub` (the
# FIN), `phone`, and `picture` (a face image — biometric-adjacent PII with no
# use here).
#
# residenceStatus is whitelisted and surfaced: Fayda covers legally resident
# foreign nationals, so this claim is the most likely home for the
# citizenship-vs-residency distinction B2 is blocked on. Its VALUE SET IS
# UNCONFIRMED — check with NIDP before gating any feature on it.
SAFE_CLAIMS = frozenset({
    "name", "birthdate", "gender", "address", "residenceStatus",
})


def safe_claims(claims: dict) -> dict:
    return {k: v for k, v in claims.items() if k in SAFE_CLAIMS}


def client_assertion() -> str:
    """private_key_jwt, RS256. This is how Fayda authenticates the relying party."""
    now = int(time.time())
    return jwt.encode(
        {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": TOKEN_URL,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 300,
        },
        CLIENT_PRIVATE_KEY,
        algorithm="RS256",
    )


# ------------------------------------------------------------- identity flow

@app.get("/login")
def login(request: Request):
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    request.session["oidc_state"] = state
    url = (
        f"{AUTHORIZE_URL}?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
        f"&response_type=code&scope=openid+profile&state={state}&nonce={nonce}"
    )
    return RedirectResponse(url)


@app.get("/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if not code:
        raise HTTPException(400, "no authorization code returned")
    if state != request.session.get("oidc_state"):
        raise HTTPException(400, "state mismatch — possible CSRF")
    request.session.pop("oidc_state", None)

    async with httpx.AsyncClient(timeout=10) as c:
        tr = await c.post(TOKEN_URL, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_assertion": client_assertion(),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        })
        if tr.status_code != 200:
            raise HTTPException(502, f"token exchange failed: {tr.text}")
        access_token = tr.json()["access_token"]

        ur = await c.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
        if ur.status_code != 200:
            raise HTTPException(502, f"userinfo failed: {ur.text}")
        claims = ur.json()

    # `sub` is the only identifier in the confirmed schema — no fayda_fin claim.
    fin = claims.get("sub")
    if not fin:
        raise HTTPException(502, "userinfo returned no sub")
    ident = store.upsert_identity(
        fin_hmac=hash_fin(fin),
        display_name=claims.get("name", "Unknown"),
        birthdate=claims.get("birthdate", ""),
    )
    request.session["identity_id"] = ident["id"]
    # Privilege change: rotate the session id so a fixated pre-auth sid cannot
    # ride into the authenticated session.
    request.session["__rotate__"] = True
    # The session is server-side now, but /api/me still echoes claims to the
    # browser and the DOM — so sub, phone and picture are stripped here, at the
    # boundary, before anything stores them.
    request.session["claims"] = safe_claims(claims)
    return RedirectResponse("/")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return JSONResponse({"ok": True})


def current(request: Request) -> str:
    iid = request.session.get("identity_id")
    if not iid:
        raise HTTPException(401, "not authenticated with Fayda")
    return iid


# --------------------------------------------------------------- wallet flow

class NonceReq(BaseModel):
    chain: str
    address: str


class BindReq(BaseModel):
    chain: str
    address: str
    nonce: str
    signature: str


@app.post("/api/wallet/nonce")
def wallet_nonce(req: NonceReq, request: Request):
    iid = current(request)
    if req.chain not in ("evm", "solana"):
        raise HTTPException(400, "chain must be evm or solana")
    if not vf.looks_like_address(req.chain, req.address):
        raise HTTPException(400, "that does not look like a valid address for this chain")

    if store.address_claimed_by_other(req.chain, req.address, iid):
        raise HTTPException(409, "this wallet is already bound to a different Fayda identity")

    ident = store.get_identity(iid)
    nonce = secrets.token_urlsafe(16)
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    message = vf.build_message(req.chain, req.address, nonce, issued_at,
                               ident["display_name"])
    store.issue_nonce(nonce, req.address, req.chain, message, NONCE_TTL)
    return {"nonce": nonce, "message": message, "expires_in": NONCE_TTL}


@app.post("/api/wallet/bind")
def wallet_bind(req: BindReq, request: Request):
    iid = current(request)

    # Consuming the nonce returns the exact message the server issued. The
    # signature is verified against that, never against anything the client sent.
    ok, err, message = store.consume_nonce(req.nonce, req.address, req.chain)
    if not ok:
        raise HTTPException(400, err)

    # Re-check the sybil constraint at commit time, not just at nonce issue.
    if store.address_claimed_by_other(req.chain, req.address, iid):
        raise HTTPException(409, "this wallet is already bound to a different Fayda identity")

    valid, verr = vf.verify(req.chain, message, req.signature, req.address)
    if not valid:
        raise HTTPException(400, f"proof of control failed: {verr}")

    incumbent = store.active_binding(iid, req.chain)
    if incumbent and incumbent["address"].lower() == req.address.lower():
        raise HTTPException(409, "that wallet is already the active one for this chain")
    if store.pending_binding(iid, req.chain):
        raise HTTPException(409, "a change is already pending on this chain — cancel it first")

    # The checks above are check-then-insert; a concurrent bind can win the
    # window. The DB indexes still hold the invariant — surface the loss as a
    # 409 like the pre-insert checks do, not a 500 stack trace.
    try:
        binding = store.create_binding(
            iid, req.chain, req.address, req.nonce, req.signature, message, COOLING_HOURS
        )
    except store.BindingConflict as e:
        raise HTTPException(409, str(e))
    return {
        "status": binding["status"],
        "activates_at": binding["activates_at"],
        "cooling_hours": COOLING_HOURS,
        "replaced": incumbent["address"] if incumbent else None,
    }


@app.get("/api/registry")
def api_registry():
    store.promote_due()
    return {"identities": store.registry(), "cooling_hours": COOLING_HOURS}


@app.get("/api/me")
def api_me(request: Request):
    iid = request.session.get("identity_id")
    if not iid:
        return {"authenticated": False, "cooling_hours": COOLING_HOURS,
                "dev": DEV_MODE}
    store.promote_due(iid)
    ident = store.get_identity(iid)
    return {
        "authenticated": True,
        "dev": DEV_MODE,
        "identity": {
            "id": ident["id"],
            "display_name": ident["display_name"],
            "birthdate": ident["birthdate"],
            "fin_hmac": ident["fin_hmac"],
            "verified_at": ident["verified_at"],
        },
        "claims": request.session.get("claims", {}),
        "active": {
            "evm": store.active_binding(iid, "evm"),
            "solana": store.active_binding(iid, "solana"),
        },
        "pending": {
            "evm": store.pending_binding(iid, "evm"),
            "solana": store.pending_binding(iid, "solana"),
        },
        "history": store.history(iid),
        "cooling_hours": COOLING_HOURS,
    }


@app.post("/api/wallet/cancel")
def wallet_cancel(req: NonceReq, request: Request):
    iid = current(request)
    if not store.cancel_pending(iid, req.chain):
        raise HTTPException(404, "no pending change on this chain")
    return {"ok": True}


class TestWalletReq(BaseModel):
    chain: str


# The entire dev surface is registered only when DEV_MODE is true. In production
# these routes do not exist (404), so none of the attacks they enable — the open
# DB wipe, the cooling-period collapse, or server-side key custody — is reachable.
# Every route still requires current(request) as a second layer, so even within a
# shared dev instance an anonymous caller cannot invoke them.
if DEV_MODE:

    @app.post("/api/dev/fast-forward")
    def dev_fast_forward(req: NonceReq, request: Request):
        """DEV ONLY. Collapses the cooling period so the lifecycle is demonstrable.

        This is exactly the "instant swap" the cooling period forbids, so it must
        never be reachable in production. It cannot be: the enclosing DEV_MODE
        guard means this route is not registered when APP_ENV != dev.
        """
        iid = current(request)
        if not store.force_due(iid, req.chain):
            raise HTTPException(404, "no pending change on this chain")
        store.promote_due(iid)
        return {"ok": True}

    @app.post("/api/dev/reset")
    def dev_reset(request: Request):
        # current() first: an unauthenticated caller must not be able to wipe the
        # registry, and a malicious cross-origin POST carries no valid session.
        current(request)
        store.reset()
        request.session.clear()
        return {"ok": True}

    @app.post("/api/dev/test-wallet")
    def dev_test_wallet(req: TestWalletReq, request: Request):
        """
        DEV ONLY. Generates a throwaway keypair, issues a nonce for it, and signs
        the resulting message — all in one pass, so the flow can be exercised
        without MetaMask, Rabby or Phantom installed.

        In production the private key never leaves the user's wallet. That is the
        whole point of self-custody, and this endpoint would not exist — the
        DEV_MODE guard ensures it is not registered when APP_ENV != dev.
        """
        iid = current(request)
        ident = store.get_identity(iid)

        if req.chain == "evm":
            acct = Account.create()
            address = acct.address
        elif req.chain == "solana":
            sk = nacl.signing.SigningKey.generate()
            address = base58.b58encode(bytes(sk.verify_key)).decode()
        else:
            raise HTTPException(400, "unsupported chain")

        nonce = secrets.token_urlsafe(16)
        issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        message = vf.build_message(req.chain, address, nonce, issued_at,
                                   ident["display_name"])
        store.issue_nonce(nonce, address, req.chain, message, NONCE_TTL)

        if req.chain == "evm":
            signature = Account.sign_message(
                encode_defunct(text=message), acct.key
            ).signature.hex()
        else:
            signature = base58.b58encode(sk.sign(message.encode()).signature).decode()

        return {"address": address, "nonce": nonce,
                "message": message, "signature": signature}


# The UI lives in frontend/ (React + Vite) and is served by Vite in dev. This
# process is API-only; the root exists so a human landing here is redirected
# to the right place instead of a 404.
@app.get("/")
def index():
    return {"service": "fayda-wallet-registry API", "ui": PUBLIC}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
