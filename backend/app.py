"""
Fayda identity to self-custodied wallet registry.

Internal proof of concept. The Fayda side is a real OIDC client pointed at a
local mock provider — swapping to production is an env var change, not a rewrite.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
from contextlib import asynccontextmanager
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import base58
import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import nacl.signing
import psycopg
import uvicorn
import webauthn as wa
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.datastructures import Headers, MutableHeaders

import chain
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
# BASE must track the actual listen port for the server's calls to itself
# (token exchange, userinfo) — on Render the process listens on $PORT.
BASE = os.getenv("BASE_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}")
# Deployed platforms provide the public origin (Render: RENDER_EXTERNAL_URL,
# e.g. https://myapp.onrender.com). Explicit PUBLIC_URL still wins.
PUBLIC = (os.getenv("PUBLIC_URL")
          or os.getenv("RENDER_EXTERNAL_URL")
          or BASE).rstrip("/")
DEMO_CLIENT_ID = "fayda-wallet-demo"
CLIENT_ID = os.getenv("FAYDA_CLIENT_ID", DEMO_CLIENT_ID)
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
# DEMO_MODE mounts ONLY the mock IdP on a production deploy that has no real
# Fayda credentials yet: a visitor can click a persona and log in, but none of
# /api/dev/* exists — the demo audience must not be able to wipe the DB (H1)
# or collapse the cooling window (H2). Everything else keeps its production
# posture, including the secrets guard and the Secure cookie.
DEMO_MODE = os.getenv("DEMO_MODE", "").lower() in ("1", "true", "yes")

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

# DEMO_MODE publishes the mock IdP, so anyone can click a persona and hold a
# session. That is the point of a demo, and it is why the registry being
# "authenticated" means little there. It becomes a real problem only if the
# same deploy ALSO points at live Fayda: real identities would then sit behind
# a login anyone can perform. Nothing prevented that combination, so make it
# structural rather than a line in DEPLOY.md — same shape as the secrets guard
# above, and it fails at boot rather than after real people have registered.
# Whether this process serves the mock identity provider at all. CLAUDE.md says
# mock_esignet.py is "deleted in production", and until now that was not true:
# app.py imported it at module scope for the client keypair, so a deployment
# that actually removed the file could not boot. Importing it only when it is
# mounted makes the documented posture real, and a production image can drop
# the throwaway IdP entirely.
if DEMO_MODE and not DEV_MODE:
    # The private key and the client id belong to the same list as the URLs:
    # each is issued by partner onboarding, and the key is the one credential
    # that cannot be rotated without going back to Fayda. Checking only the
    # URLs let the most sensitive of them onto a deploy where anybody can log
    # in with a persona.
    #
    # Checked BEFORE the mock is imported, so a dangerous configuration is
    # refused on its own terms rather than incidentally failing on a missing
    # module — the operator needs to read why, not what went wrong second.
    _live = [n for n in ("FAYDA_AUTHORIZE_URL", "FAYDA_TOKEN_URL",
                         "FAYDA_USERINFO_URL", "FAYDA_CLIENT_PRIVATE_KEY",
                         "FAYDA_CLIENT_ID") if os.getenv(n)]
    if _live:
        raise RuntimeError(
            "refusing to start: DEMO_MODE publishes the mock identity provider, "
            "but " + ", ".join(_live) + " points this deploy at a real one. "
            "Real identities must not sit behind a login any visitor can perform. "
            "Unset DEMO_MODE for a live deployment."
        )

MOCK_IDP = DEV_MODE or DEMO_MODE
if MOCK_IDP:
    import mock_esignet

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

# The RSA key that signs the private_key_jwt client assertion — how Fayda
# authenticates this relying party.
#
# R5 readiness: this used to come from mock_esignet.generate_client_keypair(),
# a FRESH key per process. Against real Fayda that can never work: onboarding
# registers one public JWK, and a key regenerated every boot (and differing
# between instances) would fail token exchange on the first request. The
# roadmap's claim that "only mock_esignet.py changes" was wrong on this point.
# A registered key therefore comes from the environment, and the ephemeral one
# remains only for dev and the persona demo, where the mock IdP verifies
# against whatever this process generated.
_CLIENT_KEY_PEM = os.getenv("FAYDA_CLIENT_PRIVATE_KEY", "").strip()
if _CLIENT_KEY_PEM:
    # PARSE it here, do not merely check that the variable is non-empty.
    # Truthiness alone let a truncated PEM, the PUBLIC half, an EC key or a
    # passphrase-protected key boot green and pass the health check, then fail
    # at the first user's /callback with a message about public keys — the
    # precise silent-boot failure this whole change exists to remove.
    try:
        _parsed = serialization.load_pem_private_key(
            _CLIENT_KEY_PEM.encode(), password=None)
    except Exception as e:
        raise RuntimeError(
            "refusing to start: FAYDA_CLIENT_PRIVATE_KEY is not a readable "
            f"unencrypted PEM private key ({type(e).__name__}). It must be the "
            "RSA private key whose public JWK is registered with Fayda."
        ) from None
    if not isinstance(_parsed, rsa.RSAPrivateKey):
        raise RuntimeError(
            "refusing to start: FAYDA_CLIENT_PRIVATE_KEY must be an RSA key — "
            "the client assertion is RS256."
        )
    # The client id is issued by the same onboarding as the key, and it goes
    # into the assertion's iss and sub. Silently defaulting to the demo id
    # would send a real IdP an assertion claiming to be "fayda-wallet-demo",
    # which fails at the first login for a reason nothing here would explain.
    if CLIENT_ID == DEMO_CLIENT_ID:
        raise RuntimeError(
            "refusing to start: a registered FAYDA_CLIENT_PRIVATE_KEY is set "
            f"but FAYDA_CLIENT_ID is still the demo default "
            f"({DEMO_CLIENT_ID!r}). Set the client id issued with the key."
        )
    CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = _CLIENT_KEY_PEM, None
elif MOCK_IDP:
    CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = mock_esignet.generate_client_keypair()
else:
    # Production against a real IdP with no registered key: fail at boot rather
    # than at the first user's token exchange.
    raise RuntimeError(
        "refusing to start: FAYDA_CLIENT_PRIVATE_KEY must be set (the RSA "
        "private key whose public JWK is registered with Fayda). Only the "
        "mock IdP accepts a per-process key."
    )

if MOCK_IDP:
    mock_esignet.CLIENT_PUBLIC_KEY = CLIENT_PUBLIC_KEY
    mock_esignet.TOKEN_ENDPOINT = TOKEN_URL
    mock_esignet.EXPECTED_CLIENT_ID = CLIENT_ID

SESSION_TTL_HOURS = 12
# A session that has not completed the Fayda round trip holds only oidc_state,
# which is dead the moment /callback runs and useless after the dance's natural
# lifetime of about a minute. Giving it the full authenticated TTL is what let
# an anonymous request loop park 12-hour rows in a database that no longer
# resets itself: a sweep can only bound a table at arrival-rate x TTL, and this
# is the term we control. Half an hour still cuts the reachable steady state
# by 24x while leaving room for a real biometric or OTP capture; ten minutes
# risked expiring a slow but legitimate login.
PRE_AUTH_SESSION_TTL_HOURS = 0.5
# How recently Fayda must have verified the person before the session may
# create a passkey — a credential that outlives the session itself. Fifteen
# minutes is long enough to finish reading the page and click, short enough
# that a stolen cookie is usually past it.
FRESH_AUTH_SECONDS = 900


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
                    # An anonymous, mid-login session gets minutes; only a
                    # completed Fayda authentication earns the full TTL.
                    ttl = (SESSION_TTL_HOURS if session.get("identity_id")
                           else PRE_AUTH_SESSION_TTL_HOURS)
                    store.save_session(sid, session, ttl)
                    headers.append(
                        "set-cookie",
                        f"{self.COOKIE}={sid}.{_sign_sid(sid)}; Path=/; HttpOnly; "
                        f"SameSite=Lax; Max-Age={int(ttl * 3600)}"
                        + ("" if DEV_MODE else "; Secure"),
                    )
                elif sid is not None:
                    store.delete_session(sid)
                    headers.append(
                        "set-cookie",
                        f"{self.COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                        + ("" if DEV_MODE else "; Secure"),
                    )
                    sid = None
            await send(message)

        await self.app(scope, receive, send_wrapper)


# Storage is durable now (R1): nothing wipes the database on redeploy, and
# sessions/auth_nonces grow with unauthenticated traffic. Each process sweeps
# TTL-dead rows on boot and every ten minutes; the DELETEs are idempotent, so
# several instances sweeping concurrently is harmless.
SWEEP_INTERVAL_SECONDS = 600


def _sweep_loop():
    failures = 0
    while True:
        try:
            store.sweep_expired()
            failures = 0
        except Exception as e:
            # Hygiene must not die on a transient DB error — a dead sweeper
            # silently returns the tables to growing forever. But it must not
            # fail *silently* either: this is the only thing bounding them, so
            # a sweeper broken for days has to be visible somewhere.
            failures += 1
            print(f"[sweep] failed {failures}x: {type(e).__name__}: {e}",
                  file=sys.stderr, flush=True)
        time.sleep(SWEEP_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app):
    # lifespan, not @app.on_event("startup"): on_event is deprecated, and if a
    # version bump drops it the thread would simply never start — no error, no
    # failed request, no test failure, just the tables quietly growing forever.
    # The sweeper is load-bearing for durability, so it hangs off the
    # supported hook.
    threading.Thread(target=_sweep_loop, daemon=True, name="ttl-sweeper").start()
    yield


app = FastAPI(
    title="Fayda wallet registry",
    lifespan=lifespan,
    # No interactive docs outside dev. They are open by default and enumerate
    # the whole surface — including the operator routes and their request
    # shapes — to anyone who asks. Nothing here is secret by obscurity, but
    # publishing a map of the compliance API is not a thing a deployment
    # should do without deciding to.
    docs_url="/docs" if DEV_MODE else None,
    redoc_url="/redoc" if DEV_MODE else None,
    openapi_url="/openapi.json" if DEV_MODE else None,
)
app.add_middleware(ServerSideSessionMiddleware)

# The mock IdP mounts in dev, and in an explicitly opted-in demo deploy.
# The /api/dev/* surface is NEVER tied to DEMO_MODE.
if MOCK_IDP:
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


def _strip_nul(v):
    """
    Postgres rejects NUL (0x00) in text and JSONB. An IdP claim carrying one
    would raise inside the session save — which happens in the ASGI send
    wrapper, after the response has started, so the connection is torn and the
    login silently fails. Drop them at the boundary instead.
    """
    if isinstance(v, str):
        return v.replace("\x00", "")
    if isinstance(v, dict):
        return {k: _strip_nul(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_strip_nul(x) for x in v]
    return v


def safe_claims(claims: dict) -> dict:
    return {k: _strip_nul(v) for k, v in claims.items() if k in SAFE_CLAIMS}


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
        # Distinguish the two causes. A session carrying no oidc_state at all
        # is almost always the pre-auth row having expired mid-login (a slow
        # biometric capture), not an attack — reporting that as CSRF sends the
        # user hunting for a security problem instead of pressing sign-in
        # again. A state that is present but WRONG is the real CSRF shape.
        if not request.session.get("oidc_state"):
            raise HTTPException(400, "sign-in took too long and expired — start again")
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
    # Explicit, not inferred from the absence of the key: this field decides
    # whether the session may register a passkey, and a security gate should
    # not rest on a default.
    request.session["auth_method"] = "fayda"
    # When that verification happened, so operations that create long-lived
    # credentials can demand a recent one (see require_fayda_session).
    request.session["auth_at"] = datetime.now(timezone.utc).isoformat()
    return RedirectResponse("/")


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return JSONResponse({"ok": True})


# ------------------------------------------------------- passkeys (R2)
#
# Return-login, not a second identity system. A passkey can only be registered
# by a session that Fayda already verified, and it carries that identity_id, so
# an assertion re-establishes an identity Fayda proved — it can never mint one.
# Fayda remains the only source of identity (CLAUDE.md), and the private key
# never leaves the authenticator, which is what makes this phishing-resistant
# in a way a password or an emailed link is not.
#
# Deliberately NOT Supabase Auth, though R2 named it: its passkey support is
# beta ("API may change without notice"), and it would put a client-readable
# JWT in the browser and a second identity authority beside Fayda. S1 moved
# sessions server-side precisely because the claims carry kebele/woreda, and
# the SPA is same-origin with a third-party wallet connector. Supabase is still
# the base — it is the Postgres that stores these credentials and enforces the
# RLS around them.

# The relying-party id is the registrable domain, WITHOUT scheme or port; the
# expected origin keeps both. Getting them confused is the classic WebAuthn
# misconfiguration — a credential is bound to the RP id, so changing it orphans
# every registered passkey. Note a bare IP is not a valid RP id (browsers
# reject it; 'localhost' is the one special case), so a deployment that never
# sets PUBLIC_URL or RENDER_EXTERNAL_URL falls back to 127.0.0.1 and passkeys
# simply will not register — the same footgun already documented for the
# session cookie, and it fails visibly rather than silently.
RP_ID = urlparse(PUBLIC).hostname or "localhost"
RP_NAME = "Fayda wallet registry"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def require_fayda_session(request: Request) -> str:
    """
    For the operations that must not be reachable with a passkey alone.

    A passkey is a long-lived credential that survives the victim's logout, so
    if a stolen session could mint one, the attacker would convert a temporary
    compromise into permanent access — and then chain-register further keys
    without ever facing Fayda again. Registration therefore requires a session
    established by an actual Fayda authentication, which is the one step an
    attacker holding only a session cookie cannot replay. This is the same
    reasoning as the cooling period: a compromise must stay recoverable.
    """
    iid = current(request)
    # Absent means "not established by Fayda" — the safe reading. The callback
    # sets this explicitly, so only a session predating that change lacks it,
    # and such a session should re-verify rather than be trusted by default.
    if request.session.get("auth_method") != "fayda":
        raise HTTPException(
            403, "verify with Fayda again to add a passkey — a passkey cannot "
                 "register another passkey")
    # Freshness, not just provenance. Gating on how the session was CREATED
    # still lets a stolen cookie mint a passkey any time in the session's 12
    # hours, because the theft inherits the victim's Fayda login. Requiring a
    # recent authentication shrinks that window to minutes and forces the
    # attacker through the one step a cookie cannot replay. Same idea as the
    # re-authentication prompt other systems put in front of adding a
    # credential.
    at = request.session.get("auth_at")
    fresh = False
    if at:
        try:
            fresh = (datetime.now(timezone.utc)
                     - datetime.fromisoformat(at)).total_seconds() < FRESH_AUTH_SECONDS
        except ValueError:
            fresh = False
    if not fresh:
        raise HTTPException(
            403, "for security, verify with Fayda again before adding a passkey")
    return iid


@app.post("/api/passkey/register/begin")
def passkey_register_begin(request: Request):
    iid = require_fayda_session(request)
    ident = store.get_identity(iid)
    if not ident:
        raise HTTPException(401, "not authenticated with Fayda")
    opts = wa.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        # The user handle is the internal identity id, never the FIN or its
        # HMAC: it is stored on the authenticator and can surface in account
        # pickers, so it must carry nothing about the person.
        user_id=iid.encode(),
        user_name=ident["display_name"],
        user_display_name=ident["display_name"],
        # Exclude what is already registered so the same authenticator does not
        # silently create a duplicate credential.
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=wa.base64url_to_bytes(c["credential_id"]))
            for c in store.credentials_of(iid)
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    # The challenge lives in the server-side session, single-use. Verifying
    # against a challenge the client echoed back would authenticate nothing.
    request.session["passkey_challenge"] = _b64(opts.challenge)
    return json.loads(wa.options_to_json(opts))


async def _json_body(request: Request) -> dict:
    """
    A body that is not a JSON object is a client error, not a server one. These
    routes are reachable unauthenticated, so a malformed body must produce 400
    rather than an unhandled exception and a 500.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "expected a JSON object")
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object")
    return body


@app.post("/api/passkey/register/complete")
async def passkey_register_complete(request: Request):
    iid = require_fayda_session(request)
    challenge = request.session.pop("passkey_challenge", None)
    if not challenge:
        raise HTTPException(400, "no registration in progress")
    body = await _json_body(request)
    credential = body.get("credential")
    if not isinstance(credential, dict):
        raise HTTPException(400, "malformed credential")
    label = body.get("label", "")
    if not isinstance(label, str):
        raise HTTPException(400, "malformed label")
    label = _clean_token(label, "label")[:64]
    try:
        v = wa.verify_registration_response(
            credential=credential,
            expected_challenge=wa.base64url_to_bytes(challenge),
            expected_origin=PUBLIC,
            expected_rp_id=RP_ID,
            # The options ask for user_verification=required; without this the
            # library does not hold the response to it, so a credential created
            # without a biometric/PIN check would be stored and then rejected
            # at every login — an unusable key the user cannot tell apart from
            # a working one.
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(400, "passkey registration failed")
    try:
        store.add_credential(
            identity_id=iid,
            credential_id=_b64(v.credential_id),
            public_key=_b64(v.credential_public_key),
            sign_count=v.sign_count,
            label=label,
        )
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "that passkey is already registered")
    return {"registered": True, "passkeys": store.credentials_of(iid)}


@app.get("/api/passkey/list")
def passkey_list(request: Request):
    return {"passkeys": store.credentials_of(current(request))}


@app.post("/api/passkey/revoke")
async def passkey_revoke(request: Request):
    """
    The escape hatch, and the reason registration is Fayda-gated rather than
    forbidden. Without a revoke path, a passkey registered by an attacker holding a
    live session would outlive the victim's logout with nothing the victim
    could do — the same failure the cooling period exists to prevent, made
    permanent. Deleting runs RLS-scoped, so one identity cannot revoke
    another's credential even if the id were guessed.
    """
    iid = current(request)
    body = await _json_body(request)
    cred_id = body.get("credential_id")
    if not isinstance(cred_id, str) or not cred_id or len(cred_id) > 512:
        raise HTTPException(400, "malformed credential id")
    if not store.delete_credential(iid, cred_id):
        raise HTTPException(404, "no such passkey on this identity")
    # Kill the sessions that passkey opened, not just its ability to open more.
    # An attacker who registered it is already signed in; leaving that session
    # alive for the rest of its 12h TTL would make revocation a formality.
    ended = store.delete_sessions_for_credential(cred_id)
    return {"revoked": True, "sessions_ended": ended,
            "passkeys": store.credentials_of(iid)}


@app.post("/api/passkey/login/begin")
def passkey_login_begin(request: Request):
    # Unauthenticated by nature — this is how a returning user signs in.
    # Discoverable credentials mean no username is sent, so this endpoint
    # reveals nothing about who is registered.
    opts = wa.generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    request.session["passkey_challenge"] = _b64(opts.challenge)
    return json.loads(wa.options_to_json(opts))


@app.post("/api/passkey/login/complete")
async def passkey_login_complete(request: Request):
    challenge = request.session.pop("passkey_challenge", None)
    if not challenge:
        raise HTTPException(400, "no sign-in in progress")
    body = await _json_body(request)
    credential = body.get("credential")
    if not isinstance(credential, dict):
        raise HTTPException(400, "malformed credential")
    cred_id = credential.get("id")
    if not cred_id or not isinstance(cred_id, str) or len(cred_id) > 512:
        raise HTTPException(400, "malformed credential")
    # One message for every failure below. An unknown credential and a bad
    # signature must be indistinguishable, or this endpoint answers "is this
    # credential id registered here?" for anyone who asks — and a credential id
    # is the one part of a passkey that is not secret.
    denied = HTTPException(400, "passkey not recognised")

    stored = store.credential_by_id(cred_id)
    if not stored:
        raise denied
    try:
        v = wa.verify_authentication_response(
            credential=credential,
            expected_challenge=wa.base64url_to_bytes(challenge),
            expected_origin=PUBLIC,
            expected_rp_id=RP_ID,
            credential_public_key=wa.base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception:
        raise denied

    store.touch_credential(cred_id, v.new_sign_count)
    ident = store.get_identity(stored["identity_id"])
    if not ident:
        raise denied

    request.session["identity_id"] = ident["id"]
    # Same privilege change as the Fayda callback, so a fixated pre-auth sid
    # cannot ride into the authenticated session.
    request.session["__rotate__"] = True
    # No claims: a passkey proves control of a registered device, not a fresh
    # Fayda authentication, so it must not resurrect kebele/woreda-level claims
    # from an older session. The dashboard falls back to the name and birthdate
    # on the identity row; re-running Fayda is what restores the full record.
    request.session["claims"] = {
        "name": ident["display_name"], "birthdate": ident["birthdate"],
    }
    request.session["auth_method"] = "passkey"
    # Which credential opened this session, so revoking it can also end it.
    request.session["passkey_credential_id"] = cred_id
    return {"authenticated": True, "identity": ident["display_name"]}


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


def _clean_token(value: str, label: str) -> str:
    """
    Reject the shapes that cannot be a real nonce or signature before they
    reach storage: a NUL byte is unrepresentable in Postgres text (it would
    become a 500 instead of the 400 this is), and an oversized value is only
    ever an attempt to write junk into a durable table.
    """
    if "\x00" in value or len(value) > 512:
        raise HTTPException(400, f"malformed {label}")
    return value


@app.post("/api/wallet/nonce")
def wallet_nonce(req: NonceReq, request: Request):
    iid = current(request)
    if req.chain not in ("evm", "solana"):
        raise HTTPException(400, "chain must be evm or solana")
    # A NUL-bearing EVM-shaped address passes the shape check but is
    # unrepresentable in Postgres text — reject it as the 400 it is.
    _clean_token(req.address, "address")
    if not vf.looks_like_address(req.chain, req.address):
        raise HTTPException(400, "that does not look like a valid address for this chain")

    if store.address_claimed_by_other(req.chain, req.address, iid):
        raise HTTPException(409, "this wallet is already bound to a different Fayda identity")

    ident = store.get_identity(iid)
    nonce = secrets.token_urlsafe(16)
    t = datetime.now(timezone.utc).replace(microsecond=0)
    message = vf.build_message(req.chain, req.address, nonce, t.isoformat(),
                               (t + timedelta(seconds=NONCE_TTL)).isoformat(),
                               ident["display_name"])
    store.issue_nonce(nonce, req.address, req.chain, message, NONCE_TTL)
    return {"nonce": nonce, "message": message, "expires_in": NONCE_TTL}


@app.post("/api/wallet/bind")
def wallet_bind(req: BindReq, request: Request):
    iid = current(request)
    # Same gates as /api/wallet/nonce, re-applied here: bind must stand alone.
    # An unrecognized chain string must never fall through to the base58
    # branch of the shape check, where it would buy quadratic decode CPU.
    if req.chain not in ("evm", "solana"):
        raise HTTPException(400, "chain must be evm or solana")
    _clean_token(req.nonce, "nonce")
    _clean_token(req.signature, "signature")
    _clean_token(req.address, "address")
    if not vf.looks_like_address(req.chain, req.address):
        raise HTTPException(400, "that does not look like a valid address for this chain")

    # Consuming the nonce returns the exact message the server issued. The
    # signature is verified against that, never against anything the client sent.
    ok, err, message, issued_via = store.consume_nonce(req.nonce, req.address, req.chain)
    if not ok:
        raise HTTPException(400, err)

    # Re-check the sybil constraint at commit time, not just at nonce issue.
    if store.address_claimed_by_other(req.chain, req.address, iid):
        raise HTTPException(409, "this wallet is already bound to a different Fayda identity")

    valid, verr = vf.verify(req.chain, message, req.signature, req.address)
    if not valid:
        raise HTTPException(400, f"proof of control failed: {verr}")

    incumbent = store.active_binding(iid, req.chain)
    # Canonical comparison, not blanket .lower(): Solana base58 is
    # case-sensitive, so lowercasing would equate two different public keys.
    if incumbent and (store.normalize_address(req.chain, incumbent["address"])
                      == store.normalize_address(req.chain, req.address)):
        raise HTTPException(409, "that wallet is already the active one for this chain")
    if store.pending_binding(iid, req.chain):
        raise HTTPException(409, "a change is already pending on this chain — cancel it first")

    # The checks above are check-then-insert; a concurrent bind can win the
    # window. The DB indexes still hold the invariant — surface the loss as a
    # 409 like the pre-insert checks do, not a 500 stack trace.
    try:
        binding = store.create_binding(
            iid, req.chain, req.address, req.nonce, req.signature, message,
            COOLING_HOURS, proof_method=issued_via,
        )
    except store.BindingConflict as e:
        raise HTTPException(409, str(e))
    return {
        "status": binding["status"],
        "activates_at": binding["activates_at"],
        "cooling_hours": COOLING_HOURS,
        "replaced": incumbent["address"] if incumbent else None,
    }


# ------------------------------------------------------ operator role (R3)
#
# The only place in the app where one person can see another's record. Two
# rules hold it together, and R4's transaction history is built on top of them:
#
#   1. Membership is granted out of band, never by an HTTP route.
#   2. Nothing cross-user is returned until the access is durably logged. The
#      log write comes FIRST and is allowed to fail the request — a lookup that
#      answers without leaving a trace is the failure R3 exists to prevent.

MIN_REASON_CHARS = 8


def require_operator(request: Request, reason: str, action: str,
                     subject_id: str | None = None, detail: str = "") -> str:
    # A Fayda-established session, not merely any session. It made no sense
    # that a passkey session was too weak to add another passkey but strong
    # enough to read every identity in the registry — operator powers are the
    # more sensitive of the two by a wide margin. A passkey is a convenience
    # for a person reaching their own record; looking at other people's
    # requires the national-ID check itself.
    iid = current(request)
    if request.session.get("auth_method") != "fayda":
        raise HTTPException(
            403, "compliance access requires verifying with Fayda in this session")
    if not store.is_operator(iid):
        raise HTTPException(403, "this view is restricted to compliance operators")
    reason = (reason or "").strip()
    # A required, non-trivial reason is the difference between an audit trail
    # and a hit counter: "who viewed whom, when" without "why" cannot be
    # reviewed by anyone afterwards.
    if len(reason) < MIN_REASON_CHARS:
        raise HTTPException(
            400, f"a reason of at least {MIN_REASON_CHARS} characters is required "
                 f"— it is written to the permanent access log")
    _clean_token(reason, "reason")
    if len(reason) > 500:
        raise HTTPException(400, "reason is too long")
    # Deliberately NOT wrapped in try/except: if the log cannot be written, the
    # caller must not get the data.
    store.log_access(actor_id=iid, action=action, reason=reason,
                     subject_id=subject_id, detail=detail[:500])
    return iid


class OperatorSearch(BaseModel):
    query: str
    reason: str


@app.post("/api/operator/search")
def operator_search(req: OperatorSearch, request: Request):
    q = (req.query or "").strip()
    if not q or len(q) > 100:
        raise HTTPException(400, "search term must be 1-100 characters")
    _clean_token(q, "query")
    iid = require_operator(request, req.reason, "search", detail=f"query={q}")
    results = store.find_identities(q)
    # One entry per identity the search actually surfaced, not just one for the
    # query. Logging only the query made the discovery phase invisible to the
    # people discovered: `%` matches everyone, and no subject would ever see
    # that their record had been returned. Each subject can now see it in
    # /api/me/access-log. Written before the results are returned, same rule
    # as everywhere else here.
    for r in results:
        store.log_access(actor_id=iid, action="search_result", reason=req.reason.strip(),
                         subject_id=r["id"], detail=f"query={q}")
    return {"results": results}


class OperatorView(BaseModel):
    identity_id: str
    reason: str


@app.post("/api/operator/identity")
def operator_identity(req: OperatorView, request: Request):
    iid = (req.identity_id or "").strip()
    if not iid or len(iid) > 64:
        raise HTTPException(400, "malformed identity id")
    _clean_token(iid, "identity id")
    # Logged BEFORE the read, and logged even when the record turns out not to
    # exist: an operator probing for which identities are present is itself
    # something a reviewer should be able to see.
    require_operator(request, req.reason, "view_identity", subject_id=iid)
    record = store.identity_full(iid)
    if not record:
        raise HTTPException(404, "no such identity")
    return {"identity": record}


# ------------------------------------------- transaction history (R4 / F1)
#
# The payoff feature and the most sensitive thing here: a verified national
# identity joined to on-chain activity. It lives entirely behind the operator
# role, is logged per access like everything else in R3, and appears in no user
# or public view.
#
# Split into two calls on purpose. The in-app timeline is local and exact and
# answers immediately; the on-chain lookup crosses the network to a third-party
# explorer that may be slow or down. One combined endpoint would make every
# case-file open as slow as the worst explorer day.
#
# LAWFUL BASIS: unresolved. Binding a national ID to persistent, queryable
# financial history is a surveillance capability, and Ethiopian data-protection
# review by NBE/NIDP has not happened. Tracked in PROGRESS.md; this code exists
# so the question can be asked about something concrete, not because the answer
# is assumed.


class OperatorTimeline(BaseModel):
    identity_id: str
    reason: str


@app.post("/api/operator/timeline")
def operator_timeline(req: OperatorTimeline, request: Request):
    iid = (req.identity_id or "").strip()
    if not iid or len(iid) > 64:
        raise HTTPException(400, "malformed identity id")
    _clean_token(iid, "identity id")
    require_operator(request, req.reason, "view_timeline", subject_id=iid)
    record = store.identity_full(iid)
    if not record:
        raise HTTPException(404, "no such identity")
    return {
        "identity": record,
        "timeline": store.identity_timeline(iid),
        # Which wallets the caller may then ask about on-chain. Only ever this
        # identity's own bindings — the on-chain endpoint re-checks it.
        "wallets": [{"chain": b["chain"], "address": b["address"],
                     "status": b["status"]}
                    for b in record["bindings"] if b["status"] == "active"],
    }


class OperatorOnchain(BaseModel):
    identity_id: str
    chain: str
    address: str
    reason: str


@app.post("/api/operator/onchain")
def operator_onchain(req: OperatorOnchain, request: Request):
    iid = (req.identity_id or "").strip()
    if not iid or len(iid) > 64:
        raise HTTPException(400, "malformed identity id")
    _clean_token(iid, "identity id")
    if req.chain not in ("evm", "solana"):
        raise HTTPException(400, "chain must be evm or solana")
    _clean_token(req.address, "address")
    if not vf.looks_like_address(req.chain, req.address):
        raise HTTPException(400, "that does not look like a valid address for this chain")

    # AUTHORIZE AND LOG FIRST — before any database lookup, and before any
    # answer that varies with the data.
    #
    # An earlier cut ran the ownership check above this line, and the distinct
    # replies it produced ("no such identity" vs "not bound to this identity"
    # vs the authorization error) let an UNAUTHENTICATED caller confirm whether
    # a given public wallet belongs to a given Fayda identity — the exact
    # linkage this whole feature is gated to protect — with no operator, no
    # reason, and no access-log row. Ordering, not design, but the effect was a
    # public oracle on the most sensitive join in the system.
    # Logged as an ATTEMPT, not as a completed trace. Authorization has to come
    # first (see above), but at this point nothing has been checked against
    # stored data — so recording "view_onchain" here would let an operator
    # write a permanent, subject-visible entry claiming they traced any address
    # they cared to name, for any identity, with no way for a later reviewer to
    # tell it from a real one. The completed trace is appended separately below
    # once the address is known to be this identity's.
    operator_id = require_operator(request, req.reason, "view_onchain_attempted",
                                   subject_id=iid,
                                   detail=f"{req.chain}:{req.address}")

    # Only now may the answer depend on stored data. The address must actually
    # be bound to the identity named in the request: otherwise this is a
    # general-purpose chain proxy that happens to need an operator, and the log
    # entry would name a subject unconnected to the address queried.
    record = store.identity_full(iid)
    if not record:
        raise HTTPException(404, "no such identity")
    # Active and archived only. An archived binding is real history — it was
    # verified and live once. A CANCELLED one never activated, and cancellation
    # is specifically how a user repudiates a swap they did not authorise, so
    # treating it as theirs would pull an attacker's address into the victim's
    # case file and write it to an append-only log. Pending is likewise not yet
    # theirs.
    owned = any(b["status"] in ("active", "archived")
                and b["chain"] == req.chain
                and store.normalize_address(req.chain, b["address"])
                == store.normalize_address(req.chain, req.address)
                for b in record["bindings"])
    if not owned:
        raise HTTPException(404, "that wallet is not bound to this identity")

    # The trace really is happening, against an address really bound to this
    # identity. Appended rather than updating the attempt row, because the log
    # is append-only: a reviewer reads the pair, and an attempt with no
    # matching completion is exactly the thing worth noticing.
    store.log_access(actor_id=operator_id, action="view_onchain",
                     reason=req.reason.strip(), subject_id=iid,
                     detail=f"{req.chain}:{req.address}")
    # Never raises: a slow or broken explorer comes back as a status the panel
    # renders, not a 500 and not an empty list pretending to be an answer.
    return {"wallet": {"chain": req.chain, "address": req.address},
            **chain.transactions(req.chain, req.address)}


@app.post("/api/operator/access-log")
def operator_access_log(request: Request, before: str | None = None):
    # Reading the log is itself an access, and is itself logged. Otherwise the
    # one action an abusive operator most wants to take unobserved — checking
    # whether anyone is watching — would be the one action nobody records.
    require_operator(request, "operator reviewing the access log", "read_access_log")
    try:
        return store.access_log_all(
            before=_clean_token(before, "cursor") if before else None)
    except store.BadCursor as e:
        raise HTTPException(400, str(e))


@app.get("/api/me/access-log")
def my_access_log(request: Request, before: str | None = None):
    """
    Who has looked at MY record. The person being surveilled can see the
    surveillance; without this the log is only ever read by the same office
    that generates it. Paged, so a burst of activity cannot push an older
    entry out of the only view its subject has.
    """
    try:
        return store.access_log_about(
            current(request),
            before=_clean_token(before, "cursor") if before else None)
    except store.BadCursor as e:
        raise HTTPException(400, str(e))


class RegistryReq(BaseModel):
    reason: str


@app.post("/api/registry")
def api_registry(req: RegistryReq, request: Request):
    # R2 made this require a session; R3 makes it operator-only and logged.
    # The reason is that this endpoint IS the sensitive cross-user join — a
    # directory of verified people and the wallets they control — and R3's
    # rule is that no cross-user visibility ships without an audit entry.
    # Requiring merely "some session" let an operator read the whole mapping
    # by the one route that left no trace, which is worse than not having the
    # audited route at all. An ordinary user now sees their own record, their
    # own history, and who has looked at them; nothing about anyone else.
    iid = require_operator(request, req.reason, "list_registry")
    store.promote_due()
    identities = store.registry()
    # Per-subject entries, the same rule search follows — and it matters more
    # here, because this discloses every bound identity's name AND both wallet
    # addresses in one call. Logging only "someone listed the registry" left
    # the people listed with nothing in their own view, which made the bulk
    # route quieter than the narrow one.
    for row in store.registry_ids():
        store.log_access(actor_id=iid, action="listed_in_registry",
                         reason=req.reason.strip(), subject_id=row)
    return {"identities": identities, "cooling_hours": COOLING_HOURS}


@app.get("/api/me")
def api_me(request: Request):
    iid = request.session.get("identity_id")
    if not iid:
        # public_origin lets the frontend detect a PUBLIC_URL misconfiguration
        # (browser origin != where the OIDC redirect will land) and show a
        # clear notice instead of a silent half-login.
        return {"authenticated": False, "cooling_hours": COOLING_HOURS,
                "dev": DEV_MODE, "demo": DEMO_MODE, "public_origin": PUBLIC}
    store.promote_due(iid)
    ident = store.get_identity(iid)
    # One query for all of this identity's bindings, sliced locally. Asking
    # the database separately for each active/pending slot cost five extra
    # round trips per page load against a managed Postgres.
    rows = store.bindings_of(iid)

    def one(status: str, chain: str):
        return next((r for r in rows
                     if r["status"] == status and r["chain"] == chain), None)

    return {
        "authenticated": True,
        "dev": DEV_MODE,
        "demo": DEMO_MODE,
        "identity": {
            "id": ident["id"],
            "display_name": ident["display_name"],
            "birthdate": ident["birthdate"],
            "fin_hmac": ident["fin_hmac"],
            "verified_at": ident["verified_at"],
        },
        "claims": request.session.get("claims", {}),
        "active": {
            "evm": one("active", "evm"),
            "solana": one("active", "solana"),
        },
        "pending": {
            "evm": one("pending", "evm"),
            "solana": one("pending", "solana"),
        },
        "history": rows,
        "cooling_hours": COOLING_HOURS,
        # Registered passkeys (public metadata only — no key material), so the
        # dashboard can say whether return-login is set up.
        "passkeys": store.credentials_of(iid),
        # How THIS session was established. A passkey proves device control,
        # not a fresh Fayda check, and the UI says so rather than implying the
        # national-ID verification just happened.
        "auth_method": request.session.get("auth_method", "unknown"),
        # Whether to offer the compliance panel at all. Purely a UI hint —
        # every operator route re-checks both conditions server-side, so this
        # flag grants nothing. It mirrors BOTH of them (role and Fayda-session)
        # because showing the panel to a passkey-session operator produced a
        # screen on which every button 403s.
        "operator": (store.is_operator(iid)
                     and request.session.get("auth_method") == "fayda"),
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
        t = datetime.now(timezone.utc).replace(microsecond=0)
        message = vf.build_message(req.chain, address, nonce, t.isoformat(),
                                   (t + timedelta(seconds=NONCE_TTL)).isoformat(),
                                   ident["display_name"])
        store.issue_nonce(nonce, address, req.chain, message, NONCE_TTL,
                          issued_via="dev-test-key")

        if req.chain == "evm":
            signature = Account.sign_message(
                encode_defunct(text=message), acct.key
            ).signature.hex()
        else:
            signature = base58.b58encode(sk.sign(message.encode()).signature).decode()

        return {"address": address, "nonce": nonce,
                "message": message, "signature": signature}


# The Privy app id is a public identifier, not a secret, and making it a
# runtime env var (instead of a Vite build-time constant) means a deploy can
# set or rotate it without rebuilding the bundle. Served before the SPA loads.
PRIVY_APP_ID = os.getenv("PRIVY_APP_ID", "")


@app.get("/config.js")
def config_js():
    return Response(
        f"window.__PRIVY_APP_ID = {json.dumps(PRIVY_APP_ID)};",
        media_type="application/javascript",
    )


# ---------------------------------------------------------------- SPA serving
#
# In dev, Vite serves the UI and proxies to this process. Outside dev, THIS
# process serves the built SPA from frontend/dist — one origin, one service,
# so the cookie/OIDC flow is identical to dev. Route order is the guarantee
# that no API route is shadowed: everything above registered first, and the
# catch-all below is registered last, so it only sees requests nothing else
# claimed.
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
SERVE_SPA = not DEV_MODE and (DIST / "index.html").is_file()

if SERVE_SPA:
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/")
    def index():
        return FileResponse(DIST / "index.html")

    # All methods, so an unmatched POST (e.g. /api/dev/* when not in dev)
    # gets the same clean 404 it had before the SPA existed — a GET-only
    # catch-all would turn those into 405s and leak route-shape information.
    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    def spa(path: str, request: Request):
        # API namespaces never fall through to HTML: an unknown /api path is
        # a 404, not a 200 page that confuses every client.
        if request.method not in ("GET", "HEAD"):
            raise HTTPException(404, "not found")
        # authorize belongs to the IdP: when the mock is mounted its routes
        # win by registration order; when it is not, the path must 404 like
        # any other absent IdP — never render the SPA shell there.
        if path.split("/", 1)[0] in ("api", "v1", "assets", "authorize"):
            raise HTTPException(404, "not found")
        # Real files from dist (favicons etc.), with the resolved path pinned
        # inside DIST so ../ traversal cannot escape it.
        f = (DIST / path).resolve()
        if path and f.is_file() and f.is_relative_to(DIST.resolve()):
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
else:

    @app.get("/")
    def index():
        return {"service": "fayda-wallet-registry API", "ui": PUBLIC}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
