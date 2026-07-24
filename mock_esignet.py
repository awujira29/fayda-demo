"""
Mock Fayda eSignet provider.

Mirrors the real contract so the client code below is production code:
    GET  /authorize
    POST /v1/esignet/oauth/v2/token     (private_key_jwt client assertion, RS256)
    GET  /v1/esignet/oidc/userinfo      (bearer token)

CAVEAT, and it is the important one: the claim names returned by /userinfo are a
reconstruction. The real scope names and claim shape are only knowable once you
hold approved partner credentials. Everything else here — the flow, the assertion
format, the signing algorithm — follows the published spec and should hold.

Personas below are fictional. FINs are 12 digits to match the real format.
"""

import secrets
import time
from datetime import datetime, timezone, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Form, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

router = APIRouter()

# In-memory state. A real provider persists these.
_codes: dict[str, dict] = {}
_tokens: dict[str, dict] = {}

# The relying party's public key, registered at onboarding. Set by app.py at startup.
CLIENT_PUBLIC_KEY = None
EXPECTED_CLIENT_ID = "fayda-wallet-demo"
TOKEN_ENDPOINT = "http://127.0.0.1:8000/v1/esignet/oauth/v2/token"

PERSONAS = [
    {
        "fin": "301884729166",
        "name": "Meseret Alemu",
        "given_name": "Meseret",
        "family_name": "Alemu",
        "birthdate": "1991-04-17",
        "gender": "female",
        "phone_number": "+251911204418",
        "region": "Addis Ababa",
        "note": "Urban, has a bank account",
    },
    {
        "fin": "774021398450",
        "name": "Tesfaye Bekele",
        "given_name": "Tesfaye",
        "family_name": "Bekele",
        "birthdate": "1978-11-02",
        "gender": "male",
        "phone_number": "+251921887340",
        "region": "Oromia",
        "note": "Rural smallholder, no prior banking",
    },
    {
        "fin": "509163472208",
        "name": "Hiwot Girma",
        "given_name": "Hiwot",
        "family_name": "Girma",
        "birthdate": "1996-07-25",
        "gender": "female",
        "phone_number": "+251913556201",
        "region": "Amhara",
        "note": "Second identity, for testing the sybil constraint",
    },
]


def generate_client_keypair():
    """
    In production you generate this once and register the public JWK with Fayda.
    Generated per run here so the demo needs no setup.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


@router.get("/authorize", response_class=HTMLResponse)
def authorize(request: Request, client_id: str, redirect_uri: str,
              response_type: str = "code", scope: str = "openid profile",
              state: str = "", nonce: str = ""):
    """
    The real thing prompts for fingerprint, iris, face or OTP. Here you pick a
    persona, which stands in for a successful biometric match.
    """
    if client_id != EXPECTED_CLIENT_ID:
        raise HTTPException(400, "unknown client_id")
    if response_type != "code":
        raise HTTPException(400, "only response_type=code is supported")

    cards = ""
    for p in PERSONAS:
        cards += f"""
        <form method="post" action="/authorize/confirm">
          <input type="hidden" name="fin" value="{p['fin']}">
          <input type="hidden" name="redirect_uri" value="{redirect_uri}">
          <input type="hidden" name="state" value="{state}">
          <input type="hidden" name="nonce" value="{nonce}">
          <button class="persona" type="submit">
            <div class="pname">{p['name']}</div>
            <div class="pmeta">FIN {p['fin']} &middot; {p['region']}</div>
            <div class="pnote">{p['note']}</div>
          </button>
        </form>"""

    return f"""<!doctype html><meta charset="utf-8">
<title>Fayda eSignet (mock)</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
  body{{margin:0;background:#12161C;color:#FBFBF9;font-family:'IBM Plex Sans',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}
  .box{{max-width:460px;width:100%}}
  .brand{{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.16em;
          text-transform:uppercase;color:#7E8794;margin-bottom:8px}}
  h1{{font-size:22px;font-weight:600;margin:0 0 6px}}
  .sub{{color:#9AA3B0;font-size:14px;margin:0 0 26px;line-height:1.5}}
  .persona{{display:block;width:100%;text-align:left;background:#1B212A;border:1px solid #2C3542;
            border-radius:6px;padding:15px 17px;margin-bottom:10px;cursor:pointer;color:inherit;
            font-family:inherit;transition:border-color .12s,background .12s}}
  .persona:hover{{border-color:#4E5D70;background:#212936}}
  .pname{{font-size:15px;font-weight:600;margin-bottom:3px}}
  .pmeta{{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:#7E8794}}
  .pnote{{font-size:12.5px;color:#9AA3B0;margin-top:5px}}
  .foot{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:#5C6673;
         margin-top:22px;line-height:1.6;border-top:1px solid #242C36;padding-top:14px}}
</style>
<div class="box">
  <div class="brand">Fayda &middot; eSignet</div>
  <h1>Verify your identity</h1>
  <p class="sub">In production this step captures a fingerprint, iris, face or OTP.
     For the demo, choosing a persona stands in for a successful biometric match.</p>
  {cards}
  <div class="foot">MOCK PROVIDER &mdash; not connected to the national register.<br>
     Requested scope: {scope}</div>
</div>"""


@router.post("/authorize/confirm")
def authorize_confirm(fin: str = Form(...), redirect_uri: str = Form(...),
                      state: str = Form(""), nonce: str = Form("")):
    persona = next((p for p in PERSONAS if p["fin"] == fin), None)
    if not persona:
        raise HTTPException(400, "unknown persona")
    code = secrets.token_urlsafe(24)
    _codes[code] = {"fin": fin, "nonce": nonce, "exp": time.time() + 120}
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=303)


@router.post("/v1/esignet/oauth/v2/token")
def token(grant_type: str = Form(...), code: str = Form(...),
          redirect_uri: str = Form(...), client_id: str = Form(...),
          client_assertion: str = Form(...), client_assertion_type: str = Form(...)):
    """
    Client authentication is private_key_jwt, not a shared secret. This is the
    part most integrations get wrong, so it is verified properly here.
    """
    if grant_type != "authorization_code":
        raise HTTPException(400, "unsupported grant_type")
    if client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        raise HTTPException(400, "bad client_assertion_type")

    try:
        claims = jwt.decode(
            client_assertion,
            CLIENT_PUBLIC_KEY,
            algorithms=["RS256"],
            audience=TOKEN_ENDPOINT,
            options={"require": ["exp", "aud", "iss", "sub"]},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"client assertion rejected: {e}")

    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise HTTPException(401, "client assertion iss/sub mismatch")

    rec = _codes.pop(code, None)
    if not rec or rec["exp"] < time.time():
        raise HTTPException(400, "invalid or expired authorization code")

    access_token = secrets.token_urlsafe(32)
    _tokens[access_token] = {"fin": rec["fin"], "exp": time.time() + 300}

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "openid profile",
    })


@router.get("/v1/esignet/oidc/userinfo")
def userinfo(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    rec = _tokens.get(authorization.split(None, 1)[1])
    if not rec or rec["exp"] < time.time():
        raise HTTPException(401, "invalid or expired access token")

    p = next(x for x in PERSONAS if x["fin"] == rec["fin"])
    # Claim names are a reconstruction. Verify against real docs before production.
    return JSONResponse({
        "sub": p["fin"],
        "fayda_fin": p["fin"],
        "name": p["name"],
        "given_name": p["given_name"],
        "family_name": p["family_name"],
        "birthdate": p["birthdate"],
        "gender": p["gender"],
        "phone_number": p["phone_number"],
        "address": {"region": p["region"], "country": "ET"},
        "auth_method": "biometric.fingerprint",
        "auth_time": int(time.time()),
    })
