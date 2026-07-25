"""
Mock Fayda eSignet provider.

Mirrors the real contract so the client code below is production code:
    GET  /authorize
    POST /v1/esignet/oauth/v2/token     (private_key_jwt client assertion, RS256)
    GET  /v1/esignet/oidc/userinfo      (bearer token)

The userinfo claim shape is CONFIRMED against the official Python client,
github.com/National-ID-Program-Ethiopia/fayda-auth-python:

    sub, name, birthdate, gender, phone, picture, residenceStatus,
    address: {kebele, region, woreda, zone}

`sub` is the only identifier — there is no fayda_fin claim. `picture` is a
face image (stubbed here). The residenceStatus VALUE SET is not confirmed:
the strings below are placeholders and must be checked with NIDP before any
feature keys off them.

Personas below are fictional. FINs are 12 digits to match the real format.
"""

import html
import secrets
import time
from urllib.parse import urlparse

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

# residenceStatus values are placeholders — the real value set is unconfirmed
# and must be checked with NIDP. picture stands in for the base64 face image
# the real provider returns.
PERSONAS = [
    {
        "fin": "301884729166",
        "name": "Meseret Alemu",
        "birthdate": "1991-04-17",
        "gender": "female",
        "phone": "+251911204418",
        "picture": "data:image/jpeg;base64,/9j/MESERET_STUB",
        "residenceStatus": "CITIZEN",
        "address": {"kebele": "13", "region": "Addis Ababa",
                    "woreda": "08", "zone": "Yeka"},
        "note": "Urban, has a bank account",
    },
    {
        "fin": "774021398450",
        "name": "Tesfaye Bekele",
        "birthdate": "1978-11-02",
        "gender": "male",
        "phone": "+251921887340",
        "picture": "data:image/jpeg;base64,/9j/TESFAYE_STUB",
        "residenceStatus": "CITIZEN",
        "address": {"kebele": "02", "region": "Oromia",
                    "woreda": "Kofele", "zone": "West Arsi"},
        "note": "Rural smallholder, no prior banking",
    },
    {
        "fin": "509163472208",
        "name": "Hiwot Girma",
        "birthdate": "1996-07-25",
        "gender": "female",
        "phone": "+251913556201",
        "picture": "data:image/jpeg;base64,/9j/HIWOT_STUB",
        "residenceStatus": "CITIZEN",
        "address": {"kebele": "07", "region": "Amhara",
                    "woreda": "Farta", "zone": "South Gondar"},
        "note": "Second identity, for testing the sybil constraint",
    },
    {
        # Fayda covers legally resident foreign nationals — a valid Fayda auth
        # is NOT proof of citizenship (CLAUDE.md, B2). This persona exists so
        # that distinction is visible and testable.
        "fin": "628304917552",
        "name": "Daniel Otieno",
        "birthdate": "1985-02-11",
        "gender": "male",
        "phone": "+251912774063",
        "picture": "data:image/jpeg;base64,/9j/DANIEL_STUB",
        "residenceStatus": "FOREIGN_NATIONAL",
        "address": {"kebele": "12", "region": "Addis Ababa",
                    "woreda": "03", "zone": "Bole"},
        "note": "Foreign national, legally resident — valid Fayda, not a citizen",
    },
]


def _valid_redirect(redirect_uri: str) -> bool:
    """
    A real OIDC provider only ever redirects to a pre-registered URI. The
    client here always registers a `/callback`, so we accept exactly that
    path (relative or on any http(s) origin) and reject everything else.
    This closes the open redirect — an attacker cannot point a persona login
    at an arbitrary site — and, with the output escaping below, the mock's
    reflected inputs stop being an XSS/phishing surface even though DEMO_MODE
    publishes this page on a real origin.
    """
    try:
        u = urlparse(redirect_uri)
    except ValueError:
        return False
    return u.path == "/callback" and u.scheme in ("", "http", "https")


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
    The real eSignet screen is a biometric prompt: fingerprint, iris, face or
    OTP, matched against the national register. This mock cannot capture
    anything, so the page is framed as exactly that — a simulated capture —
    and choosing a resident below stands in for a successful match. The form
    contract (fin/state/nonce/redirect_uri → POST /authorize/confirm) is the
    part the client code depends on; the framing around it is presentation.
    """
    if client_id != EXPECTED_CLIENT_ID:
        raise HTTPException(400, "unknown client_id")
    if response_type != "code":
        raise HTTPException(400, "only response_type=code is supported")
    if not _valid_redirect(redirect_uri):
        raise HTTPException(400, "invalid redirect_uri")

    # Every reflected value is escaped: these are attacker-supplied query
    # params, and DEMO_MODE serves this page on the deploy's real origin.
    e_redirect = html.escape(redirect_uri, quote=True)
    e_state = html.escape(state, quote=True)
    e_nonce = html.escape(nonce, quote=True)
    cards = ""
    for p in PERSONAS:
        cards += f"""
        <form method="post" action="/authorize/confirm">
          <input type="hidden" name="fin" value="{p['fin']}">
          <input type="hidden" name="redirect_uri" value="{e_redirect}">
          <input type="hidden" name="state" value="{e_state}">
          <input type="hidden" name="nonce" value="{e_nonce}">
          <button class="persona" type="submit">
            <span class="match">MATCH</span>
            <span class="pbody">
              <span class="pname">{p['name']}</span>
              <span class="pmeta">FIN {p['fin']} &middot; {p['address']['region']} &middot; {p['residenceStatus']}</span>
              <span class="pnote">{p['note']}</span>
            </span>
          </button>
        </form>"""

    return f"""<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fayda eSignet (mock)</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@200;400;500;600&display=swap');
  body{{margin:0;background:#12161C;color:#FBFBF9;font-family:'IBM Plex Sans',sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}}
  .box{{max-width:480px;width:100%}}
  .brand{{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.16em;
          text-transform:uppercase;color:#7E8794;margin-bottom:8px}}
  h1{{font-size:24px;font-weight:200;margin:0 0 6px;letter-spacing:-.01em}}
  h1 b{{font-weight:600}}
  .sub{{color:#9AA3B0;font-size:14px;margin:0 0 22px;line-height:1.5}}
  .capture{{display:flex;align-items:center;gap:18px;background:#1B212A;border:1px dashed #3A4656;
            border-radius:6px;padding:16px 18px;margin-bottom:22px}}
  .capture svg{{flex:none}}
  .cap-label{{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:.14em;
              text-transform:uppercase;color:#C9A227;margin-bottom:4px}}
  .cap-text{{font-size:12.5px;color:#9AA3B0;line-height:1.55}}
  .step{{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:.12em;
         text-transform:uppercase;color:#7E8794;margin:0 0 10px}}
  .persona{{display:flex;gap:14px;align-items:flex-start;width:100%;text-align:left;
            background:#1B212A;border:1px solid #2C3542;border-radius:6px;padding:14px 16px;
            margin-bottom:10px;cursor:pointer;color:inherit;font-family:inherit;
            transition:border-color .12s,background .12s}}
  .persona:hover{{border-color:#4E5D70;background:#212936}}
  .persona:focus-visible{{outline:2px solid #C9A227;outline-offset:2px}}
  .match{{font-family:'IBM Plex Mono',monospace;font-size:9.5px;letter-spacing:.12em;
          color:#48A971;border:1px solid #2C5540;border-radius:3px;padding:2px 6px;margin-top:2px}}
  .pbody{{display:block}}
  .pname{{display:block;font-size:15px;font-weight:600;margin-bottom:3px}}
  .pmeta{{display:block;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#8B95A3}}
  .pnote{{display:block;font-size:12.5px;color:#9AA3B0;margin-top:4px}}
  .foot{{font-family:'IBM Plex Mono',monospace;font-size:11px;color:#7E8794;
         margin-top:22px;line-height:1.6;border-top:1px solid #242C36;padding-top:14px}}
</style>
<div class="box">
  <div class="brand">Fayda &middot; eSignet &middot; National ID</div>
  <h1>Biometric verification <b>&mdash; simulated</b></h1>
  <p class="sub">In production this screen captures a <strong>fingerprint, iris or face</strong>
     and matches it against the national register. This mock captures nothing.</p>
  <div class="capture">
    <svg width="44" height="44" viewBox="0 0 44 44" fill="none" aria-hidden="true">
      <!-- fingerprint: nested ridge loops around a core, ridges broken the way
           a print is, with a horizontal scan line -->
      <g stroke="#4E5D70" stroke-width="1.5" stroke-linecap="round">
        <path d="M11.5 30.5C10.5 28 10 25.5 10 23c0-6.6 5.4-12 12-12 4.2 0 7.9 2.2 10 5.4"/>
        <path d="M33.9 20.5c.4 1.1.6 2.3.6 3.5 0 2.8-.4 5.6-1.2 8.5"/>
        <path d="M14.8 33.8C14 31.2 13.5 28 13.5 23c0-4.7 3.8-8.5 8.5-8.5 3.3 0 6.1 1.8 7.5 4.5"/>
        <path d="M30.4 22.2c.1.6.1 1.2.1 1.8 0 3.3-.5 6.6-1.5 9.5"/>
        <path d="M18.4 35c-.9-3-1.4-6.6-1.4-11 0-2.8 2.2-5 5-5s5 2.2 5 5c0 3.7-.4 7.3-1.3 10.5"/>
        <path d="M22 22.5c.8 0 1.5.7 1.5 1.5 0 3.9-.5 7.6-1.4 11"/>
      </g>
      <line x1="6" y1="24" x2="38" y2="24" stroke="#C9A227" stroke-width="1.2" stroke-dasharray="3 3"/>
    </svg>
    <div>
      <div class="cap-label">Step 1 of 2 &mdash; simulated capture, no sensor read</div>
      <div class="cap-text">Selecting a resident below stands in for a successful
        biometric match. The OIDC flow from here on is the real contract.</div>
    </div>
  </div>
  <p class="step">Step 2 of 2 &mdash; select the matched resident</p>
  {cards}
  <div class="foot">MOCK PROVIDER &mdash; not connected to the national register.<br>
     Requested scope: {html.escape(scope, quote=True)}</div>
</div>"""


@router.post("/authorize/confirm")
def authorize_confirm(fin: str = Form(...), redirect_uri: str = Form(...),
                      state: str = Form(""), nonce: str = Form("")):
    persona = next((p for p in PERSONAS if p["fin"] == fin), None)
    if not persona:
        raise HTTPException(400, "unknown persona")
    # Re-validate: this POST can be crafted directly, not only via the page above.
    if not _valid_redirect(redirect_uri):
        raise HTTPException(400, "invalid redirect_uri")
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
    # Confirmed shape (fayda-auth-python): sub is the only identifier.
    return JSONResponse({
        "sub": p["fin"],
        "name": p["name"],
        "birthdate": p["birthdate"],
        "gender": p["gender"],
        "phone": p["phone"],
        "picture": p["picture"],
        "residenceStatus": p["residenceStatus"],
        "address": p["address"],
    })
