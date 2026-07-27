"""
Mock Fayda eSignet provider.

Mirrors the real contract so the client code in app.py is production code:
    GET  /authorize                     (identity capture — see below)
    POST /authorize/confirm             (capture result -> authorization code)
    POST /v1/esignet/oauth/v2/token     (private_key_jwt client assertion, RS256)
    GET  /v1/esignet/oidc/userinfo      (bearer token)

The userinfo claim shape is CONFIRMED against the official Python client,
github.com/National-ID-Program-Ethiopia/fayda-auth-python:

    sub, name, birthdate, gender, phone, picture, residenceStatus,
    address: {kebele, region, woreda, zone}

`sub` is the only identifier — there is no fayda_fin claim. The
residenceStatus VALUE SET is not confirmed: the strings below are placeholders
and must be checked with NIDP before any feature keys off them.

WHY THE CAPTURE LIVES HERE, NOT IN THE SPA
------------------------------------------
Identity verification is the identity provider's job. The real eSignet captures
a face on ITS OWN page, on its own origin, and hands the relying party nothing
but claims. Putting the capture in our SPA would invert that: the registry
would be handling biometric images it has no business seeing, and would create
a second way to become authenticated that does not go through the OIDC code
exchange. Here, the browser holds the images, this page runs the (mocked)
match, and only the resulting CLAIMS cross to the relying party — through
exactly the same code -> token -> userinfo handoff as before.

WHAT IS MOCKED, PRECISELY
-------------------------
The liveness check and the face-to-ID comparison. They always pass. Everything
else is real: a real camera frame, a real document image, a real form, the real
OIDC dance. The page says so on screen rather than implying a biometric match
happened.

WHAT NEVER LEAVES THE BROWSER
-----------------------------
The face frame and the ID image. They live in JavaScript variables and an
object URL, are drawn to a canvas for the match animation, and are dropped when
the page navigates. `POST /authorize/confirm` carries text fields only. Nothing
here writes an image anywhere, and there is no endpoint that would accept one.
A stored face would be the most sensitive object in this system — special
category data, sitting inside the operator/transaction-history surface built in
R3/R4. The verification RESULT persists as an identity row; the biometrics do
not exist after the tab closes.
"""

import hashlib
import html
import json
import secrets
import threading
import time
from urllib.parse import urlencode, urlparse

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

# Injected by app.py at startup, alongside the values above, so the capture
# flow can ask "have we seen this person before?".
#
# INJECTED, not imported. `import app` from here is a trap: app.py imports this
# module, and when the server is started as `python app.py` the main module is
# named `__main__`, so `import app` loads a SECOND copy of app.py — re-running
# its module body, generating a fresh client keypair, and overwriting
# CLIENT_PUBLIC_KEY above with one whose private half nobody holds. Every
# subsequent token exchange then fails with "signature verification failed".
# Observed exactly that. The behaviour also differed by launch method
# (`uvicorn app:app` names the module `app`), which is the worst kind of bug.
HASH_FIN = None

# The one redirect URI registered for this client, injected by app.py from
# PUBLIC_URL. See _valid_redirect — an exact match is what stops an
# authorization code being delivered to somebody else's server.
REGISTERED_REDIRECT = None

# Whether the "have I verified here before?" probe is exposed. True only in
# dev. It answers, unauthenticated, whether a given name and date of birth is
# registered — harmless on a developer's machine, an enumeration oracle over
# real people's details on a published demo. The capture page offers the
# passkey route unconditionally, so a returning user is never forced back
# through capture even where the probe does not exist.
KNOWN_PROBE = False

# Placeholders — the real value set is unconfirmed and must be checked with
# NIDP (CLAUDE.md, B2). Fayda covers legally resident foreign nationals, so a
# valid Fayda authentication is NOT proof of citizenship; the capture form
# makes that a deliberate choice rather than an assumption.
RESIDENCE_STATUSES = ("CITIZEN", "FOREIGN_NATIONAL")

REGIONS = ("Addis Ababa", "Oromia", "Amhara", "Tigray", "Sidama", "Somali",
           "Afar", "Benishangul-Gumuz", "Gambela", "Harari", "Dire Dawa",
           "South West Ethiopia", "Central Ethiopia")

GENDERS = ("female", "male")

MAX_FIELD = 120


def derive_sub(full_name: str, birthdate: str) -> str:
    """
    A stable FIN-shaped identifier for the captured person.

    The same name and birthdate must always produce the same `sub`, because
    that is what makes "verify once" true: the registry keys identities on
    HMAC(pepper, sub), so a returning person lands on their existing row rather
    than a duplicate. Name is folded to lower case and internal whitespace is
    collapsed so "  Meseret   Alemu " is the same person as "Meseret Alemu".

    Twelve digits because a real FIN is twelve digits, and the point of a mock
    is to have the same shape as the thing it stands in for.
    """
    norm = " ".join((full_name or "").split()).lower()
    digest = hashlib.sha256(f"{norm}|{(birthdate or '').strip()}".encode()).hexdigest()
    return str(int(digest[:16], 16) % 10**12).zfill(12)


def _valid_redirect(redirect_uri: str) -> bool:
    """
    Exact match against the ONE registered redirect URI. Host included.

    This used to check the path only, accepting `/callback` on any host, and
    that was written off as inconsequential because the leaked authorization
    code "maps only to a mock persona anyone could select anyway". The capture
    flow destroys that reasoning: a code now maps to a real person's verified
    identity. An attacker who starts their own login, reads their own `state`,
    and sends a victim a link with `redirect_uri=https://evil/callback` receives
    the victim's code on their own server and replays it into their own
    session — demonstrated end to end, landing authenticated as the victim.
    DEMO_MODE publishes this page on a real origin, so it was reachable.

    A real OIDC provider compares against the URI registered at onboarding and
    nothing else. So does this now. REGISTERED_REDIRECT is injected by app.py,
    which derives it from PUBLIC_URL — the same value the browser is required
    to stay on for the session cookie to work.
    """
    if not REGISTERED_REDIRECT:
        # Not wired up: refuse everything rather than fall back to the loose
        # check. A mock that cannot tell where it is allowed to send a code
        # should not send one.
        return False
    return redirect_uri == REGISTERED_REDIRECT


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


MAX_PENDING = 5_000
_STATE_LOCK = threading.Lock()


def _expire() -> None:
    """
    Reclaim spent and expired codes and tokens. In-process maps that only ever
    grow are a denial of service by patience; a real provider persists these
    with a TTL, and the mock should at least not fall over.

    Under a lock: these handlers are sync, so uvicorn runs them on a thread
    pool and two concurrent requests really can mutate the dict while this
    iterates ("dictionary changed size during iteration"). Not reproducible
    through HTTP in testing, but the window is real and the fix is one lock.
    """
    now = time.time()
    with _STATE_LOCK:
        for m in (_codes, _tokens):
            for k in [k for k, v in list(m.items()) if v["exp"] < now]:
                m.pop(k, None)
            # Hard ceiling, in case something issues faster than they expire.
            while len(m) > MAX_PENDING:
                m.pop(next(iter(m)), None)


def _clean(value: str, label: str, allowed=None) -> str:
    v = " ".join((value or "").split())
    if not v:
        raise HTTPException(400, f"{label} is required")
    if len(v) > MAX_FIELD:
        raise HTTPException(400, f"{label} is too long")
    if "\x00" in v:
        raise HTTPException(400, f"{label} is malformed")
    if allowed is not None and v not in allowed:
        raise HTTPException(400, f"{label} is not a recognised value")
    return v


# --------------------------------------------------------------- capture page

_PAGE_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#12161C;color:#FBFBF9;font-family:'IBM Plex Sans',sans-serif;
     display:flex;align-items:flex-start;justify-content:center;min-height:100vh;padding:24px}
.box{max-width:520px;width:100%}
.brand{font-family:'IBM Plex Mono',monospace;font-size:11px;letter-spacing:.16em;
       text-transform:uppercase;color:#7E8794;margin-bottom:8px}
h1{font-size:24px;font-weight:200;margin:0 0 6px;letter-spacing:-.01em}
h1 b{font-weight:600}
.sub{color:#9AA3B0;font-size:14px;margin:0 0 20px;line-height:1.55}
.steps{display:flex;gap:6px;margin:0 0 20px}
.pip{flex:1;height:2px;background:#242C36;border-radius:2px}
.pip.on{background:#C9A227}
.pip.done{background:#48A971}
.step-label{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:.14em;
            text-transform:uppercase;color:#7E8794;margin:0 0 12px}
.card{background:#1B212A;border:1px solid #2C3542;border-radius:6px;padding:18px}
label{display:block;font-family:'IBM Plex Mono',monospace;font-size:10.5px;
      letter-spacing:.12em;text-transform:uppercase;color:#8B95A3;margin:0 0 5px}
input[type=text],input[type=date],select{width:100%;background:#12161C;color:#FBFBF9;
      border:1px solid #2C3542;border-radius:4px;padding:9px 11px;font-size:14px;
      font-family:inherit;margin-bottom:14px}
input:focus,select:focus{outline:2px solid #C9A227;outline-offset:1px;border-color:#4E5D70}
.row{display:flex;gap:12px}
.row>div{flex:1}
.toggle{display:flex;gap:8px;margin-bottom:6px}
.toggle button{flex:1;background:#12161C;border:1px solid #2C3542;color:#9AA3B0;
      border-radius:4px;padding:11px 8px;cursor:pointer;font-family:inherit;font-size:13px;
      transition:border-color .12s,color .12s,background .12s}
.toggle button[aria-pressed=true]{border-color:#C9A227;color:#FBFBF9;background:#212936}
.toggle button:focus-visible{outline:2px solid #C9A227;outline-offset:2px}
.hint{font-size:12px;color:#7E8794;line-height:1.5;margin:2px 0 16px}
.btn{width:100%;background:#C9A227;border:1px solid #C9A227;color:#12161C;border-radius:4px;
     padding:12px;font-size:14px;font-weight:600;font-family:inherit;cursor:pointer;
     transition:opacity .12s}
.btn:hover{opacity:.9}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn.ghost{background:transparent;color:#9AA3B0;border-color:#2C3542;font-weight:400}
.btn.ghost:hover{color:#FBFBF9;border-color:#4E5D70}
.btnrow{display:flex;gap:10px;margin-top:14px}
video,canvas.preview,img.preview{width:100%;border-radius:4px;background:#0C0F14;display:block}
video{transform:scaleX(-1)}
.frame{position:relative;border:1px dashed #3A4656;border-radius:6px;padding:8px;background:#12161C}
.oval{position:absolute;inset:8px;border:2px solid rgba(201,162,39,.5);
      border-radius:50%/38%;pointer-events:none}
.filedrop{border:1px dashed #3A4656;border-radius:6px;padding:22px;text-align:center;
          background:#12161C;cursor:pointer}
.filedrop:hover{border-color:#4E5D70}
.filedrop input{display:none}
.filedrop .ico{font-family:'IBM Plex Mono',monospace;font-size:10.5px;letter-spacing:.14em;
               text-transform:uppercase;color:#C9A227;margin-bottom:6px}
.sidebyside{display:flex;gap:12px}
.sidebyside>div{flex:1}
.cap{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.12em;
     text-transform:uppercase;color:#7E8794;margin:6px 0 0}
.checks{list-style:none;padding:0;margin:16px 0 0}
.checks li{display:flex;align-items:center;gap:10px;padding:7px 0;font-size:13px;
           color:#7E8794;border-top:1px solid #242C36}
.checks li .dot{width:14px;height:14px;border-radius:50%;border:1.5px solid #3A4656;flex:none}
.checks li.run{color:#FBFBF9}
.checks li.run .dot{border-color:#C9A227;border-top-color:transparent;animation:spin .7s linear infinite}
.checks li.ok{color:#FBFBF9}
.checks li.ok .dot{border-color:#48A971;background:#48A971}
@keyframes spin{to{transform:rotate(360deg)}}
.result{text-align:center;padding:8px 0 4px}
.tick{width:52px;height:52px;border-radius:50%;border:2px solid #48A971;color:#48A971;
      display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:26px}
.score{font-family:'IBM Plex Mono',monospace;font-size:12px;color:#48A971;letter-spacing:.1em}
.alert{background:#221C10;border:1px solid #4A3A16;border-radius:4px;padding:12px 14px;
       font-size:13px;color:#E8CF8A;line-height:1.5;margin-bottom:14px}
.alert b{color:#FBFBF9}
.known{background:#101A16;border:1px solid #2C5540;border-radius:4px;padding:14px;
       font-size:13px;color:#9FD9B8;line-height:1.55;margin-bottom:14px}
.foot{font-family:'IBM Plex Mono',monospace;font-size:11px;color:#7E8794;
      margin-top:20px;line-height:1.6;border-top:1px solid #242C36;padding-top:14px}
.err{color:#E88A8A;font-size:13px;margin:10px 0 0;line-height:1.5}
.hidden{display:none}
"""


def _page(e_redirect: str, e_state: str, e_nonce: str, e_scope: str,
          redirect_js: str) -> str:
    """
    The capture flow, as one self-contained document.

    Deliberately no framework and no network calls that carry an image: the
    only request this page makes with a body is the final form POST of text
    fields, plus an optional "do you already know me?" probe that sends a name
    and a date. Everything visual happens against local object URLs and a
    canvas, so the frames genuinely cannot leave the machine.
    """
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fayda eSignet — identity verification (mock)</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@200;400;500;600&display=swap');
{_PAGE_CSS}
</style>
<body>
<div class="box">
  <div class="brand">Fayda &middot; eSignet &middot; National ID</div>
  <h1>Identity <b>verification</b></h1>
  <p class="sub" id="lede">Confirm who you are with a live photo and your national ID.
     This takes about a minute and happens once.</p>

  <div class="steps" aria-hidden="true">
    <div class="pip on" id="pip0"></div><div class="pip" id="pip1"></div>
    <div class="pip" id="pip2"></div><div class="pip" id="pip3"></div>
  </div>

  <!-- 1 ─ details ------------------------------------------------------- -->
  <section id="s0">
    <p class="step-label">Step 1 of 4 — your details</p>
    <div class="card">
      <label for="f_name">Full name</label>
      <input type="text" id="f_name" autocomplete="name" maxlength="120"
             placeholder="As printed on your ID">
      <div class="row">
        <div>
          <label for="f_dob">Date of birth</label>
          <input type="date" id="f_dob">
        </div>
        <div>
          <label for="f_gender">Gender</label>
          <select id="f_gender">
            <option value="female">female</option>
            <option value="male">male</option>
          </select>
        </div>
      </div>
      <label for="f_region">Region</label>
      <select id="f_region">{"".join(f'<option>{html.escape(r)}</option>' for r in REGIONS)}</select>

      <label id="rs_label">Residence status</label>
      <div class="toggle" role="group" aria-labelledby="rs_label">
        <button type="button" id="rs_cit" aria-pressed="true">Ethiopian citizen</button>
        <button type="button" id="rs_for" aria-pressed="false">Foreign national, resident</button>
      </div>
      <p class="hint">Fayda is issued to legally resident foreign nationals as well as
        citizens, so holding one does not by itself prove citizenship. Say which
        applies — services that are citizens-only depend on this answer.</p>
      <div id="knownbox"></div>
      <button class="btn" id="go1" disabled>Continue to photo</button>
      <p class="hint" style="margin:12px 0 0;text-align:center">
        Verified here before?
        <a href="#" id="pklink" style="color:#C9A227">Sign in with your passkey instead</a>
        — no need to photograph anything again.
      </p>
      <p class="err hidden" id="err0"></p>
    </div>
  </section>

  <!-- 2 ─ face ---------------------------------------------------------- -->
  <section id="s1" class="hidden">
    <p class="step-label">Step 2 of 4 — live photo</p>
    <div class="card">
      <div id="cam_wrap">
        <div class="frame"><video id="cam" autoplay playsinline muted></video><div class="oval"></div></div>
        <p class="hint" style="margin-top:10px">Look straight at the camera in even light.
          Nothing is recorded — the frame stays on this device.</p>
        <button class="btn" id="snap">Capture photo</button>
      </div>
      <div id="cam_denied" class="hidden">
        <div class="alert"><b>The camera is not available.</b> You can upload a photo of
          yourself instead — it is used for the same check and is not stored.</div>
        <label class="filedrop" for="f_selfie">
          <div class="ico">Upload a photo of yourself</div>
          <div class="hint" style="margin:0">JPEG or PNG, taken just now</div>
          <input type="file" id="f_selfie" accept="image/*">
        </label>
        <p class="err hidden" id="err_selfie"></p>
      </div>
      <div id="cam_shot" class="hidden">
        <canvas class="preview" id="shot"></canvas>
        <p class="cap">Captured — held on this device only</p>
        <div class="btnrow">
          <button class="btn ghost" id="retake">Retake</button>
          <button class="btn" id="go2">Use this photo</button>
        </div>
      </div>
      <p class="err hidden" id="err1"></p>
    </div>
  </section>

  <!-- 3 ─ document ------------------------------------------------------ -->
  <section id="s2" class="hidden">
    <p class="step-label">Step 3 of 4 — your national ID</p>
    <div class="card">
      <label class="filedrop" for="f_id" id="iddrop">
        <div class="ico">Upload your Fayda card or passport</div>
        <div class="hint" style="margin:0">Photo or scan of the front, all four corners visible</div>
        <input type="file" id="f_id" accept="image/*">
      </label>
      <div id="id_preview_wrap" class="hidden">
        <img class="preview" id="id_preview" alt="The identity document you uploaded">
        <p class="cap">Held on this device only</p>
        <div class="btnrow">
          <button class="btn ghost" id="id_again">Choose another</button>
          <button class="btn" id="go3">Continue to review</button>
        </div>
      </div>
      <p class="err hidden" id="err2"></p>
    </div>
  </section>

  <!-- 4 ─ match --------------------------------------------------------- -->
  <section id="s3" class="hidden">
    <p class="step-label">Step 4 of 4 — verification</p>
    <div class="card">
      <div class="sidebyside">
        <div><canvas class="preview" id="rev_face"></canvas><p class="cap">Live photo</p></div>
        <div><img class="preview" id="rev_id" alt="Your uploaded document"><p class="cap">Document</p></div>
      </div>
      <ul class="checks" id="checks">
        <li data-k="live"><span class="dot"></span><span>Liveness — confirming a real person</span></li>
        <li data-k="doc"><span class="dot"></span><span>Document — reading the identity page</span></li>
        <li data-k="face"><span class="dot"></span><span>Face match — photo against document</span></li>
        <li data-k="reg"><span class="dot"></span><span>National register — matching the record</span></li>
      </ul>
      <div id="verdict" class="hidden">
        <div class="result">
          <div class="tick" aria-hidden="true">&#10003;</div>
          <div style="font-size:15px;font-weight:600;margin-bottom:4px">Identity verified</div>
          <div class="score" id="scoretext">MATCH CONFIDENCE 98.7%</div>
        </div>
        <div class="alert" style="margin-top:14px"><b>Simulated match.</b> No real
          biometric comparison was performed. The photo and document were read on this
          device, used for this screen, and discarded — they are never uploaded or stored.
          <br><br>Because nothing was checked against the national register, <b>anyone who
          enters the same name and date of birth reaches this same demo record.</b>
          Treat it as a demonstration, not as your identity, and do not put anything
          private here.</div>
        <button class="btn" id="finish">Continue to the registry</button>
      </div>
      <p class="err hidden" id="err3"></p>
    </div>
  </section>

  <!-- the only thing that crosses to the server: text -------------------- -->
  <form id="handoff" method="post" action="/authorize/confirm" class="hidden">
    <input type="hidden" name="full_name" id="h_name">
    <input type="hidden" name="birthdate" id="h_dob">
    <input type="hidden" name="gender" id="h_gender">
    <input type="hidden" name="region" id="h_region">
    <input type="hidden" name="residence_status" id="h_rs">
    <input type="hidden" name="redirect_uri" value="{e_redirect}">
    <input type="hidden" name="state" value="{e_state}">
    <input type="hidden" name="nonce" value="{e_nonce}">
  </form>

  <div class="foot">MOCK PROVIDER — not connected to the national register.<br>
    Photo and document never leave this device.<br>
    Requested scope: {e_scope}</div>
</div>

<script>
(function(){{
  var $ = function(id){{ return document.getElementById(id); }};
  var state = {{ rs: "CITIZEN", face: null, doc: null, stream: null,
                 told: false, busy: false }};

  function show(n){{
    for (var i=0;i<4;i++){{
      $("s"+i).classList.toggle("hidden", i!==n);
      var pip = $("pip"+i);
      pip.className = "pip" + (i<n ? " done" : i===n ? " on" : "");
    }}
    window.scrollTo(0,0);
  }}
  function err(id, msg){{ var e=$(id); e.textContent=msg; e.classList.remove("hidden"); }}
  function clearErr(id){{ $(id).classList.add("hidden"); }}

  /* ---- step 1: details ------------------------------------------------ */
  function detailsReady(){{
    return $("f_name").value.trim().length > 1 && $("f_dob").value !== "";
  }}
  function refresh(){{ $("go1").disabled = !detailsReady(); }}
  $("f_name").addEventListener("input", refresh);
  $("f_dob").addEventListener("input", refresh);

  $("rs_cit").addEventListener("click", function(){{
    state.rs="CITIZEN"; $("rs_cit").setAttribute("aria-pressed","true");
    $("rs_for").setAttribute("aria-pressed","false");
  }});
  $("rs_for").addEventListener("click", function(){{
    state.rs="FOREIGN_NATIONAL"; $("rs_for").setAttribute("aria-pressed","true");
    $("rs_cit").setAttribute("aria-pressed","false");
  }});

  $("go1").addEventListener("click", function(){{
    clearErr("err0");
    // Guard against a second press while the probe is in flight: two presses
    // called startCamera() twice, and the first getUserMedia stream was
    // orphaned — the camera light stayed on after the photo was taken, which
    // on a page about not keeping your image is precisely the wrong signal.
    if (state.busy) return;
    // Once told they are already known, a second press means "verify anyway".
    if (state.told) {{ show(1); startCamera(); return; }}
    state.busy = true;
    // Ask whether this person has already been verified here. If so there is
    // nothing to capture — they sign back in with the passkey they registered.
    // The endpoint only exists in dev; anywhere else this 404s and the flow
    // simply carries on to capture, which is the safe default.
    fetch("/authorize/known", {{
      method: "POST",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify({{ full_name: $("f_name").value, birthdate: $("f_dob").value }})
    }}).then(function(r){{ return r.ok ? r.json() : {{known:false}}; }})
      .catch(function(){{ return {{known:false}}; }})
      .then(function(j){{
        state.busy = false;
        if (j && j.known) {{ alreadyVerified(); return; }}
        show(1); startCamera();
      }});
  }});

  function backToRegistry(){{
    // The relying party's own origin; the passkey button lives there.
    var u = new URL({redirect_js}, window.location.href);
    window.location.href = u.origin + "/";
  }}
  $("pklink").addEventListener("click", function(e){{ e.preventDefault(); backToRegistry(); }});

  function alreadyVerified(){{
    $("knownbox").innerHTML =
      '<div class="known"><b>You have already verified with us.</b><br>' +
      'There is no need to photograph anything again — return to the registry and ' +
      'sign in with the passkey you registered on your device.</div>' +
      '<button class="btn" id="backpk">Return and sign in with a passkey</button>';
    $("backpk").addEventListener("click", backToRegistry);
    // The continue button STAYS. Registering a passkey is optional, so a
    // returning person may genuinely have none — hiding this stranded them
    // with no way forward at all. Recognition is advice, not a gate.
    state.told = true;
    $("go1").textContent = "Verify again instead";
    $("go1").classList.add("ghost");
  }}

  /* ---- step 2: face --------------------------------------------------- */
  function startCamera(){{
    stopCamera();   // never hold two streams; the light must go out
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {{ denied(); return; }}
    navigator.mediaDevices.getUserMedia({{ video: {{ facingMode: "user", width: {{ideal: 640}} }} }})
      .then(function(s){{ state.stream = s; $("cam").srcObject = s; }})
      .catch(function(){{ denied(); }});
  }}
  function denied(){{
    $("cam_wrap").classList.add("hidden");
    $("cam_denied").classList.remove("hidden");
  }}
  function stopCamera(){{
    if (state.stream) {{ state.stream.getTracks().forEach(function(t){{ t.stop(); }});
                        state.stream = null; }}
  }}
  function drawFace(source, w, h){{
    var c = $("shot"); c.width = w; c.height = h;
    var g = c.getContext("2d");
    // Un-mirror the preview so the stored frame matches what a document shows.
    g.save(); g.translate(w,0); g.scale(-1,1); g.drawImage(source,0,0,w,h); g.restore();
    state.face = true;
    var r = $("rev_face"); r.width = w; r.height = h;
    r.getContext("2d").drawImage(c,0,0);
    $("cam_wrap").classList.add("hidden");
    $("cam_denied").classList.add("hidden");
    $("cam_shot").classList.remove("hidden");
  }}
  $("snap").addEventListener("click", function(){{
    var v = $("cam");
    if (!v.videoWidth) {{ err("err1","The camera is not ready yet — give it a moment."); return; }}
    clearErr("err1"); drawFace(v, v.videoWidth, v.videoHeight); stopCamera();
  }});
  $("f_selfie").addEventListener("change", function(e){{
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var img = new Image();
    img.onload = function(){{ drawFace(img, img.width, img.height); URL.revokeObjectURL(img.src); }};
    img.onerror = function(){{ err("err_selfie","That file could not be read as an image."); }};
    img.src = URL.createObjectURL(f);
  }});
  $("retake").addEventListener("click", function(){{
    state.face = null;
    $("cam_shot").classList.add("hidden");
    $("cam_wrap").classList.remove("hidden");
    startCamera();
  }});
  $("go2").addEventListener("click", function(){{ stopCamera(); show(2); }});

  /* ---- step 3: document ----------------------------------------------- */
  $("f_id").addEventListener("change", function(e){{
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    clearErr("err2");
    var url = URL.createObjectURL(f);
    $("id_preview").src = url; $("rev_id").src = url;
    state.doc = true;
    $("iddrop").classList.add("hidden");
    $("id_preview_wrap").classList.remove("hidden");
  }});
  $("id_again").addEventListener("click", function(){{
    state.doc = null;
    $("id_preview_wrap").classList.add("hidden");
    $("iddrop").classList.remove("hidden");
    $("f_id").value = "";
  }});
  $("go3").addEventListener("click", function(){{
    if (!state.doc) {{ err("err2","Upload your ID to continue."); return; }}
    show(3); runMatch();
  }});

  /* ---- step 4: the mocked match --------------------------------------- */
  function runMatch(){{
    var items = Array.prototype.slice.call($("checks").children);
    items.forEach(function(li){{ li.className = ""; }});
    $("verdict").classList.add("hidden");
    var i = 0;
    (function next(){{
      if (i > 0) items[i-1].className = "ok";
      if (i >= items.length) {{
        // Decorative, and labelled as such on screen. It is not derived from
        // any comparison, because no comparison happened.
        $("scoretext").textContent = "MATCH CONFIDENCE " +
          (97 + Math.random() * 2.4).toFixed(1) + "%";
        $("verdict").classList.remove("hidden");
        return;
      }}
      items[i].className = "run";
      i++;
      setTimeout(next, 620 + Math.random() * 420);
    }})();
  }}

  /* ---- handoff: TEXT ONLY --------------------------------------------- */
  $("finish").addEventListener("click", function(){{
    $("h_name").value   = $("f_name").value;
    $("h_dob").value    = $("f_dob").value;
    $("h_gender").value = $("f_gender").value;
    $("h_region").value = $("f_region").value;
    $("h_rs").value     = state.rs;
    // state.face / state.doc are booleans; the pixels live in canvases and an
    // object URL and are never read into this form. The browser navigates away
    // and they cease to exist.
    $("handoff").submit();
  }});

  refresh();
}})();
</script>
</html>"""


@router.get("/authorize", response_class=HTMLResponse)
def authorize(request: Request, client_id: str, redirect_uri: str,
              response_type: str = "code", scope: str = "openid profile",
              state: str = "", nonce: str = ""):
    """
    The verification screen. In production this is eSignet's own page capturing
    a fingerprint, iris or face against the national register; here it captures
    a real photo and a real document and mocks only the comparison.
    """
    if client_id != EXPECTED_CLIENT_ID:
        raise HTTPException(400, "unknown client_id")
    if response_type != "code":
        raise HTTPException(400, "only response_type=code is supported")
    if not _valid_redirect(redirect_uri):
        raise HTTPException(400, "invalid redirect_uri")

    # Every reflected value is escaped: these are attacker-supplied query
    # params, and DEMO_MODE serves this page on the deploy's real origin.
    # HTML-escaping is right for attribute context; the one place the redirect
    # URI is needed as a JS *value* gets json.dumps, which is what makes a
    # correctly-quoted string literal in a script context. `</` is then broken
    # up so a payload cannot close the <script> element from inside a string.
    redirect_js = json.dumps(redirect_uri).replace("</", "<\\/")
    return _page(
        html.escape(redirect_uri, quote=True),
        html.escape(state, quote=True),
        html.escape(nonce, quote=True),
        html.escape(scope, quote=True),
        redirect_js,
    )


@router.post("/authorize/known")
async def already_verified(request: Request):
    """
    Has this person verified here before?

    Answers so the capture flow can send a returning user to their passkey
    instead of making them photograph themselves again. It reveals only what
    someone who already knows an exact name and date of birth could learn by
    starting a verification anyway, and it exists on the mock IdP alone —
    dev/demo only, never mounted against a real provider.
    """
    # The gate comes FIRST, before any parsing or early return. Answering
    # `{"known": false}` to a malformed body ahead of the guard made the route
    # detectable outside dev — it leaked no person's data, but a 200 where a
    # 404 is expected tells an attacker the surface exists.
    if not KNOWN_PROBE or HASH_FIN is None:
        raise HTTPException(404, "not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "expected a JSON object")
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object")
    name = " ".join(str(body.get("full_name", "")).split())[:MAX_FIELD]
    dob = str(body.get("birthdate", ""))[:MAX_FIELD]
    if not name or not dob:
        return JSONResponse({"known": False})

    import store as _store
    try:
        known = _store.identity_exists(HASH_FIN(derive_sub(name, dob)))
    except Exception:
        known = False
    return JSONResponse({"known": bool(known)})


@router.post("/authorize/confirm")
def authorize_confirm(full_name: str = Form(...), birthdate: str = Form(...),
                      gender: str = Form(...), region: str = Form(...),
                      residence_status: str = Form(...),
                      redirect_uri: str = Form(...),
                      state: str = Form(""), nonce: str = Form("")):
    """
    The capture result becomes an authorization code.

    Note what this signature accepts: five text fields and the OIDC
    parameters. There is no image field, so there is no path by which a face
    or a document could reach the server even if a client tried to send one —
    FastAPI drops unknown form parts, and nothing here reads the raw body.
    """
    name = _clean(full_name, "full name")
    dob = _clean(birthdate, "date of birth")
    sex = _clean(gender, "gender", GENDERS)
    reg = _clean(region, "region", REGIONS)
    res = _clean(residence_status, "residence status", RESIDENCE_STATUSES)

    # Re-validate: this POST can be crafted directly, not only via the page above.
    if not _valid_redirect(redirect_uri):
        raise HTTPException(400, "invalid redirect_uri")

    # Drop what has expired before adding more. Both maps are in-process and
    # were never pruned: an unauthenticated loop on this endpoint grew them
    # until the container died, which is a slow way to take the demo down.
    _expire()

    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "subject": {"name": name, "birthdate": dob, "gender": sex,
                    "region": reg, "residenceStatus": res},
        "redirect_uri": redirect_uri,
        "nonce": nonce, "exp": time.time() + 120,
    }
    # Encoded, not concatenated. `state` is caller-supplied, and an unencoded
    # `&code=…` inside it appended a second `code` parameter — Starlette's
    # parser prefers the LAST one, so an attacker could choose which code the
    # callback exchanged. Inert today because app.py checks `state` before
    # exchanging anything, but this file is the template a real integration
    # gets copied from, and that check is one refactor away from moving.
    sep = "&" if "?" in redirect_uri else "?"
    query = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}{sep}{query}", status_code=303)


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

    with _STATE_LOCK:
        rec = _codes.pop(code, None)
    if not rec or rec["exp"] < time.time():
        raise HTTPException(400, "invalid or expired authorization code")
    # RFC 6749 §4.1.3: the redirect_uri presented here must match the one the
    # code was issued against. With a single registered URI this cannot
    # currently differ — but "cannot currently differ" is not a check, and this
    # file is what a real integration is modelled on.
    if redirect_uri != rec["redirect_uri"]:
        raise HTTPException(400, "redirect_uri does not match the authorization request")

    access_token = secrets.token_urlsafe(32)
    _tokens[access_token] = {"subject": rec["subject"], "exp": time.time() + 300}

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

    s = rec["subject"]
    sub = derive_sub(s["name"], s["birthdate"])
    # Confirmed shape (fayda-auth-python): sub is the only identifier.
    #
    # `phone` and `picture` are stubs, and they are here on purpose: the real
    # provider returns both, and app.py's SAFE_CLAIMS whitelist is what stops
    # them reaching the session or the browser. Dropping them would make that
    # whitelist untestable. `picture` is a fixed placeholder string — it is NOT
    # the photo the user just took, which never left their browser.
    return JSONResponse({
        "sub": sub,
        "name": s["name"],
        "birthdate": s["birthdate"],
        "gender": s["gender"],
        "phone": "+2519" + sub[:7],
        "picture": "data:image/jpeg;base64,/9j/PLACEHOLDER_NOT_THE_CAPTURED_FACE",
        "residenceStatus": s["residenceStatus"],
        "address": {
            # Fixed placeholders. These were briefly derived from `sub`
            # (`sub[:2]`, `sub[2:4]`), which quietly put four digits of the
            # FIN-shaped identifier into `address` — and `address` IS in
            # SAFE_CLAIMS, so those digits landed in sessions.data and came
            # back from /api/me. Non-negotiable #1 says the raw FIN never
            # reaches the browser; four digits of it is still four digits of
            # it, and a substring test looking for the whole value would never
            # have caught it. Nothing in this claim derives from `sub`.
            "kebele": "00",
            "region": s["region"],
            "woreda": "00",
            "zone": s["region"],
        },
    })
