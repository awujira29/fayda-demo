# AUDIT

Adversarial security audit of the Fayda identity → wallet registry.
Newest run at the top. The auditor reports; it does not fix.

---

## Audit - 2026-07-27 — capture flow (Sumsub-style mock IdP), working tree at 0da04c3

**Scope.** The uncommitted diff: `backend/mock_esignet.py` (rewritten),
`backend/store.py` (+`identity_exists`), `backend/app.py` (+1 line),
`backend/t.py` (tests 58/59), `frontend/src/components/VerifyGate.jsx` (copy).
Read against `CAPTURE.md` and CLAUDE.md's non-negotiables.

**Method.** Two throwaway uvicorn instances of my own, both terminated: :8099
(`APP_ENV=dev`, `RATE_LIMIT=off`, `BASE_URL`/`PUBLIC_URL` pinned to itself so the
token exchange is self-consistent) and :8098 in the **shipped** posture
(`APP_ENV=production DEMO_MODE=1`, limiter ON) to check what the Render deploy
actually exposes. `t.py` not run (test 32 resets the shared database). Every
attack below was driven, not reasoned about. Probe scripts lived in the
scratchpad; no project file was modified. The dev database picked up a handful of
throwaway identity rows ("Victim Person", "Squat Target", "Probe *") — the next
`t.py` run resets them.

**Headline: the central claim holds. The front door does not.** I could not find
any path by which a face or document byte reaches the session, a table, the
access log, or a response — verified by parsing the served DOM and by pushing
real multipart image parts at the server. But the flow that replaced the persona
picker turns the demo's sign-in into a working identity takeover, and
`/authorize/known` hands an attacker the target list.

**1 critical, 1 high, 5 medium, 6 low.**

### Critical

#### C1 — Attacker-chosen `state` + the path-only redirect check = full takeover of any identity that completes capture. Demonstrated end to end.

*Where:* `backend/mock_esignet.py:120-134` (`_valid_redirect`), `:687-689` (the
303 that carries the code), `backend/app.py:605-618` (`/callback`). Published on
the public internet by `render.yaml:16-18` (`DEMO_MODE=1`).

*Confidence: certain.* Driven against a running server; transcript below.

`_valid_redirect` checks only that the **path** is `/callback`. The host is free.
So `https://evil.example.com/callback` validates, and `/authorize/confirm` 303s
the freshly minted authorization code to it. The previous audit
(AUDIT.md:5294-5308) looked at exactly this and ruled it inconsequential, on two
grounds: *"the leaked code is unexchangeable without the private_key_jwt client
assertion"* and *"the code maps only to a mock persona that anyone can select via
`/login` anyway"*. **This diff invalidates both.** The attacker never needs to
exchange the code — they feed it to the relying party's own `/callback`, which
holds the key. And the code no longer maps to a shared fictional persona; it maps
to whatever the victim just typed into a real identity-capture form.

The attack, exactly as run:

1. Attacker hits `/login` in their own browser and reads `state=S` out of the
   redirect. `S` is now bound to the **attacker's** pre-auth session (valid 30
   min, `PRE_AUTH_SESSION_TTL_HOURS`).
2. Attacker sends the victim
   `https://<demo>/authorize?client_id=fayda-wallet-demo&redirect_uri=https://evil.example.com/callback&state=S&nonce=n`.
   This is the legitimate origin serving the legitimate capture page — I confirmed
   it renders (200, `getUserMedia` present) in the production+DEMO_MODE posture
   with the foreign `redirect_uri`.
3. Victim fills in the form, photographs themselves, uploads their ID, sees
   "Identity verified", clicks Continue.
4. The code lands on the attacker's server:
   `https://evil.example.com/callback?code=W4X_A_dkdVrODWI8HisGhIPsBnAy5VrA&state=UTUw9CbqSZK1C-pVaTPtgA`
5. Attacker replays it into their **own** session: `GET /callback?code=...&state=S`
   → 307, and `/api/me` returns `authenticated: True`,
   `display_name: "Victim Person"`, the victim's claims, the victim's
   `identity_id`.

The `state` check at `app.py:609` does not stop this: it binds the code to the
session that *chose* the state, and the attacker chose it. From there the attacker
holds an `auth_method: "fayda"` session — `POST /api/passkey/register/begin`
returns 200, so they can enrol a permanent credential on the victim's identity,
read the victim's bindings and history, and start a wallet swap.

*Invariant broken:* #7 (a passkey is supposed to re-establish an identity Fayda
verified for *that person*; here it is enrolled onto an identity the attacker does
not own) and the premise that a Fayda session belongs to the person Fayda checked.

*Why the capture flow makes this worse rather than equal:* the persona picker
leaked a code for a fictional shared persona nobody owned. The capture page leaks
a code for a real person's real details, and it does so from a page designed to
look like a national-ID checkpoint — which is exactly what makes step 2 clickable.
The redirect also drops the victim on the attacker's origin immediately after a
screen that told them they were verified: a natural place to host a cloned capture
page that *does* upload the photo.

*The test that gives false comfort:* `backend/t.py:415-422` asserts only that
`https://evil.example.com/`**`phish`** is rejected. It varies the path, never the
host, so it passes with the hole wide open.

### High

#### H1 — A name and a date of birth are now the entire credential, and `/authorize/known` tells an unauthenticated attacker which pairs are live.

*Where:* `backend/mock_esignet.py:102-117` (`derive_sub`), `:623-654`
(`/authorize/known`), `:657-689` (`/authorize/confirm`), `backend/store.py:766-778`.

*Confidence: certain.* Driven.

`derive_sub` is `sha256(lower(collapse_ws(name)) + "|" + birthdate)` folded to 12
digits, with **no secret**. `/authorize/confirm` accepts those two strings from
anyone and mints a code. So possession of a name and a birthdate *is* possession
of the identity:

```
real user identity:      df25fa78-2c7b-4fda-9b24-e34bb3494551  "Squat Target"
POST /authorize/known {"full_name":"Squat Target","birthdate":"1992-12-01"} -> {"known": true}
POST /authorize/known {"full_name":"Squat Target","birthdate":"1992-12-02"} -> {"known": false}
POST /authorize/known {"full_name":"squat  target", ...}                    -> {"known": true}  (normalised)
attacker lands on identity: df25fa78-2c7b-4fda-9b24-e34bb3494551  same: True
attacker auth_method: fayda | POST /api/passkey/register/begin: 200
```

The attacker also got to *choose* the victim's session claims — they logged into
the victim's identity asserting `residenceStatus: FOREIGN_NATIONAL` and
`region: Tigray` where the real user had asserted `CITIZEN` / `Amhara`. The
citizenship signal `CAPTURE.md` wants surfaced is self-asserted per login and
attached to the session, not to the identity, so two sessions on one identity can
disagree about it.

`/authorize/known` is a clean oracle: unauthenticated, DB-backed, stable across
processes (the pepper is pinned in the deploy), and it lands in the `login` tier —
I measured **52 of 60** burst probes allowed against the production-posture
instance, then ~1/s sustained. Given a name, an 80-year DOB window is ~29,000
probes: about eight hours from one address, minutes from a spread of them. It also
confirms *registration*, which for this population is itself the sensitive bit
("did this person use the wallet registry").

The docstring's defence — *"it reveals only what someone who already knows an exact
name and date of birth could learn by starting a verification anyway"* — is true,
and is the problem: starting a verification anyway **logs you in as them**.

*Invariant broken:* #8 (a cross-identity read with no operator check and no
access-log entry) and, in spirit, #7.

*Not reachable against a real provider* — the router mounts only under `MOCK_IDP`,
and `app.py:145-164` still refuses to boot `DEMO_MODE` with any `FAYDA_*`
credential set; I verified `/api/dev/*` stays 404 in that posture. The blast radius
is the shipped public demo, its real Supabase database, and the real people who
type real details into it.

### Medium

#### M1 — Four digits of the FIN-shaped `sub` now reach the browser and are persisted in Postgres, through the `address` claim. Non-negotiable #1.

*Where:* `backend/mock_esignet.py:759-767` — `"kebele": sub[:2]`,
`"woreda": sub[2:4]`. `address` **is** in `SAFE_CLAIMS` (`app.py:549-551`), so it
survives the whitelist into `session["claims"]` and out of `/api/me`.

*Confidence: certain.* Read out of the live `sessions` table:

```
sub for "Squat Target" = 461697870520
stored session row: {"claims": {..., "address": {"zone":"Amhara","kebele":"46",
                     "region":"Amhara","woreda":"16"}, ...}}
```

`kebele` and `woreda` are exactly `sub[0:2]` and `sub[2:4]`. The old personas
carried fixed strings ("13"/"08") with no relationship to the FIN; this diff
derived them from it. Non-negotiable #1 is written without a percentage — "the raw
FIN is never persisted, logged, or sent to the browser" — and a third of it now is,
in the database and in the DOM. It also cuts the guessing space by 10^4.

Test 3b (`t.py:97`) cannot catch this: it substring-searches for the whole 12-digit
value. And this is the file CLAUDE.md calls "the only file to touch when real
credentials arrive", so the pattern is sitting in the template.

#### M2 — `identity_exists` is an unauthenticated cross-identity read on the privileged, RLS-bypassing connection.

*Where:* `backend/store.py:775` uses `conn()`, not `user_conn()`. Its only caller
is an HTTP route open to the world (`mock_esignet.py:651`).

CLAUDE.md #9 reserves `conn()` for "genuinely cross-identity work (the sybil check,
promotion, sessions, credential lookup at login)"; #8 requires an operator check
**and** an access-log entry before any cross-user read. This is a cross-user read,
by an anonymous caller, with neither. The mock is a throwaway, but it reaches the
production `identities` table through the owner role. It is also an unauthenticated
round trip on a 12-connection pool (`store.py:442`), i.e. a cheap way to hold
connections the app needs.

*Confidence: certain* on the mechanism; *likely* on the pool-pressure angle
mattering before the limiter bites.

#### M3 — `_codes` and `_tokens` are never pruned: unauthenticated memory exhaustion of the demo instance.

*Where:* `backend/mock_esignet.py:66-67`, `:682` (insert), `:719` (pop on
redemption only), `:724`.

An authorization code that is minted and never redeemed lives forever; nothing
sweeps on `exp`. `POST /authorize/confirm` is unauthenticated and needs five short
strings, so at the login tier's sustained 1/s an attacker adds ~86,000 dict entries
per day per source address — order 70 MB/day/IP against a 512 MB free Render
instance, faster from several addresses. Pre-existing in shape (the persona flow
had the same dicts), but untouched by a diff that rewrote the file around it.
`_tokens` leaks the same way but needs a valid client assertion, so only the RP
grows it.

*Confidence: certain* that nothing prunes; *likely* on the timeline.

#### M4 — "Already verified" is a dead end for anyone without a passkey, and the name space is squattable.

*Where:* `backend/mock_esignet.py:466-478` — `alreadyVerified()` writes the "sign
in with the passkey you registered" panel and then
`$("go1").classList.add("hidden")`. There is no other way forward in the UI.

Passkey registration is optional in the SPA (`App.jsx:146` — a button the user may
never press). A demo visitor who verifies, never adds a passkey, and comes back is
told they have already verified and handed a button that returns them to a passkey
prompt no authenticator can answer. Their only escape is to type a slightly
different name, which mints a *different* identity — and if they then try to bind
the wallet they already bound, the sybil index refuses them.

Worse, the check keys on name+DOB alone, so an attacker can pre-register a name
they do not own (H1's flow) and strand the real person on arrival. The server does
not enforce the routing at all — `/authorize/confirm` proceeds happily for a known
person — so the lockout is purely a UI decision, which is the wrong half to
enforce.

*Confidence: certain* on the dead end; *likely* on squatting mattering in practice.

#### M5 — The demo now collects real names and dates of birth from the public and stores them durably, with no retention story and an enumeration oracle over them.

`CAPTURE.md`'s data-protection reasoning covers images only. But
`identities.display_name` and `identities.birthdate` (`app.py:642-646`) and the
session claims (gender, region, residenceStatus, kebele/woreda) are written to a
real Supabase project that "survives redeploy/restart/scale" — from a page that
asks a member of the public for their legal name, date of birth and residence
status under a national-ID banner. The persona picker asked for none of that. Add
`/authorize/known` (H1) and the set of people who used the demo becomes confirmable
by anyone. A policy gap rather than a code bug, but much cheaper to fix before the
demo is shared than after.

*Confidence: certain* on the persistence; the severity judgement is mine.

### Low

- **L1 — `/authorize/confirm`'s 422 echoes `UploadFile` internals.** Send a file
  part where a text field is expected and the response body contains the attacker's
  `filename`, `size`, the content-type header, and `_max_size` /
  `_TemporaryFileArgs` from the spooled file. No image bytes (I checked), but it is
  an image-shaped object being reflected out of the endpoint the diff claims cannot
  reflect one, and test 58 would not notice if that ever became the content.
- **L2 — No body-size cap on either new/rewritten POST.** A 12 MB multipart part at
  `/authorize/confirm` is parsed, spooled (rolling to a temp file above 1 MB) and
  discarded — 303, no temp file left behind, nothing persisted, but the parse is
  free for the attacker. `/authorize/known` swallowed a 20 MB JSON body and answered
  200. Bounded only by the login tier.
- **L3 — `derive_sub` normalisation.** Case and whitespace are folded (verified),
  Unicode is not: NFC and NFD spellings of the same accented name produce different
  subs, so one person can end up with two identities. `birthdate` is unvalidated
  free text, so `1990-1-1` and `1990-01-01` are different people. And 64 bits folded
  into 10^12 means two different people can collide onto one identity row —
  irrelevant at demo scale (50% at ~1.2M identities), fatal if this shape were ever
  kept.
- **L4 — Test 58 is sound but under-tests its own claim.** It pushes image-ish
  values as *urlencoded* fields only, never a real multipart file part (I verified
  separately that the file-part path is also clean, so the conclusion holds — the
  test just does not establish it). `assert "face_image" not in page and "id_image"
  not in page` pins two arbitrary strings rather than the form's shape; a future
  `<input name="selfie_b64">` sails through. One of its three "response bodies" is
  `page`, fetched before the sentinel existed. The information_schema column sweep
  is genuinely good and worth keeping.
- **L5 — No CSP, `X-Frame-Options` or `Referrer-Policy` on the capture page**
  (checked the live headers: `content-type` only). The page is framable, and it
  `@import`s Google Fonts, so the "mock IdP" makes a third-party request from the
  deploy's real origin while telling the user nothing leaves their device.
- **L6 — The document object URL is never revoked.** `f_selfie` revokes (`:516`)
  but the ID document's URL does not, and `id_again` (`:539-544`) drops the
  reference without revoking, so each re-pick leaks a blob. The images stay resident
  longer than "discarded immediately" implies. Cosmetic against the real guarantee,
  which holds.

### Verified safe

Actively attacked and could not break:

- **No image byte can reach the server.** I parsed the page the server actually
  serves: exactly **one** form (`action=/authorize/confirm`, no enctype) with
  **eight hidden text inputs** and nothing else; the two `<input type=file>`
  elements sit **outside** it, carry **no `name`**, and have no `form=` attribute,
  so they are unsubmittable twice over. The page contains **no** `toDataURL`,
  `toBlob`, `getImageData`, `FormData`, `XMLHttpRequest`, `sendBeacon` or
  `WebSocket` — there is no API present capable of serialising the canvas or the
  File. The only `fetch` is `/authorize/known`, carrying a name and a date.
- **A hostile client cannot make the server keep one either.** Real multipart parts
  (`face.jpg`, 12 MB) posted alongside the text fields: 303, code minted, parts
  dropped, **no temp file left in the temp dir**, and the sentinel appears in no
  column of any table.
- **`picture` is a fixed placeholder** and is not in `SAFE_CLAIMS`; `/api/me`
  carries neither `picture` nor `phone`. `log_event`'s whitelist (`app.py:263-266`)
  admits no claim field, so nothing image-shaped can reach a structured log line.
- **Injection.** `"><script>alert(1)</script>` in `state`, `nonce` and `scope`: all
  escaped, zero live script. In the JS context, a `redirect_uri` containing
  `</script><script>` comes back as `<\/script><script>` inside a `json.dumps`
  string literal; `\` and `"` are escaped; U+2028 comes back as ` `
  (`ensure_ascii`). No brace/format bug — the page renders and the doubled braces in
  the inline JS are correct throughout.
- **No header injection.** `state` containing CRLF is percent-encoded by
  `RedirectResponse` (`state=a%0D%0AX-Injected:%201`); no extra header appeared.
- **Duplicate `code=` cannot be pre-seeded.** `redirect_uri=/callback?code=ATTACKER`
  produces `?code=ATTACKER&code=<real>`; Starlette's query parsing takes the
  **last**, so the genuine code wins (307, login succeeds). Not a code-substitution
  path.
- **The OIDC handoff is intact and mandatory.** Capture mints nothing but an
  authorization code; there is no new way to obtain a session. `code → token
  (private_key_jwt RS256, `iss`/`sub` checked against `client_id`) → userinfo` is
  still the only route, codes are single-use (`_codes.pop`) and 120-second bound,
  `/authorize/confirm` still re-validates `redirect_uri`, and `app.py`'s callback
  still checks `state`.
- **The double-import trap is genuinely fixed.** `mock_esignet.HASH_FIN = hash_fin`
  is injected at `app.py:527-535`; the only function-level import left in the mock
  is `import store as _store` (`:645`), which resolves to the module `app.py`
  already loaded under both `python app.py` and `uvicorn app:app` — no second copy,
  no regenerated keypair. `grep` confirms the only other function-level imports in
  the backend are `getpass`/`socket`/`sys` inside `store.py`'s CLI helpers. Token
  exchange still worked after repeated `/known` probes.
- **Gating.** The router mounts only under `MOCK_IDP = DEV_MODE or DEMO_MODE`
  (`app.py:516-517`); `mock_esignet` is imported only then (`:167-168`); the
  `DEMO_MODE`-with-real-credentials boot refusal (`:145-164`) is untouched. Against
  the production+`DEMO_MODE` instance I confirmed `/api/dev/reset` → **404** while
  the capture page and `/authorize/known` are live, which is the documented split.
- **`/authorize` and `/authorize/known` mint no session and set no cookie**, so
  neither grows the sessions table.
- **`/authorize/known` fails closed** on non-dict JSON, junk bodies, a 100 kB name,
  a dict or list where a string was expected, and (by construction) an unset
  `HASH_FIN` or a DB error — always `{"known": false}` or 400, never a stack trace.
- **No CORS middleware**, so the oracle is not usable from a victim's browser
  cross-origin; it is a server-side attack only.
- **Binding, nonce, sybil and cooling logic are untouched** by this diff; the only
  `store.py` change is a read-only existence check, and no schema, index, policy or
  RLS definition moved. `upsert_identity` does not overwrite `display_name` or
  `birthdate` on a returning login, so an impersonator cannot rewrite the victim's
  stored name.
- **Test 59 is not vacuous** — it asserts a real `known: true` / `known: false`
  pair, that the passkey path lands on the *same* `identity_id`, that `auth_method`
  is `passkey`, and that a token exchange still succeeds after a probe (the
  regression it was written for).

**Verdict: not safe to build on — no.** The image guarantee, the hard part and the
thing the spec cared most about, is genuinely met: I attacked it from the page,
from a hostile client and from the database and found nothing. But the new front
door is an identity takeover (C1, driven end to end in the shipped `DEMO_MODE`
posture) sitting beside an unauthenticated oracle that names the targets (H1), and
`render.yaml` publishes both to the public internet.

---

## Closing fix review — R6 round 4, 2026-07-27 (NEW-3, NEW-4 at ddd26d4)

**Scope:** two deltas only — `proxy_headers=False` / `--no-proxy-headers` on every
launch path, and `save_session(..., is_new=)` with `is_new=fresh` in the session
middleware. Plus tests 54 and 55.

**Method.** Three fresh uvicorn instances, all terminated: :8155 (unlimited),
:8156 (limited, `TRUST_PROXY_HEADERS=1`), and :8158 bound to `0.0.0.0` and
reached over the machine's LAN address — the last one because every previous
probe of the self-call exemption connected from loopback, where the exemption
legitimately applies and therefore proves nothing. A scratchpad ASGI probe
(outside the project tree) read `scope["client"]` as the real server builds it.
Both original attacks re-driven with the scripts that broke them. `t.py` not run
(test 32 resets the shared database). No project file modified.

**Status: NEW-3 RESOLVED, NEW-4 RESOLVED. 2 new findings, both low, both
test-coverage only.**

### NEW-3 — RESOLVED

uvicorn no longer rewrites the client address. With `--no-proxy-headers`,
`scope["client"]` is the socket peer whatever the header says, and the app's
right-counting sees the raw header for the first time:

```
XFF="198.51.100.90"          -> client='127.0.0.1'  peer_of='127.0.0.1'  key='198.51.100.90'
XFF="127.0.0.1"              -> client='127.0.0.1'  peer_of='127.0.0.1'  key='127.0.0.1'
XFF="::1"                    -> client='127.0.0.1'  peer_of='127.0.0.1'  key='::1'
XFF="127.0.0.1, 198.51.100.7"-> client='127.0.0.1'  peer_of='127.0.0.1'  key='198.51.100.7'
XFF=""                       -> client='127.0.0.1'  peer_of='127.0.0.1'  key='127.0.0.1'
```

Driven against a server whose socket peer is genuinely **not** loopback — bound
`0.0.0.0`, reached over the LAN address — the header no longer buys the
exemption:

```
80x /v1/esignet/oidc/userinfo, XFF=127.0.0.1  -> 429s: 40   (was 0/80)
80x /v1/esignet/oidc/userinfo, XFF=::1        -> 429s: 40
80x /login, rotating forged prefix, real client constant -> 429s: 26 (one bucket)
```

**Every launch path is covered.** `backend/app.py`'s `__main__`
(`proxy_headers=False`), `Dockerfile:33` CMD (`--no-proxy-headers`), and
`backend/t.py`'s `server()` helper. `render.yaml` is `runtime: docker` with
`dockerfilePath: ./Dockerfile` and no `startCommand` override, so production
goes through that CMD. README and CLAUDE.md only ever document
`python backend/app.py`, which is the covered `__main__` path; DEPLOY.md:29-30
now states the flag and why. The screenshots harness
(`frontend/scripts/screenshots.mjs`) starts no backend — it names the command in
a comment only. `grep -rn 'uvicorn'` across the repo finds no fourth invocation.

**Nothing depended on the value that was removed.** There is no `request.client`,
`request.url`, `base_url`, `url_for` or `.scheme` anywhere in `backend/` (the one
`.scheme` hit is `mock_esignet.py:117`, parsing a redirect_uri string, unrelated
to the ASGI scope). `PUBLIC`/`REDIRECT_URI`/`AUTHORIZE_URL` derive from
`PUBLIC_URL` or `RENDER_EXTERNAL_URL`, both environment variables. The `Secure`
cookie flag comes from `DEV_MODE`, not from `scope["scheme"]`, so losing
`X-Forwarded-Proto` handling changes nothing. The `access_log` schema records no
client address, so the audit trail is not degraded either. Confirmed live with
Render-shaped headers present (`X-Forwarded-Proto: https`,
`X-Forwarded-For: 198.51.100.240`): **3/3 complete OIDC logins on the
rate-limited instance**, so the loopback self-call exemption still recognises the
app's own token/userinfo calls, and `/` still refuses to echo `evil.example.com`
from `Host`/`X-Forwarded-Host`.

Test 55 discriminates: it drives a real server through `server()` and asserts 90
distinct forged header values share one bucket, which is false under the old
default.

### NEW-4 — RESOLVED

`fresh = sid is None` is evaluated immediately before
`sid = secrets.token_urlsafe(32)`, so `is_new=True` can only ever accompany a sid
minted microseconds earlier in the same block. A cookie-borne sid cannot reach
the INSERT branch structurally, not by convention — there is no ordering of
events that makes `fresh` true while `sid` still holds a value that arrived in a
cookie.

The parked-request attack, re-driven end to end:

```
request parked mid-body (session already loaded)
logout -> tombstone -> sweep reclaimed it: True
parked request completed with 200; sent a clearing cookie: True
row for the revoked sid recreated: False        (was True)
revoked cookie authenticates: False   /api/wallet/nonce -> 401   (was True / 200)
```

The full lifecycle battery is clean:

* **Rotation** — sid rotates, the old row is tombstoned, the new row is created,
  three further logins on the same client all succeed.
* **`/login` on a revoked sid** and **on a swept sid** — both 307, the old sid's
  row is never recreated, a new sid is minted, and the user can still sign in.
* **A session-writing request on a vanished sid** — old row not recreated, a new
  sid minted instead.
* **Three concurrent anonymous mints** — three distinct sids, three rows, no
  collision.
* **Two revocations racing** (re-checked from round 3) — one tombstone, and the
  `AND revoked_at IS NULL` predicate makes the loser a no-op.

The one remaining way to create a row is a freshly minted 256-bit sid. `__rotate__`
reaches the INSERT branch only after setting `sid = None` and minting a new one,
and both handlers that set it (`/callback`, `passkey_login_complete`) overwrite
`identity_id` from a fresh authentication — so a rotation cannot carry a revoked
session's authority into the new row.

---

### NEW-6 — Low. The production launch flag is the one nothing asserts. (`backend/t.py:36-41`) — **certain**

Test 55 boots its server through `t.py`'s own `server()` helper, which carries
`--no-proxy-headers`. Delete the flag from `Dockerfile:33` or `proxy_headers=False`
from `app.py`'s `__main__` and the entire suite still passes: the test pins the
harness, not the two invocations that actually run in production and in local
dev. Given that this fix exists precisely because a default-on middleware was
invisible, the assertion worth having is a textual one over the Dockerfile CMD
and the `uvicorn.run(...)` call, in the style of the existing deploy-config
checks.

### NEW-7 — Low. Test 54 pins `save_session`'s contract but not the middleware's use of it. (`backend/t.py`, step 54) — **certain**

Test 54 is a store-level unit test: mint-inserts, update-updates, tombstone
refuses, swept row refuses. All correct, and it fails against the old code. But
nothing asserts that the middleware passes `is_new=fresh` rather than
`is_new=True`; a future edit could reopen NEW-4 with test 54 still green. Tests
49 and 52 cover the tombstone path end to end, so only the swept-row path — the
one that needed a parked request to find — is unit-only. The HTTP-level version
is not hard: park a request mid-body, revoke, delete the row, finish the body,
assert the cookie is dead.

---

### Verified safe / residual

* **The `TRUST_PROXY_HEADERS` trust model itself.** With the flag set, whoever can
  write the *last* `X-Forwarded-For` entry gets their own bucket — measured, 60
  requests with 60 distinct trusted-hop values drew 0 refusals. That is the
  design, not a defect: the last entry is by definition the trusted proxy's
  observation. It is safe on Render because the service is reachable only through
  that proxy, and it would be a total bypass on any deployment that sets the flag
  while remaining directly reachable. DEPLOY.md warns about hop counts; this is
  the assumption underneath them.
* **Out of scope, noted:** the working tree carries uncommitted R7 work — a test
  56 (`PUBLIC_URL` origin derivation) in `t.py` and DEPLOY.md edits. Not reviewed
  here; this review covers ddd26d4.

---

**Closing verdict: yes — safe to build on.** Both remaining highs are closed, and
closed structurally rather than patched: `scope["client"]` is a socket fact again
with one owner for the forwarded-header decision, and the INSERT branch is
reachable only by a sid the middleware just minted. Each was re-verified by
re-running the attack that broke it, with a non-loopback peer for the one that
needed it, and neither fix costs anything elsewhere — self-calls, origin
derivation, the audit trail and the whole session lifecycle are unaffected. The
two residual findings are test coverage, not running behaviour: nothing asserts
the production launch flag, and the swept-row property is unit-tested rather than
driven over HTTP.

---


---

## Fix review — R6 round 3, 2026-07-27 (NEW-1, NEW-2 and the named lows)

**Scope:** the tombstoning of `delete_sessions_for_credential`, `REVOKED_GRACE_MINUTES`,
the joined-header `client_key`, the peer-based self-call exemption
(`check(..., peer=)` + `peer_of`), the `elif not written` cookie branch, the
`/api/passkey/revoke` tier entry, and tests 52/53 plus the tightened 46/51.

**Method.** Fresh uvicorn on :8145 (unlimited) and :8146 (limited,
`TRUST_PROXY_HEADERS=1`), both terminated. Each previous finding re-driven with
the script that broke it. Header parsing exercised across 18 shapes. One
scratchpad ASGI probe (outside the project tree) to read `scope["client"]` as
the real server builds it. `t.py` not run (test 32 resets the shared database).
No project file modified.

**Status: NEW-1 RESOLVED, NEW-2 PARTIAL (logic correct, input is not), all five
named lows RESOLVED. 2 new findings, both high.**

| # | Finding | Status |
|---|---|---|
| NEW-1 | passkey revocation resurrectable | **RESOLVED** |
| NEW-2a | duplicate/multi-value XFF chose the bucket | **RESOLVED** |
| NEW-2b | spoofed loopback bought the exemption | **PARTIAL** — logic fixed, see NEW-3 |
| low | tombstones parked 12 h | **RESOLVED** — but see NEW-4 |
| low | `save_session` bool discarded | **RESOLVED** |
| low | `/api/passkey/revoke` in `read` tier | **RESOLVED** (`bind`) |
| low | test 46 eviction bound unfailable | **RESOLVED** (0.6 s) |
| low | test 51 one-word sweep check vacuous | **RESOLVED** |

### NEW-1 — RESOLVED

`delete_sessions_for_credential` now tombstones with the same UPDATE as logout.
The attack that defeated revocation 5/5 now loses every round:

```
attempt 0..4: authed=False  nonce=401  tombstoned=True  reclaim_in=10.0min
=> passkey revocation defeated: 0/5
```

`grep 'DELETE FROM sessions'` leaves exactly two sites, neither a kill path:
`load_session`'s lazy cleanup of an already-expired row (which returns `None`
regardless) and the TTL sweep. Two revocations racing the same row
(`/logout` and `delete_sessions_for_credential` on a barrier) produce one
tombstone and one dead session — the `AND revoked_at IS NULL` predicate makes
the loser a no-op. Rotation, the swept-sid path and the `_expiry_due` renewal
were re-checked from the previous round and still hold. Test 52 drives a real
`SoftAuthenticator` registration and sign-in, so it tests the code and not a
mock, and would fail against the previous cut.

### NEW-2a — RESOLVED

`client_key` joins every `x-forwarded-for` header before counting from the
right. Eighteen shapes, peer `203.0.113.9`, one trusted hop — the attacker's
prefix never wins, and every malformed proxy entry falls back to the peer (the
visible-but-safe direction), never to a caller value:

```
duplicate: attacker first, proxy second  -> '198.51.100.7'
attacker multi-value + proxy header      -> '198.51.100.7'
three headers                            -> '198.51.100.7'
attacker claims loopback first           -> '198.51.100.7'
attacker trailing comma / only commas    -> '198.51.100.7'
whitespace soup / empty header + proxy   -> '198.51.100.7'
IPv6 proxy entry                         -> '2001:db8::1'
IPv6-with-port / IPv4-with-port          -> peer   (unparseable, falls back)
>64-char entry / '_hidden' (RFC 7239)    -> peer
empty-only / commas-only / no header     -> peer
```

`TRUSTED_HOPS` cannot be walked left by any of them: the trusted proxy always
appends last, so `parts[-1]` is its observation whatever precedes it.

### NEW-2b — PARTIAL

The logic is right. Exercised in isolation, the exemption follows the peer and
not the key:

```
peer=127.0.0.1      key=198.51.100.90  -> allowed 200/200  (exempt)
peer=198.51.100.90  key=127.0.0.1      -> allowed  40/200  (spoof refused)
```

But the value the middleware hands it is not the socket peer — see **NEW-3**.
The self-call exemption is otherwise sound: on the limited instance three
complete OIDC logins succeeded (3/3), so the token/userinfo self-calls are not
throttled, and a loopback peer on a non-`/v1/` path is still limited
(`90x /login -> 33 refusals`).

### The named lows — all RESOLVED

* Tombstones now carry `expires_at = now + 10 min` (measured `reclaim_in=10.0min`
  on every revocation) instead of parking for the original 12 h. **This fix is
  also the cause of NEW-4.**
* `elif not written` is correct and cannot misfire: `written` is only ever
  assigned from `save_session`, which returns `False` only when
  `revoked_at IS NOT NULL`. Six plain reads plus a forced renewal write on a
  healthy session emitted no clearing cookie and left it authenticated.
* `/api/passkey/revoke` now resolves to the `bind` tier.
* Test 46's bound is now `< 0.6 s`; the replaced `min()` implementation needed
  ~1.5 s for the same loop, so the assertion can now fail against the regression
  it guards.
* Test 51 screens `"Someone"` against `"Someone Else Entirely"` — names that
  share a token — so the one-word sweep check can now fail.

---

### NEW-3 — High. `peer_of` is not the socket peer: uvicorn has already rewritten `scope["client"]` from `X-Forwarded-For`, so a header still buys the self-call exemption — and, with `TRUST_PROXY_HEADERS` unset, still chooses the bucket. (`backend/ratelimit.py` `peer_of`; `Dockerfile:28`) — **certain** for the code, **likely** for reachability

`peer_of`'s docstring says "The socket peer — never caller-influenced, whatever
the headers say." It reads `scope["client"]`, which is not a socket-level fact.
uvicorn 0.51 enables `ProxyHeadersMiddleware` by default
(`proxy_headers=True`, `forwarded_allow_ips` resolving to `"127.0.0.1"`); when
the connecting peer is trusted it joins every `x-forwarded-for` value and
**overwrites `scope["client"]`** before any application middleware runs. A
scratchpad ASGI probe wrapping the real functions, served by the same uvicorn
invocation the project uses:

```
XFF="198.51.100.90"  -> client='198.51.100.90'  peer_of='198.51.100.90'  self_call=False
XFF="127.0.0.1"      -> client='127.0.0.1'      peer_of='127.0.0.1'      self_call=True
XFF="::1"            -> client='::1'            peer_of='::1'            self_call=True
XFF=""               -> client='127.0.0.1'      peer_of='127.0.0.1'      self_call=True
```

End to end against the limited instance, one header line apart:

```
80x /v1/esignet/oidc/userinfo, XFF=198.51.100.99 -> 429s: 40   (limited)
80x /v1/esignet/oidc/userinfo, XFF=127.0.0.1     -> 429s:  0   (exempt)
90x /login,                    XFF=127.0.0.1     -> 429s: 33   (still limited)
```

Zero refusals in eighty. The exemption the fix moved onto the peer specifically
to stop this is bought by writing `127.0.0.1` into a header.

The second half is worse in principle: when `TRUST_PROXY_HEADERS` is **unset** —
the documented default, "*(leave unset)*" — `client_key` skips its careful
right-counting entirely and returns `peer_of(scope)`. If uvicorn has rewritten
that value, the bucket key is caller-chosen again. That is the original H2
bypass, reinstated in the configuration chosen to avoid it, and it bypasses
`TRUSTED_PROXY_HOPS` because the app's parser never runs.

**Reachability.** Not the shipped Render topology: the Dockerfile binds
`0.0.0.0` and Render's proxy connects from a non-loopback address, so uvicorn
does not trust it and leaves `client` alone. It **is** live in local dev
(`uvicorn --host 127.0.0.1`) and in any deployment fronted by a same-host
reverse proxy — nginx, Caddy, Apache on 127.0.0.1 — which is the ordinary
self-hosting shape and exactly the topology `TRUST_PROXY_HEADERS` exists for.
Exploitability there depends on the local proxy's own XFF policy: if it passes
the client's header through (nginx adds no `X-Forwarded-For` unless configured
to), the caller owns `scope["client"]` outright.

The underlying defect is structural: there are now **two** `X-Forwarded-For`
parsers in the stack with different trust models — uvicorn's (trusts loopback
peers, walks right skipping trusted hosts) and the app's
(`TRUST_PROXY_HEADERS` + a fixed hop count) — and the app's runs on a value the
other has already rewritten. Every comment in `ratelimit.py` describes a
single-owner decision the process does not actually make. Starting with
`proxy_headers=False` (`--no-proxy-headers`) makes `scope["client"]` the socket
peer again and leaves the app the only parser, which is what the code already
believes.

Test 53 passes `peer="203.0.113.9"` explicitly, so it asserts `check`'s logic
and can never observe what `scope["client"]` actually contains. Nothing in
46–53 exercises the composed server.

### NEW-4 — High. Pulling the tombstone in to 10 minutes reopened resurrection: a parked request outlives the sweep and `save_session` takes its INSERT branch. (`backend/store.py` `REVOKED_GRACE_MINUTES`, `save_session`; `backend/app.py` session middleware) — **certain**

`save_session` refuses to overwrite a **tombstoned** row. It has nothing to say
about a **missing** one — no row means no conflict, so the INSERT branch runs
and the session is recreated with `revoked_at = NULL` and a fresh 12-hour TTL.
The sweep now removes the tombstone after ten minutes, so the attacker only has
to outlast ten minutes rather than the twelve hours the previous cut left.

The session is loaded by the middleware when the request headers arrive; the
body is read later, downstream. So a request parked mid-body holds a
pre-revocation snapshot for as long as the attacker likes — uvicorn applies no
request-body timeout by default. Driven end to end:

```
request parked mid-body (session already loaded, response not started)
logout -> tombstoned: True
sweep reclaimed the tombstone (as it does at +10min): True
parked request completed with 200
row for the revoked sid RECREATED: True  identity_id=True  expires=2026-07-28T05:36
revoked cookie authenticates again: True   /api/wallet/nonce -> 200
```

No race timing is involved — the attacker sends headers plus one byte, waits,
and finishes. The recreated row carries **no tombstone**, so logout and passkey
revocation are both defeated again and the owner is back to having no lever.
The precondition is only that `save_session` be called on the response path,
which `_expiry_due` guarantees for any session older than an hour — the normal
state of a session worth stealing.

The fix that closed the parking problem and the fix that closed resurrection are
in tension because both are expressed as row lifetime. They separate cleanly if
the middleware distinguishes the two cases it already knows apart: a sid it
minted this request (`fresh`) may INSERT; a sid that arrived in a cookie may
only UPDATE an existing, unrevoked row. Then no sweep timing can matter.

### NEW-5 — Low

Test 53's exemption assertion supplies `peer` directly, and tests 46–53 build
their scopes by hand, so no test in the suite observes the ASGI scope as the
production server actually composes it. That is the gap NEW-3 lives in; a single
end-to-end assertion (a spoofed loopback header against a limited instance must
still be refused on `/v1/`) would close it.

---

**Fix-review verdict: no — one more round, and it is the same root cause both
times.** NEW-1 is properly dead: no kill path hard-DELETEs, racing revocations
converge on one tombstone, and test 52 exercises a real passkey. NEW-2a is
comprehensively fixed across every header shape I could construct. But the two
remaining highs are both "the guard is correct, the input to it is not" — the
exemption trusts a `scope["client"]` that uvicorn rewrote from a header, and
`save_session` trusts a row's absence as evidence that the sid is new. Both are
small: start uvicorn with `--no-proxy-headers`, and let only a freshly minted
sid take the INSERT branch.


---

## Audit - 2026-07-27 — R6 production hardening (uncommitted working tree vs 7f0a748)

**Scope:** the uncommitted diff only — `backend/app.py` (+167/-15), `backend/store.py`
(+45/-6), `backend/t.py` (+219), CLAUDE.md, DEPLOY.md, render.yaml, plus the two
new untracked files `backend/ratelimit.py` (129 lines) and `backend/screening.py`
(126 lines).

**Method.** Two throwaway uvicorn instances of the current tree on ports 8123/8125/8126
(rate limiting on, off, and on-with-`TRUST_PROXY_HEADERS=1`), all terminated. Raw
sockets for path-normalisation probes so no client library could normalise the request
line for me. Barrier-synchronised 3-thread races for the logout work (6 attempts each,
modest concurrency). Direct `store.conn()` reads of the `sessions` table to observe
rows rather than infer them. `t.py` was **not** run — its test 32 calls `store.reset()`
and would have wiped the database the dev server on :8000 is using. No code modified.

**Counts: 0 critical / 2 high / 6 medium / 13 low.**

Both highs are the same failure: a control whose *documented* mechanism is not the
mechanism actually doing the work. `__killed__` cannot reach the request it was written
to stop, and the rate-limit key is chosen by the caller in the one deployment config
that ships. Everything R6 claims about tiers, middleware order, path normalisation,
the log whitelist and the nonce binding held up under attack.

---

## Re-audit of the R6 fixes — 2026-07-27 (same working tree, after the fix delta)

**Scope:** the fix delta only — `sessions.revoked_at` + tombstoning
`delete_session` + conditional `save_session` + synchronous revoke in `/logout`
(`scope["session_sid"]`), `client_key` counting X-Forwarded-For from the right,
the login-tier retune, the `OrderedDict` LRU, sampled refusal logging, the
`SUPABASE_CA_CERT` startup raise, bidirectional subset screening, the narrowed
`/v1/` self-call exemption, and the rewrites of tests 46/49/51.

**Method.** Two fresh uvicorn instances (:8135 unlimited, :8136 limited with
`TRUST_PROXY_HEADERS=1`), both terminated. Every original finding was re-driven
with the *same* attack script that broke it the first time, not a new one. Raw
sockets for header-shape probes. `t.py` was again not run (test 32 resets the
database the :8000 dev server uses). No code modified.

**Status: 7 of 8 RESOLVED, 1 PARTIAL. 2 new findings (2 high). Counts after
re-audit: 0 critical / 3 high / 0 medium / 17 low.**

| # | Finding | Status |
|---|---|---|
| H1 | `/logout` resurrection | **RESOLVED** |
| H2 | attacker-chosen limiter key | **PARTIAL** — see NEW-2 |
| M1 | shared-NAT login lockout | **RESOLVED** |
| M2 | O(n) eviction under the lock | **RESOLVED** |
| M3 | refusal log flood | **RESOLVED** |
| M4 | silent TLS downgrade | **RESOLVED** |
| M5 | screening false-clean | **RESOLVED** |
| M6 | self-throttled OIDC token exchange | **RESOLVED** |

### H1 — RESOLVED

The tombstone now lives in the row (`sessions.revoked_at`), `delete_session` is an
UPDATE rather than a DELETE so the sid cannot be INSERTed back, `save_session`'s
`ON CONFLICT … WHERE sessions.revoked_at IS NULL` refuses to write over it, and
`/logout` revokes synchronously in the handler off `scope["session_sid"]` rather
than trusting the response path. The same attack that won 5 times in 6 now loses
every time — attacker polling `/api/passkey/login/begin` with the stolen cookie
across the logout and for 0.6 s after:

```
attempt 0..5: authed=False  nonce_status=401  revoked=yes
=> stolen cookie survived logout: 0/6
```

Checked separately, all clean:

* **The `_expiry_due` variant.** A session aged past `SESSION_RENEW_SECONDS` and
  then logged out stays dead; the renewal write is refused by the WHERE clause
  (`aged+revoked: authed=False, still tombstoned=True`).
* **Rotation.** `__rotate__` tombstones the old sid, the new row is written clean
  (`revoked_at=None`, no `__killed__`, keys exactly
  `__renewed__/auth_at/auth_method/claims/identity_id`), the old row's `data` is
  emptied to `{}`, and three consecutive logins on the same client all succeed.
  The tombstone does not leak into the new session.
* **Reuse after the sweep.** With the tombstone row deleted outright (simulating
  the TTL sweep), replaying the old cookie authenticates `False` and a
  session-writing request on that sid mints a **fresh** sid rather than
  recreating the old row — `load_session` returning `None` forces `sid = None` in
  the middleware, so a client can never steer a write back onto a dead sid.
* **The handler-to-response window.** The double revoke (handler, then the
  middleware's `elif sid is not None` branch) is idempotent: the UPDATE's
  `AND revoked_at IS NULL` makes the second a no-op.

Test 49 is now a real test — it reproduces the winning attack (separate client,
stolen cookie, session-*writing* endpoint, kept running past the logout) and
asserts against both `/api/me` and `/api/wallet/nonce`. It would have failed
against the previous code.

### H2 — PARTIAL

The left-to-right change itself is correct, and correct **for Render
specifically**: `TRUSTED_PROXY_HOPS=1` takes `parts[-1]`, which is the true
client whether the fronting proxy appends to a caller-supplied header
(`1.2.3.4, <client>` → `<client>`) or replaces it wholesale (`<client>` →
`<client>`). Both cases give the same answer, so the documented Render
assumption is safe in either direction. Verified over HTTP on :8136 — 60
requests with a rotating forged prefix and a constant real client all landed in
**one** bucket (`429s: 1, first at 59`, exactly the single-bucket refill curve),
where the old code allowed 60/60. Junk and empty headers fall back to the socket
peer as intended.

It is PARTIAL because the caller can still choose the key by two other routes,
both of which also hand over the `/v1/` self-call exemption — see **NEW-2**.

### M1 — RESOLVED

`login` retuned to `1.0/s burst 40`. Nine consecutive visitors sharing one NAT
address each completed a full four-token sign-in:

```
visitor 0..8: [307, 200, 303, 307] authed=True
=> 9/9 signed in behind one address (previously the 5th was refused at /login)
```

### M2 — RESOLVED

`OrderedDict` with `popitem(last=False)` and pop/re-insert on every touch.
Measured: 22 000 distinct keys in **0.016 s (0.7 µs/call)**, table capped at
20 000; 5 000 further inserts against a full table also 0.7 µs/call, against
~770 µs before. The event loop is no longer blocked and the ~1 300 req/s
process-wide ceiling is gone. LRU semantics are correct — a continuously-touched
key survived 5 000 evictions (`True`), so an attacker cannot flush a specific
victim's bucket by keeping it "at the front"; touching a key is what protects it,
and only the attacker's own keys age out. The added
`and bucket_key not in _BUCKETS` guard correctly stops an existing caller from
evicting a stranger on every request.

### M3 — RESOLVED

Sampled 1 in 50, and the sample carries `count` so the true volume is still
legible. Over the ~300 refusals driven in this session the server emitted **two**
lines: `"count": 1` and `"count": 51`.

### M4 — RESOLVED

```
$ SUPABASE_CA_CERT=/nonexistent/ca.crt python -c "import store; store._conninfo()"
RuntimeError: refusing to start: SUPABASE_CA_CERT points at '/nonexistent/ca.crt',
which is not a readable file...
```

Set-but-unreadable is now a startup failure rather than a silent fall back to
unauthenticated TLS.

### M5 — RESOLVED

Subset in either direction. The false-clean is gone and the feared noise did not
materialise:

```
'Tesfaye Bekele'        -> [('Tesfaye Bekele','exact')]
'Tesfaye Bekele Alemu'  -> [('Tesfaye Bekele','partial')]     <- was []
'Abebe Kebede'          -> [('Abebe Kebede Tesfaye','partial')]
'Hiwot Girma'           -> []                                  <- still clean
'Ali Mohammed Hassan' vs a 2 000-entry list with one 1-token entry -> 1 match
```

A one-token list entry adds exactly one match rather than sweeping, and the cap
of 25 still holds.

### M6 — RESOLVED

`BASE` defaults to `http://127.0.0.1:${PORT}` and `render.yaml` does not set
`BASE_URL`, so on Render the token/userinfo self-calls are genuinely loopback and
hit the exemption. The exemption is narrow on both axes (`_is_self_call` requires
loopback **and** the `/v1/` prefix), and `/v1/` is now in the route table at the
`login` tier, so a remote caller is limited — confirmed on :8136: an honest
single-header client hitting `/v1/esignet/oidc/userinfo` was refused 30 times in
70. Test 46 asserts both axes independently and both assertions can fail.

---

### NEW — High

#### NEW-1. The *other* session-kill path was not fixed: passkey revocation still hard-DELETEs, so an in-flight write resurrects the revoked session. (`backend/store.py:790-805` `delete_sessions_for_credential`; `backend/app.py:797-819`) — **certain**

`save_session`'s new guard only refuses to overwrite a **tombstoned** row. A row
that has been DELETEd carries no tombstone, so the INSERT branch takes the
conflict-free path and succeeds. `delete_sessions_for_credential` — the only
thing `/api/passkey/revoke` uses to end the attacker's session — is still a hard
`DELETE`:

```
delete_sessions_for_credential -> 1 row(s) removed
row after revoke: GONE (hard DELETE, no tombstone)
concurrent save_session returned True; load_session -> RESURRECTED, identity_id=d15c5846
--- contrast, same row via the logout path ---
after delete_session (tombstone): save_session returned False; load_session -> None
```

Over HTTP, with the attacker holding a passkey-established session and polling
`/api/passkey/login/begin` while the owner revokes the credential:

```
attempt 0..4: revoked session still authed=True  can_start_a_bind=True
=> passkey revocation defeated: 5/5
```

The resurrected row carries a fresh 12-hour TTL and **no tombstone**, so the
attacker can keep re-winning the same race indefinitely; the owner has no
remaining lever, because revoking the credential a second time only repeats the
DELETE. `can_start_a_bind=True` means the resurrected session can reach
`/api/wallet/nonce` — the binding surface, not just a read.

This is the exact failure H1 was fixed for, on the path whose own docstring says
"Revocation that only blocks the NEXT sign-in is not an escape hatch … leaving
that session alive for the rest of its 12h TTL would make revocation a
formality." It is the *more* attacker-relevant of the two, because the session
being killed is by construction the attacker's, and the attacker is the party
with a reason to be polling. Nothing in tests 46-51 covers it; test 49 tests only
`/logout`.

Same shape, unaudited: any future kill path that DELETEs rather than tombstones.
The invariant now belongs in `save_session`'s contract, not in each caller.

#### NEW-2. `client_key` still lets the caller choose the bucket — via a duplicated `X-Forwarded-For` header, or via a `TRUSTED_PROXY_HOPS` over-count that DEPLOY.md explicitly invites — and either one also grants the loopback self-call exemption to a remote caller. (`backend/ratelimit.py:139-160`; `DEPLOY.md:127-134`) — **certain** for the code path, **likely** for reachability

Two independent triggers, both restoring the full H2 bypass.

**(a) Duplicated header.** RFC 7230 §3.2.2 makes repeated field-names
semantically one comma-joined list. `client_key` iterates `scope["headers"]`,
takes the **first** `x-forwarded-for` and `break`s — so if the fronting proxy
emits its own header instead of appending to the caller's, position 0 of the
first header is again whatever the caller sent:

```
attacker header first, proxy header second -> '9.9.9.9'        (proxy said 198.51.100.7)
single joined header                       -> '198.51.100.7'   (correct)
attacker claims loopback, proxy appends    -> '127.0.0.1'
```

uvicorn preserves both headers separately in the scope, so this is reachable end
to end. Demonstrated on :8136 against the self-call surface:

```
70x /v1/esignet/oidc/userinfo, first header claims 127.0.0.1 -> 429s: 0
70x /v1/esignet/oidc/userinfo, honest single header          -> 429s: 30
```

Zero refusals in seventy — not merely a fresh bucket per request but **complete
exemption**, because `_is_self_call` believes the caller is loopback.

**(b) Hop over-count.** With one appending proxy and `TRUSTED_PROXY_HOPS=2`,
`parts[-2]` is the attacker's last forged entry:

```
hops=2, XFF '1.2.3.4, 198.51.100.7'   -> key '1.2.3.4'
        XFF '5.5.5.5, 198.51.100.7'   -> key '5.5.5.5'      (fresh bucket per request)
        XFF '127.0.0.1, 198.51.100.7' -> key '127.0.0.1'
        -> _is_self_call('/v1/…') == True
```

DEPLOY.md:134 tells the operator, when the hop count looks wrong, to "raise or
lower `TRUSTED_PROXY_HOPS` by one" — presenting the two directions as
symmetric. They are not. Lowering costs availability (everyone shares a bucket,
loudly). Raising silently hands the key, and the exemption, to the caller. The
guidance points at the dangerous direction half the time and the observable
symptom it describes (everyone refused together) is the symptom of the *safe*
direction, so an operator debugging that symptom will raise the value.

Both are cheap to close: join every `x-forwarded-for` value before splitting, and
clamp the candidate so the exemption can never come from a forwarded header at
all (require the socket peer to be loopback for `_is_self_call`, not the derived
key). Test 46 builds its probe scope with a single header and never varies the
hop count, so neither trigger is covered.

---

### NEW — Low

* **NEW-L1.** Test 46's O(1) assertion cannot fail against the implementation it
  guards. `assert evict_elapsed < 10.0` for `_MAX_BUCKETS + 2000` keys; the
  replaced `min()` code costs 0.749 ms per new key at 20 000 entries, so the old
  implementation completes the same loop in **~1.51 s** — six times inside the
  threshold. Measured. A threshold near 0.5 s, or a per-call assertion, would
  actually pin the property.
* **NEW-L2.** Test 51's "a one-word name must not sweep the list" assertion is
  vacuous: it screens `"Tesfaye"` and asserts `"Someone Else Entirely"` is absent,
  but those two share no token, so no subset rule in any direction could ever
  match them. To fail, the control entry would have to share a token with the
  one-word query.
* **NEW-L3.** `delete_session` tombstones without shortening `expires_at`, so a
  logged-out session's row now occupies the table for the remainder of its
  original TTL — up to 12 hours — where it used to be freed at once. Observed: 28
  of 188 rows tombstoned after this session's testing. The asymptotic bound
  (arrival rate × TTL) is unchanged and the sweep still reclaims them, but on the
  one table CLAUDE.md flags as attacker-growable the constant got worse for no
  benefit; `revoked_at = now, expires_at = now` would let the next ten-minute
  sweep take it.
* **NEW-L4.** `save_session` now returns whether it wrote and the middleware
  discards the result, so a refused write is silent — no log, no metric. In the
  same branch the middleware still appends `Set-Cookie` for a sid it just failed
  to persist, handing the browser a cookie for a dead session. Harmless today
  (`load_session` returns `None` for it, verified) but it means the one signal
  that a resurrection attempt was blocked is thrown away.
* **NEW-L5.** `/api/passkey/revoke` remains in the loosest `read` tier
  (10/s, burst 120) — unchanged from the first run's L1, but now more pointed:
  NEW-1 makes it the security-critical escape hatch, and it is the one
  passkey route the tier table does not name.

Still open from the first pass, unchanged by this delta: L2 (cookie `Max-Age` no
longer slides while the row does), L3 (`SESSION_RENEW_SECONDS` > pre-auth TTL),
L7 and L8 (test 51's `scr.LIST_PATH = ""` mutates the test process, not the
server, so the endpoint's `not_configured` path is still unasserted over HTTP;
`prod_dir if False else …` is still dead code), L9 (`RATE_LIMIT=off` silent in
production), L10 (tests 1-45 still run unlimited).

---

**Re-audit verdict: no — one more round.** The R6 fixes are real and hold up:
`/logout` is genuinely un-resurrectable across rotation, the sweep, the hourly
renewal and every session-writing endpoint I could reach, and six of the seven
other findings are closed with margin. But the same bug survives one door over —
passkey revocation, the escape hatch, is defeated 5 times in 5 because it DELETEs
where logout now tombstones — and the limiter key is still caller-choosable
through a duplicated header or the hop count DEPLOY.md tells operators to raise.
Both are small: make every kill path tombstone, and derive the self-call
exemption from the socket peer rather than the forwarded key.


---

### Critical

None.

---

### High

#### H1. `/logout` does not reliably end the session. M7's tombstone cannot reach the request it was written to stop. (`backend/app.py:379-380`, `:395-399`, `:621`; `backend/store.py:773-782`) — **certain** — **RESOLVED (re-audit 2026-07-27)**

`__killed__` is written into `request.session` — the dict belonging to the *logout*
request. The concurrent request that M7 exists to defeat holds a **different dict**,
deserialised independently by `store.load_session` at its own request start. Nothing
the logout request pops from its own dict is ever observable by that other request. The
tombstone is therefore functionally identical to the `request.session.clear()` it
replaced: both make `if session:` false and both fall to `store.delete_session(sid)`.
It fixes nothing.

What actually suppresses most resurrections is M6's change detection (`:395`) — and
that fails open in two ways:

* **any concurrent request that writes to the session** sets `changed = True` and
  unconditionally re-saves its stale snapshot;
* **any concurrent request on a session whose `__renewed__` is older than
  `SESSION_RENEW_SECONDS`** (once per hour per session) takes the `_expiry_due` branch
  and re-saves for the same reason.

`save_session` is `INSERT … ON CONFLICT(sid) DO UPDATE` (`store.py:778`), so the re-save
re-creates the row logout just deleted, **with `expires_at` reset to a full 12 hours**.

Concrete attack, measured on a fresh instance of this tree:

1. Attacker holds a stolen session cookie (the exact premise CLAUDE.md names: "an
   attacker with a live session"; logout is the user's remedy).
2. Attacker loops `POST /api/passkey/login/begin` with the stolen cookie. It is
   unprivileged, it is reachable to any session, and it writes `passkey_challenge`
   into the session — so every one of its responses re-saves.
3. Victim clicks Sign out.

Result over 6 barrier-synchronised trials: **the stolen cookie still authenticated in
5 of 6**, with the row's `expires_at` pushed to now + 12 h each time:

```
attempt 0: stolen cookie still authenticated=True  row_expires=2026-07-28T04:15:51
attempt 1: stolen cookie still authenticated=True  row_expires=2026-07-28T04:15:58
attempt 2: stolen cookie still authenticated=False row_expires=gone
attempt 3: stolen cookie still authenticated=True  row_expires=2026-07-28T04:16:09
attempt 4: stolen cookie still authenticated=True  row_expires=2026-07-28T04:16:16
attempt 5: stolen cookie still authenticated=True  row_expires=2026-07-28T04:16:22
STOLEN COOKIE SURVIVES VICTIM'S LOGOUT: 5/6
```

The `_expiry_due` variant needs no attacker at all — two ordinary tabs, one polling
`/api/me`, on a session last renewed over an hour ago, resurrected the row in **3 of 6**
trials (`row=PRESENT, identity_id_in_row=True, replayed_cookie_authenticated=True`).

The victim gets a cleared cookie and a signed-out UI, so the failure is invisible to
them. The attacker can hold it open indefinitely; each resurrection buys another 12 h.

**Invariant broken:** the session-compromise remedy CLAUDE.md builds the cooling period
around — "Signing out is the user's means of ending a session they may believe is
compromised; it must not be undone by their own overlapping request" (the code's own
comment at `app.py:614-620`).

**Why test 49 misses it:** it calls `fayda_login()` at the top of every attempt, so
`__renewed__` is always ~0 seconds old and `_expiry_due` is always false, and it races
`GET /api/me`, which never writes to the session. It exercises only the interleaving
that M6 already covers. It passes for a reason unrelated to the mechanism it names.

#### H2. The rate-limit key is attacker-chosen wherever `TRUST_PROXY_HEADERS` is set, and `render.yaml` sets it for production. (`backend/ratelimit.py:92-99`; `render.yaml:45-49`) — **likely** (certain for the code; deployment-dependent for Render specifically) — **PARTIAL (re-audit 2026-07-27; see NEW-2)**

`client_key` takes the **left-most** `X-Forwarded-For` entry, with no proxy-hop count,
no validation that it is an IP, and no check that it came from the trusted hop:

```python
return value.decode("latin-1").split(",")[0].strip()[:64]
```

The left-most entry is only trustworthy if the fronting proxy **replaces** the header.
Every proxy that *appends* — nginx `proxy_add_x_forwarded_for`, HAProxy `option
forwardfor`, AWS ALB, Cloudflare, Fly — leaves the client's own bytes in position 0.
DEPLOY.md's guidance is generic ("Set it ONLY when a trusted proxy sets
`X-Forwarded-For`"), which is satisfied by all of them.

Measured against this tree with `TRUST_PROXY_HEADERS=1`:

```
no XFF,      30x GET /login  -> first 429 at index 13
spoofed XFF, 60x GET /login  -> 429 count 0
XFF = 200 x 'A' (not an IP)  -> 307 (accepted as a bucket key, truncated to 64)
```

Sixty consecutive session-minting requests, zero refused. Three consequences:

* **Bypass.** The limiter — the only thing bounding the unbounded `sessions` table,
  the `/api/me/access-log` `count(*)`, the signature-verification CPU and the outbound
  IdP amplification, all of which prior audit rounds flagged — is a no-op.
* **Weaponisation.** Because the key is chosen by the caller, an attacker can send
  `X-Forwarded-For: <victim IP>` and drain *that* IP's login bucket, denying a named
  user the ability to sign in. The limiter becomes an offensive primitive.
* **It feeds M2 below.** One keep-alive connection sprayed 21 000 unique keys into the
  bucket table in 9.3 s with zero database work.

There is currently **no correct setting of this variable**. Off, every visitor behind a
proxy shares one bucket (M1). On, the key is caller-supplied. The missing piece is a
trusted-proxy hop count and taking the Nth entry from the right.

`render.yaml` hard-codes `value: "1"`, so this is the shipped production configuration,
not an operator mistake. Test 46's `assert rlmod.TRUST_FORWARDED is False` reads the
*test process's* environment and pins a property that render.yaml explicitly negates.

---

### Medium

#### M1. Behind a proxy without `TRUST_PROXY_HEADERS`, one bucket serves the entire internet; even with it, a shared NAT is locked out of login after ~3 sign-ins. (`backend/ratelimit.py:39-48`, `:92-99`) — **certain** — **RESOLVED**

A full login costs **four** `login`-tier tokens — `/login`, `/authorize`,
`/authorize/confirm`, `/callback` all match that tier — against `burst=10` refilling at
`0.5/s`. So one public IP supports ~2 back-to-back sign-ins and then one per 8 seconds.
Measured with five visitors sharing one NAT address:

```
visitor 0..3: [('login',307),('authorize',200),('confirm',303),('callback',...)]
visitor 4:    [('login', 429)]
```

The fifth person to click Sign in is refused at the first hop. DEMO_MODE's stated
purpose is "a credential-less shared demo" — a room of people on one venue Wi-Fi is
precisely one NAT address. On a deployment behind Cloudflare/nginx/ALB where the
operator followed DEPLOY.md's "*(leave unset)*" default, `scope["client"]` is always the
proxy and **all** users worldwide share that one bucket at 10 reads/s.

#### M2. Eviction is an O(n) `min()` under a global lock on every new key once the table is full, and it blocks the event loop. (`backend/ratelimit.py:111-116`) — **certain** — **RESOLVED**

`check()` tests the cap on every call, before it knows whether the key already exists.
Once `len(_BUCKETS)` reaches 20 000, every request bearing a **new** key scans all
20 000 entries. Measured in-process on this machine:

```
fill to 19 990 buckets      : 0.6 us/call
table full (20 000)         : 0.771 ms/call  -> ceiling ~1 297 req/s process-wide
existing-bucket hit         : 0.001 ms/call
```

`ratelimit.check` is a synchronous call from an async middleware, so those 0.771 ms are
spent with the asyncio event loop blocked — no other request in the process progresses.
~1 300 cheap requests/s stalls the whole instance, and via H2 that is reachable from a
single connection. Two secondary effects: eviction is global, so a `read`-tier flood
destroys `login`-tier buckets belonging to real users (the limiter loses state on the
callers it should be tracking); and the table never shrinks, so a process that has once
seen a spike pays the scan for every new visitor forever.

Memory itself is fine — ~4 MB at the cap. The vector is CPU under a lock, not RAM.

#### M3. A refused request writes a flushed JSON line to stderr, so the cheap path for the app is the expensive path for the log pipeline. (`backend/app.py:305`) — **certain** — **RESOLVED**

`log_event("rate_limited", …)` runs on every refusal with `flush=True`, ~107 bytes per
line, with no sampling, no suppression and no per-key backoff. One keep-alive connection
sustained ~2 250 req/s against this tree with zero database work; if all were refused
that is ~240 KB/s of log output from one attacker, on a platform where log ingestion is
metered. A limiter that converts a request flood into a log flood has moved the cost,
not removed it.

#### M4. `SUPABASE_CA_CERT` pointing at a missing file silently downgrades to `sslmode=require`, contradicting the comment that says the absence is visible at startup. (`backend/store.py:386-390`) — **certain** — **RESOLVED**

```
$ SUPABASE_CA_CERT=/nonexistent/ca.crt python -c "import store; store._conninfo()"
sslmode = require
sslrootcert present: False
```

`if ca and Path(ca).is_file()` fails closed on the *check* and open on the *outcome*:
no exception, no warning, no startup log. The store.py comment claims "the upgrade is
explicit and its absence is visible at startup" — it is not. The realistic failure is a
container where the certificate was not baked into the image or the mount path differs
between the Dockerfile and render.yaml: the operator sets the variable, believes the
connection is `verify-full`, and gets a TLS connection that authenticates nothing —
exactly the state the code's own comment describes as leaving "the credential and every
row" readable to anything that can intercept. Nothing in tests 46-51 covers this path.

#### M5. Screening's partial-match rule is backwards for the naming convention the module is written for. (`backend/screening.py:104`) — **certain** — **RESOLVED**

`needle_parts <= set(e["_norm"].split())` requires every token of the **queried** name to
appear in the **listed** name. Ethiopian names are given + father + grandfather; Fayda's
`name` claim will carry all three. Sanctions lists routinely carry two. Measured against
a list holding `Tesfaye Bekele`:

```
'Tesfaye Bekele'        -> [('Tesfaye Bekele', 'exact')]
'Tesfaye Bekele Alemu'  -> []            <-- the common real case, no hit
'Bekele Tesfaye'        -> [('Tesfaye Bekele', 'partial')]
'Mohammed'              -> [('Mohammed Ali','partial'), ('Mohammed Hassan Ibrahim','partial')]
```

The dominant real-world shape — a three-part Fayda name against a two-part list entry —
produces a **clean report**, and `status: "screened"` with `list_size: 40000` reads as a
positive statement that the person was checked. That is the one outcome the module's
docstring is at pains to avoid ("a screening module that overstates itself is worse than
none"). The inverse direction — a bare given name matching every entry sharing it — is
noisy but honest, and capped at 25.

Test 51 puts *both* `Tesfaye Bekele` and `Tesfaye Bekele Alemu` in the list and queries
the two-token name, which is the direction that works. The failing direction is never
exercised.

#### M6. In DEMO_MODE the app rate-limits its own OIDC token exchange, and all logins share one bucket. (`backend/ratelimit.py:52-63`; `backend/app.py:74-75`) — **likely** — **RESOLVED**

`TOKEN_URL`/`USERINFO_URL` default to `{BASE}/v1/esignet/…` — this process calling
itself over HTTP. Neither path is in `ROUTES`, so both land in `read`, and every
self-call carries the *same* client key (the app's own peer address), not the visitor's:

```
tier for /v1/esignet/oauth/v2/token : read
tier for /v1/esignet/oidc/userinfo  : read
self-calls allowed from one key: 120 (= 60 demo logins), then 10/s = 5 logins/s
```

Sixty logins of burst, then five per second **for the whole deployment**, after which
`/callback` fails with a token-exchange error for everyone. Combined with H2 an attacker
who sets `X-Forwarded-For` to the app's own egress address can drain that shared bucket
directly and deny logins to every visitor.

---

### Low

* **L1.** `/api/passkey/revoke` sits in the loosest `read` tier (10/s, burst 120) while
  `/api/passkey/register/` and `/api/passkey/login/` are explicitly tiered. It performs
  `delete_sessions_for_credential`, a `DELETE … WHERE data->>'passkey_credential_id' = %s`
  — an unindexed JSONB scan of the whole `sessions` table — plus a second durable delete.
  `/logout` is in the same tier and also does a durable delete per hit.
  (`ratelimit.py:52-63`, `app.py:797`)
* **L2.** The session cookie's `Max-Age` no longer slides while the database row does
  (`app.py:397` vs `:400`). A renewal-only save refreshes `expires_at` to now + 12 h but
  emits no `Set-Cookie` — confirmed empirically. An actively-used session is therefore
  dropped by the *browser* exactly 12 h after the last session *change*, while the server
  keeps writing renewals for a row nobody can present a cookie for. The renewal writes
  buy nothing for the client; they only extend the row's lifetime in the table the sweep
  exists to bound.
* **L3.** `SESSION_RENEW_SECONDS` (3600) is longer than `PRE_AUTH_SESSION_TTL_HOURS`
  (0.5 h = 1800 s), so a pre-auth session's sliding expiry can never fire before the row
  dies. Harmless today because nothing touches the server during the IdP round trip, but
  the two constants are in contradiction. (`app.py:235`, `:276`)
* **L4.** Test 46's `assert rlmod.TRUST_FORWARDED is False` (t.py:1893) asserts the
  *test process's* environment, not the server's. It would pass unchanged against a
  server started with `TRUST_PROXY_HEADERS=1` — which is what render.yaml does.
* **L5.** Test 46's `assert 5 <= first429 <= 20` (t.py:1859) would pass for a configured
  burst of 5 or of 20. It does not pin the value in `RULES`.
* **L6.** Test 49 (t.py:1954) re-logs-in on every attempt and races a read-only endpoint,
  so it can never reach either resurrection path (see H1). It is the test for the finding
  it cannot detect.
* **L7.** Test 51's `scr.LIST_PATH = ""` at t.py:2046 mutates the **test** process; the
  server under test has its own `screening` module and its own env. The endpoint's
  `not_configured` behaviour is never asserted over HTTP — only the module's, in-process.
* **L8.** Test 51's `os.path.join(prod_dir if False else tempfile.mkdtemp(), …)`
  (t.py:2015) is dead code left in.
* **L9.** `RATE_LIMIT=off` disables the entire control with no startup warning, in
  production as in dev. Production refuses to start without `SESSION_SECRET` and
  `FIN_PEPPER`; it says nothing about having no limiter. CLAUDE.md's Testing section now
  leads with `RATE_LIMIT=off` as the normal command to copy. (`ratelimit.py:77`)
* **L10.** The whole committed suite (tests 1-45) now runs against a server with the
  limiter disabled, so nothing but test 46 exercises any interaction between limiting and
  the binding, cooling, passkey or operator flows.
* **L11.** `screening._load()` caches keyed only on the path (`screening.py:56`), so an
  updated sanctions list file is never re-read without a process restart; and the module
  lock is held across the file read.
* **L12.** `_expiry_due` accepts `True` as an int — `isinstance(True, int)` is true, so a
  `__renewed__` of `True` would compute `time.time() - True`. Not reachable (the key is
  server-set), but the type guard does not do what it looks like it does. (`app.py:280`)
* **L13.** `store.py:389-390` — `kw.setdefault("sslmode", "verify-full")` immediately
  followed by `kw["sslmode"] = "verify-full"`. The `setdefault` is dead.

---

### Verified safe

Actively attacked, could not break. Do not re-plough these.

**Rate limiter classification and path normalisation.** No bypass exists. uvicorn
percent-decodes into `scope["path"]` *before* either the limiter or Starlette's router
sees it, so the two always agree. Raw-socket probes (no client-side normalisation):
`/api%2Fwallet%2Fbind` and `/%61pi/wallet/bind` reach the real bind handler **and** are
classified `bind` — a 40-request burst hit its first 429 at index 15, which is `burst=15`,
not the `read` tier's 120. `/API/wallet/bind`, `//api/wallet/bind`, `/./api/wallet/bind`,
`/api/./wallet/bind`, `/api/x/../wallet/bind`, `/api/wallet//bind` and
`/api/wallet/bind%20` all 404 at the router, so a loose tier buys nothing. Query strings
are excluded from `scope["path"]`, so `?x=1` neither changes the tier nor reaches the log
line. Trailing-slash forms redirect within the same tier. HTTP method is irrelevant to
classification but no method reaches a handler a mismatched tier protects.

**Middleware order — verified empirically, not by reading the registration lines.**
40 × `GET /login` against a limited instance: 11 allowed, 29 refused, and exactly **+11**
rows in `sessions`. Zero refused requests reached the session layer, and no 429 carried a
`Set-Cookie`. `app.add_middleware(RateLimitMiddleware)` last is genuinely outermost.

**Tier assignment across the real route table.** All 29 routes enumerated from
`app.app.routes` with `DEMO_MODE=1` and checked against `tier_for`. Every wallet, operator,
registry, access-log, passkey-login and passkey-register route lands where R6 claims. The
only misfits are L1 and M6 above; nothing sensitive silently fell into `read` beyond those.

**`__killed__` / `__renewed__` are not client-reachable.** Every `request.session[...]`
write in app.py uses a server-side literal key (`oidc_state`, `identity_id`, `claims`,
`auth_method`, `auth_at`, `passkey_challenge`, `passkey_credential_id`, `__rotate__`,
`__killed__`); there is no `session.update()` and nothing merges a request body into the
session. No client can plant either key.

**The tombstone is never persisted.** `session.pop("__killed__")` precedes the
`if session:` branch, so the killed dict is empty by the time anything could write it.
`sessions` rows inspected after 12 logout races contained no `__killed__`. (The tombstone
is useless — H1 — but it is not itself dangerous.)

**`__renewed__` does not leak.** Present in the stored row
(`['__renewed__','auth_at','auth_method','claims','identity_id']`), absent from the
`/api/me` response body, absent from the cookie (which carries only `sid.hmac`).

**M6 does not lose a legitimate change.** `original` is a string captured before the
handler runs, so later mutation of the same dict cannot corrupt it; `sort_keys=True`
recurses into nested dicts, so key ordering cannot produce a false "unchanged";
`default=str` cannot raise on the load side because everything came out of JSONB. Login
still persists and still sets the cookie (`fresh` forces both). An empty-data row is
still deleted. The lost-write failure mode I was looking for is not there — the M6 defect
is the opposite one (H1: it saves when it should not).

**The whitelist logger.** `log_event` cannot raise: the only failure-capable calls
(`json.dumps` with `default=str`, `print`) are inside the `try`. The whitelist genuinely
drops `fin_hmac`, `claims`, `sid`, `address`. `path` is the only attacker-influenced
field and it cannot carry a subject: no route in the table has a path parameter other
than the SPA catch-all, the frontend does no client-side routing (no `pushState`,
`pathname` or router in `frontend/src`), and the query string is not in `scope["path"]`.
`json.dumps` escapes newlines and quotes, so no log-line injection. Only two call sites
exist, so R6's "structured logging" is thin but not leaky.

**No raw FIN anywhere in R6.** `hash_fin` untouched. `/api/operator/screen` returns only
`{id, display_name}` — both already visible to an operator through `/api/operator/identity`
— and screens the stored `display_name`, never a client-supplied string. `fin_hmac` appears
in no log line, response body or cookie added by this diff.

**Nonce identity binding.** Both `issue_nonce` call sites (`app.py:944` real,
`app.py:1433` dev test-key) pass `identity_id`, so the dev path is bound too and no new
code path creates a NULL row. `wallet_bind` derives `iid` from `current(request)`, which
401s first — the argument cannot be omitted or nulled by a client. The NULL escape only
covers rows predating the `ALTER TABLE`, which the sweep clears within `NONCE_TTL`. The
check sits after the address/chain comparison and **before** the `consumed = 1` UPDATE,
which is the right order: a wrong-identity attempt does not burn the nonce, so the
rightful owner can still redeem it. Verified end to end — a second identity redeeming
another's nonce gets 400 "different identity" before verification is reached.

**Dev surface.** `APP_ENV` of `''`, `'Dev'`, `'development'` and `'prod'` all refuse to
start (missing `FAYDA_CLIENT_PRIVATE_KEY`) and register zero `/api/dev/*` routes. The new
`/api/dev/` entry in the tier table is inert outside dev. R6 changed none of this.

**Bucket table memory.** Hard-capped at 20 000 entries, ~4 MB. Not a memory-exhaustion
vector; the cost is CPU (M2).

**Screening input handling.** `_normalise` is linear — NFKD, a combining-mark filter, and
`re.sub(r"[^\w\s]", " ", …)`, a character class with no backtracking. Accents, case and
repeated whitespace all fold correctly (`Tesfayé Bekele`, `TESFAYE  bekele` both match).
Matches cap at 25. Malformed JSON yields `status: screened, list_size: 0` rather than a
clean-looking empty result. The list path is operator-supplied via env, never client-
supplied, so it is not a traversal vector. The endpoint is operator-gated (403 for an
ordinary session, 401 anonymous) and writes to the subject's access log.

**Not touched by R6, spot-checked for regression:** the sybil indexes, the cooling
period, `create_binding`'s `BindingConflict` handling, signature verification, and the
`__rotate__` session-fixation path all behave as they did at 7f0a748.

---

**Verdict: no — not safe to build on as it stands.** `/logout` demonstrably fails to end
a session 5 times in 6 against an attacker who is merely polling with the stolen cookie,
and the fix credited with preventing that (`__killed__`) cannot reach the request it
targets; separately, the limiter's key is caller-supplied in the configuration
`render.yaml` ships. Both are small, local fixes — compare `X-Forwarded-For` from the
right with a hop count, and give the session a server-side kill that a concurrent
request can observe (a generation counter or a conditional `UPDATE … WHERE sid = %s`
instead of an upsert). Everything else in R6 — the tiering, the middleware order, the
nonce binding, the log whitelist — survived attack intact.

---


## Audit - 2026-07-27 — R5 readiness (uncommitted working tree vs 8a154a9)

**Scope:** only the uncommitted diff — `backend/app.py` (+46/-4), `backend/t.py`
(+98), CLAUDE.md, DEPLOY.md, PROGRESS.md. Nothing else is modified.

**Scope correction.** The brief listed a `backend/verify.py` change
(`looks_like_address` requiring hex for EVM) as part of this diff. **It is not.**
`git diff --name-only` returns five files, none of them `verify.py`, and
`git log -S'0123456789abcdefABCDEF' -- backend/verify.py` puts that change in
**8a154a9 (HEAD)** — it was committed with R4/F1. It was still re-tested here
(see Verified safe) but it is not part of what is under review, and R5 readiness
does not depend on it.

**Method.** No servers started (the machine's port pressure was respected):
every probe was a short-lived `python -c "import app"` subprocess with a
synthetic env, plus Starlette's in-process `TestClient` for the HTTP-layer
checks. Six malformed-PEM shapes were driven through `jwt.encode` directly.
`store.init()` ran on import as it always does; nothing was reset, no operator
grant was made, no row was written. No code was modified.

**Counts: 0 critical / 0 high / 3 medium / 7 low.**

Nothing here is attacker-reachable. All three mediums are the same shape: an
operator misconfiguration that **boots silently and fails at the first real
user's login** — precisely the failure class this change was written to
eliminate, left open on three of the four variables that carry it.

---

### Critical

None.

### High

None.

### Medium

#### M1 — `DEMO_MODE` + `FAYDA_CLIENT_PRIVATE_KEY` boots, sets `mock_esignet.CLIENT_PUBLIC_KEY = None`, and 500s every login
`backend/app.py:165`, `backend/app.py:177-178`, `backend/mock_esignet.py:41,277-285`
**Confidence: certain (reproduced end-to-end).**

`backend/app.py:165` is `CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = _CLIENT_KEY_PEM, None`.
The `if MOCK_IDP:` block three lines later then assigns that `None` straight into
the mock: `mock_esignet.CLIENT_PUBLIC_KEY = CLIENT_PUBLIC_KEY`. The mock's token
endpoint verifies with it:

```python
claims = jwt.decode(client_assertion, CLIENT_PUBLIC_KEY, algorithms=["RS256"], ...)
except jwt.InvalidTokenError as e:
```

PyJWT 2.7.0 `RSAAlgorithm.prepare_key(None)` raises **`TypeError: Expecting a
PEM-formatted key.`** — a builtin, *not* a `jwt.InvalidTokenError`, so the
`except` does not catch it.

Steps (reproduced):
1. Deploy the shipped `render.yaml` (`APP_ENV=production`, `DEMO_MODE=1`).
2. Also set `FAYDA_CLIENT_PRIVATE_KEY` — while staging the R5 cutover, or from a
   shared Render env group, or because DEPLOY.md:44 introduces the variable and
   its "required outside dev/demo" qualifier is easy to read past.
3. The app **boots clean**. No warning.
4. Any visitor clicks a persona → `POST /v1/esignet/oauth/v2/token` →
   `500 Internal Server Error` (measured), which `/callback` re-wraps as
   `502 token exchange failed: Internal Server Error`.

Two problems, one root cause:
- **Availability:** the demo is 100% dead for every user, with a message that
  points at nothing.
- **Secret placement (the real one):** the boot guard at `app.py:130-139` exists
  specifically to stop real Fayda material from co-existing with a mock IdP that
  *anyone on the internet can log in through*. It checks the three URL variables
  and **not** the private key. So the one piece of genuinely irreplaceable
  partner material — the registered RSA private key — is the one the guard lets
  through onto a publicly-loginable deploy. The guard's own comment ("Real
  identities must not sit behind a login any visitor can perform") argues for
  covering it.

Same breakage in `APP_ENV=dev` with the variable set.

Not a bypass: the exception propagates to a 500 and `/callback` fails closed on
`status_code != 200`. No key material appears in any body (verified).
Invariant broken: none of the numbered nine directly — this is the DEMO_MODE
boot guard failing to cover the variable this diff added.

#### M2 — the key is checked for presence, never for validity; a wrong-but-present PEM boots and fails at the first user's `/callback`
`backend/app.py:163-175`, `backend/app.py:381-395`
**Confidence: certain (reproduced).**

`_CLIENT_KEY_PEM = os.getenv(...).strip()` is tested for truthiness only. The PEM
is never parsed at import — it is first touched inside `client_assertion()`, which
is first called from `/callback`.

Confirmed boot-clean-then-500 for every realistic wrong key:

| `FAYDA_CLIENT_PRIVATE_KEY` is… | boots? | first login raises |
|---|---|---|
| truncated / copy-paste-mangled PEM | **yes** | `ValueError: Unable to load PEM file … MalformedFraming` |
| a body that is not a key | **yes** | `ValueError: Valid PEM but no BEGIN PUBLIC KEY/END PUBLIC KEY delimiters. Are you sure this is a public key?` |
| the **public** half | **yes** | `AttributeError: 'RSAPublicKey' object has no attribute 'sign'` |
| an **EC** key | **yes** | `TypeError: ECPrivateKey.sign() takes 2 positional arguments but 3 were given` |
| **passphrase-protected** PKCS#8 | **yes** | `TypeError: Password was not given but private key is encrypted` |
| whitespace only | no — correctly refused | — |

The stated contract of this change, in the code comment at `app.py:169-170`, is
"fail at boot rather than at the first user's token exchange." For four of the
five shapes above it does the opposite, and the health check (`healthCheckPath:
/api/me` in render.yaml) passes throughout, so the deploy is reported green.
The messages are also misdirecting: a *private*-key variable failing with "Are
you sure this is a public key?" and an EC key failing with a positional-argument
`TypeError` will not send anyone to the right env var.

Mitigating: no key material is echoed in any of these messages (checked against
the supplied bytes, not a substring heuristic), and no traceback reaches the
client — `debug=True` is not set anywhere, so Starlette's locals-printing 500
page is off. Notably, a PEM whose newlines have been collapsed to spaces (the
classic env-var mangling) still signs fine under PyJWT 2.7.0, so that particular
foot-gun is not one.

#### M3 — `FAYDA_CLIENT_ID` has identical registered-per-partner semantics, has no guard, and silently defaults to `"fayda-wallet-demo"`; test 45's own production config exhibits this and asserts nothing
`backend/app.py:66`, `backend/t.py:1743-1758`
**Confidence: certain (reproduced).**

The whole argument for M2's guard is that partner onboarding registers **one**
value per relying party, so a per-process or defaulted value can never match.
`CLIENT_ID = os.getenv("FAYDA_CLIENT_ID", "fayda-wallet-demo")` has exactly that
property and got neither a guard nor a test.

Reproduced with test 45's own env (live `esignet.fayda.et` URLs + a registered
key, no `FAYDA_CLIENT_ID`) — the app boots and signs:

```
iss/sub sent to REAL Fayda = 'fayda-wallet-demo' 'fayda-wallet-demo'
aud = https://esignet.fayda.et/v1/token
client_id posted in the token form = 'fayda-wallet-demo'
```

Every token exchange goes to the real IdP claiming to be `fayda-wallet-demo`, and
is rejected — the same first-real-login failure M2 was written to prevent, from
the sibling variable.

What makes this a finding rather than a nit is that **test 45 demonstrates it and
looks away.** `backend/t.py:1758` is `print('AUD', p['aud']); print('ISS', p['iss'])`
— `AUD` is asserted at line 1766; `ISS` is printed and never asserted. The test
runs a configuration whose `iss`/`sub` is the hardcoded demo string, prints that
string, and concludes "R5 readiness". `exp`, `iat` and `jti` are likewise
unasserted. An assertion on `ISS` would have caught this at authoring time.

### Low

- **L1 — DEPLOY.md:45 documents a guard that does not exist.** The row covering
  "`FAYDA_CLIENT_ID`, `FAYDA_AUTHORIZE_URL`, `FAYDA_TOKEN_URL`,
  `FAYDA_USERINFO_URL`" says "Setting **any of them** alongside `DEMO_MODE=1`
  refuses to start". The guard at `app.py:131-132` lists only the three URLs.
  Reproduced: `DEMO_MODE=1 FAYDA_CLIENT_ID=real-partner-client` boots, and
  `app.CLIENT_ID` becomes `real-partner-client`. A doc that promises a structural
  guarantee the code does not provide is worse than no doc — it is exactly what
  an operator checks instead of reading the code. *(certain)*

- **L2 — a failing test 45 leaves `backend/.env` in `/tmp`.** `t.py:1730` copies
  `.env` (158 bytes, mode 0644, holds `SUPABASE_DB_URL` — a live DB credential)
  into the temp dir; `shutil.rmtree` is at `t.py:1796`, on the **success path
  only**. Any assert between 1765 and 1795 aborts the suite and strands the
  credential. `tempfile.mkdtemp` is 0700 so the exposure is same-user, not world
  — hence Low, not Medium — but t.py is the most-run command in the repo and
  nothing ever sweeps these. A `try/finally` costs two lines. *(certain)*

- **L3 — the assertion's `iss`/`sub`/`exp`/`jti` are unasserted in test 45.**
  See M3. The mock covers `iss`/`sub` in dev (`mock_esignet.py:287`), so the
  production-shaped path is the only one with no coverage — and it is the one
  the test exists for. *(certain)*

- **L4 — `app.py:166` is `elif DEV_MODE or DEMO_MODE:` where the file already
  has `MOCK_IDP`.** Functionally identical today, so not a bug. But that branch
  calls `mock_esignet.generate_client_keypair()`, and the import guarding it
  (`app.py:127`) is keyed on `MOCK_IDP`. The moment anyone narrows `MOCK_IDP`
  — e.g. `MOCK_IDP = (DEV_MODE or DEMO_MODE) and not os.getenv("FAYDA_TOKEN_URL")`,
  a plausible next step — line 166 becomes a `NameError` at import. The invariant
  is "these two conditions are the same condition"; write it once. *(certain)*

- **L5 — unauthenticated outbound amplification toward the partner IdP, live from
  R5 on.** `GET /login` (no auth) seeds `oidc_state` and returns it in the
  redirect; `GET /callback?code=x&state=<that state>` then makes the server
  perform an RSA-2048 signature and an outbound `POST` to `FAYDA_TOKEN_URL` with
  a **10-second** timeout, before any credential is validated. Each loop also
  writes a pre-auth session row. Pre-existing in shape and currently harmless
  (the mock is in-process, and `PRE_AUTH_SESSION_TTL_HOURS = 0.5` bounds the
  table), but this diff is what makes `FAYDA_TOKEN_URL` a real third party's
  endpoint — at which point an anonymous loop is pointing the partner's
  infrastructure at itself from our IP, with no rate limit anywhere on the path.
  Worth a bounded retry/rate limit before the cutover, not now. *(likely)*

- **L6 — `aud = TOKEN_URL` is asserted as correct but cannot be verified here.**
  `client_assertion()` sets `aud` to the token endpoint and `t.py:1766` pins it.
  RFC 7523 §3 permits the token endpoint URL **or** the issuer identifier, and
  which one eSignet requires is unconfirmed — the same B1 uncertainty PROGRESS.md
  correctly flags for the userinfo claim names, not flagged for this. A test that
  pins an unverified choice reads as confirmation of it. Add it to the
  credentials-day checklist alongside the claim names. *(worth checking)*

- **L7 — PROGRESS.md:820 "Delete `backend/mock_esignet.py`. Verified to work."
  contradicts the shipped config.** `render.yaml:17-18` sets `DEMO_MODE=1`, which
  *requires* the mock; `Dockerfile:22` is `COPY backend/ backend/`, so the image
  ships `mock_esignet.py` **and** `t.py`. The claim is true only of a future
  non-demo deploy. The deletion step needs "…and unset `DEMO_MODE`" beside it, or
  the first person to follow the checklist bricks the running demo. *(certain)*

---

### Verified safe

Actively attacked and could not break — do not re-plough:

- **`MOCK_IDP` gating is complete.** All nine `mock_esignet` references in
  `app.py` (lines 121, 128, 155, 159, 167, 178-180, 335) are inside
  `if MOCK_IDP:` / `elif DEV_MODE or DEMO_MODE:` blocks or are comments.
  Repo-wide grep across `*.py/*.js/*.jsx/*.yaml/*.json` finds no other importer
  outside `t.py`. **Reproduced: `APP_ENV=production` with `mock_esignet.py`
  physically absent boots and serves.** The SPA catch-all (`app.py:1310`)
  explicitly 404s `authorize` and `v1` rather than rendering the shell, so the
  IdP paths do not silently become HTML when unmounted. No error handler, dev
  route, or `t.py`-driven path reaches the module when the flag is false.
- **`CLIENT_PUBLIC_KEY = None` breaks nothing outside M1.** It has exactly two
  readers: `app.py:178` and `mock_esignet.py:279`. Nothing else in the repo reads
  it; it is never serialised, returned, or persisted.
- **The private key never reaches a response.** Checked `/api/me`, `/config.js`,
  `/`, `/docs`, `/openapi.json` against the actual PEM bytes and against
  `BEGIN PRIVATE KEY`/`MII` — all clean. `/api/me` unauthenticated returns exactly
  `{authenticated, cooling_hours, dev, demo, public_origin}`. `docs_url`,
  `redoc_url` and `openapi_url` are `None` outside dev (`app.py:326-328`). No
  `logging`/`logger` in `app.py` at all; the single `print` (`app.py:302`, sweep
  failures) formats only an exception type and message. `debug=True` appears
  nowhere, so Starlette's frame-locals 500 page — which *would* print
  `CLIENT_PRIVATE_KEY` — is off. `.dockerignore` still excludes `**/.env`.
- **Guard ordering is correct, and reproduced.** `DEMO_MODE=1` + a live
  `FAYDA_TOKEN_URL` + no key raises the **DEMO/live-URL** error, not the key
  error. That is the right precedence: the URL guard describes a security
  posture, the key guard describes a missing credential, and reporting the
  missing credential first would send the operator to supply one for a
  combination that must never boot regardless.
- **The empty/whitespace key is handled.** `.strip()` then truthiness →
  `"   \n  "` correctly falls through to the production refusal.
- **The key guard fires with the mock present on disk** (the real Docker image
  layout): `APP_ENV=production`, mock file present, no key → refuses. The guard
  is not accidentally dependent on the file's absence.
- **No `alg` confusion on the verifying side.** `mock_esignet.py:277-285` pins
  `algorithms=["RS256"]` and `options={"require": ["exp","aud","iss","sub"]}`,
  then checks `iss == sub == client_id`. `alg: none` and HS256-with-the-public-key
  are both rejected by the pin, and the public PEM is not published anywhere
  regardless. `aud` is pinned to `TOKEN_ENDPOINT`.
- **The assertion payload is byte-for-byte unchanged by this diff** — `iss`,
  `sub`, `aud`, `jti`, `iat`, `exp`, RS256. Only the key *source* moved. No
  attacker input reaches any claim; all inputs are env vars.
- **Test 45 is not vacuous.** Reverting either half of the fix makes it fail for
  the right reason: restoring the module-scope `import mock_esignet` (or the
  unconditional `generate_client_keypair()` call) makes `import app` raise
  `ModuleNotFoundError` in a directory that has no `mock_esignet.py`, so
  `probe.returncode == 0` fails first. `probe3` cannot pass by accident either —
  with the fix reverted its stderr says `mock_esignet`, not
  `FAYDA_CLIENT_PRIVATE_KEY`. `probe2`'s `bool(jwt.decode(...))` is non-empty-dict,
  so it is a real signature check against the configured key's public half.
- **The dev surface is untouched and correctly *not* widened.** `/api/dev/*`
  remains gated on `DEV_MODE` alone (`app.py:1195`); `MOCK_IDP` deliberately does
  not extend to it, preserving "DEMO_MODE mounts the mock IdP but NEVER
  /api/dev/*". Test 13 still pins the 404s — it now supplies a production client
  key, which is a legitimate accommodation of the new guard, not a weakening of
  what it asserts.
- **`verify.py:96-102` `looks_like_address` (committed in 8a154a9, not this
  diff).** Re-tested: EIP-55 mixed case, all-lower and all-upper checksummed
  addresses all accepted; `0x` + non-hex, `0x` + markup at 40 chars, and short
  input all rejected. It rejects no legitimate EVM address. `0X`-prefixed input
  is rejected, which is correct — no wallet or checksum scheme emits it. The
  change is strictly narrowing: nothing is accepted that was not accepted before.
- **Untouched by this diff, and confirmed untouched:** FIN hashing and the
  `SAFE_CLAIMS` whitelist, nonce issue/consume, the sybil partial unique index,
  the cooling period, RLS/`user_conn()`, the operator role and access log. No
  line of the diff enters any of those paths.

**Verdict: yes, safe to build on — nothing here is attacker-reachable, the
`MOCK_IDP` gating is genuinely complete (production boots with the mock deleted),
and the private key never leaves the process; but close M1 and M2 before anyone
touches real credentials, because all three mediums are silent-boot /
fail-at-first-login misconfigurations, which is the exact failure this change was
written to eliminate.**

---

## Audit - 2026-07-27 — R4/F1 fix review (re-audit of the 2026-07-26 findings)

**Scope:** only the fix deltas on top of the previous run. `git diff` vs `0f9a9ef`
(`backend/app.py` +108, `backend/store.py` +63, `backend/t.py` +278,
`frontend/src/App.jsx` +5, CLAUDE.md / DEPLOY.md / render.yaml) plus the untracked
`backend/chain.py` and `frontend/src/components/OperatorPanel.jsx`. Each of C1,
H1, H2, M1–M4 was re-attacked on its own terms; the previous run's Lows were
re-checked only where a fix touched them.

**Method.** A fresh `uvicorn` on `127.0.0.1:8123` (`APP_ENV=dev`, no reload) so the
existing `:8000` process and `t.py`'s `store.reset()` were never involved. Route
ordering re-enumerated programmatically over `app.app.routes` with
`inspect.getsource`, comparing the first-authorization line index to the first
`store.*`/`chain.*` line index. No third-party API was contacted: every explorer
test ran against local stubs on ephemeral loopback ports (gzip/deflate bombs of
16 MB–1 GB, a 302 to `169.254.169.254`, four stall shapes, a query-echoing server,
and exotic schemes). `tracemalloc` for heap peaks. Concurrency kept to ≤12 sockets.
One temporary operator grant was made and **revoked** (`492eb15a-…`, revoked
`2026-07-27T14:10:57Z`); the ~20 `access_log` rows those probes wrote carry
reasons beginning "audit re-verification" and one deliberate `"framing …"` row —
they are audit artefacts, not real activity, and the table is append-only. No code
was modified.

**Counts: 0 critical / 0 high / 1 medium / 8 low (all new). Previous run: 1
critical, 2 high, 4 medium — 6 RESOLVED, 1 PARTIAL.**

---

### Fix status, per previous finding

| # | Was | Status | One-line evidence |
|---|---|---|---|
| C1 | Critical | **RESOLVED** | 7 anonymous probe shapes → 1 byte-identical answer, 0 log rows, no DB query |
| H1 | High | **RESOLVED** | drip provider cut off at 15.02 s; ceiling ≈ 20 s, finite and operator-gated |
| H2 | High | **RESOLVED** | 302 / list / null / string / non-JSON / `{"result":{}}` / `[1,2,"three"]` all → a status |
| M1 | Medium | **PARTIAL** | `detail` reaches the API but `AccessLedger` never renders it |
| M2 | Medium | **RESOLVED** | cancelled → 404, archived → 200, active → 200, wrong-chain → 404 |
| M3 | Medium | **RESOLVED** | peak heap flat at ~48 MB for bombs 16 MB → 1 GB (was 134.6 MB) |
| M4 | Medium | **RESOLVED** | `?chainid=1` and a URL `apikey` both survive; env key wins; no test though |

#### C1 — RESOLVED

`require_operator` at `backend/app.py:988` is the first statement that can produce
a data-dependent answer. Seven anonymous probe shapes — bound-active,
bound-archived, bound-cancelled, real-identity-unbound, nonexistent-identity ×2,
and empty-reason — collapse to **one** distinct `(status, body, non-volatile
headers)` tuple:

```
bound-active / bound-archived / bound-cancelled /
real-id-unbound / nonexistent-id / nonexistent-id-unbound / empty-reason
  -> 401 {"detail":"not authenticated with Fayda"}     (1 distinct answer)
access_log rows written by these probes: 0
median latency  bound-active 0.76 ms | real-id-unbound 0.66 ms | nonexistent-id 0.58 ms
```

The anonymous path executes no database query at all — `current()` raises before
`store.is_operator()` — so there is no timing channel to find. An authenticated
non-operator is equally uniform (4 shapes → one `403 "this view is restricted to
compliance operators"`, 0 log rows), and a short reason does not change it: the
role check precedes the reason check. Post-revocation → 403 immediately.

**The shape checks that still run before `require_operator` are not an oracle.**
`iid` length/NUL, the chain enum, `_clean_token(address)`, `looks_like_address`
and Pydantic's 422 are all pure functions of the request body. Probed each
against a real identity and a nonexistent one: identical answers
(`400 malformed identity id`, `400 chain must be evm or solana`, `400 that does
not look like a valid address for this chain`, `400 malformed address`, `422
…Field required`). None of them reads storage, so none can distinguish a bound
address from an unbound one — which is the join being protected. Leaving them
above the authorization is correct: it keeps a malformed request from being
written to the permanent log as a real lookup.

Route enumeration over all routes confirms no regression elsewhere. The only rows
that flag are the ones the previous run already cleared (`/callback`, the
`/api/passkey/*` flows, and `/api/me/access-log` where `current(request)` is an
argument to the store call). Operator routes:

```
operator_onchain    require_operator@22  data-calls@[29,40,41,48]  ok
operator_timeline   require_operator@6   data-calls@[7,12,13]      ok
operator_identity   require_operator@9   data-calls@[10]           ok
operator_search     require_operator@6   data-calls@[7,15]         ok
operator_access_log require_operator@5   data-calls@[7,9]          ok
```

#### H1 — RESOLVED (the bound is real; the constant's name overstates it — see NEW-3)

`_read_bounded` terminates every stall shape I could build:

```
stall before the status line     ->  8.00 s   provider_unreachable / ReadTimeout
headers sent, body never starts  ->  8.01 s   provider_unreachable / ReadTimeout
one chunk at 7.5 s, then stall   -> 15.51 s   provider_unreachable / ReadTimeout
1 byte every 7.5 s, forever      -> 15.02 s   provider_unreachable / TimeoutError
```

The last is the case that previously ran past 30 s with no exception. The
`chain.transactions()` call is the only outbound work `/api/operator/onchain`
does after authorization, and it is now finite, so a slow explorer can no longer
hold an anyio worker indefinitely. It is also now reachable only with the
operator role and only after a log write, which removes the unauthenticated
amplifier entirely.

#### H2 — RESOLVED

`json.loads`, the `isinstance(body, dict)` guard, the `result`-is-a-list guard and
the per-entry `isinstance(t, dict)` guard are all inside the one `try` at
`backend/chain.py:142-188`. Every hostile shape degrades:

```
302 -> link-local metadata   provider_error         "explorer returned HTTP 302"
top-level list / null / string / number, non-JSON, {"result":{...}}, [1,2,"three"]
                             provider_error / provider_unreachable, transactions: []
```

Nothing raised; no 500; `transactions` is `[]` in every failure case. `t.py`
42(f) now covers six of these and — importantly — the non-dict-entry case would
have **passed as `status: "ok"` with 0 transactions** before the fix, so the test
can now fail.

#### M1 — PARTIAL

Backend resolved: `backend/store.py:998` selects `detail`, `id` is stripped from
what is returned, and the subject's own `view_onchain` rows carry
`detail: "evm:0x…"`. `t.py` 42(h) asserts it.

**Not resolved in the product.** `AccessLedger`
(`frontend/src/components/Ledgers.jsx:56-96`) renders three columns — When,
Action, Stated reason. `detail` is never displayed, and `view_onchain` is absent
from the action label map at `Ledgers.jsx:72-76`, so a subject sees the raw string
`view_onchain` and no wallet. The finding was "the subject can never learn which
of their wallets was investigated"; through the UI they still cannot. See also
NEW-1: the value they would be shown is not guaranteed to name a wallet that was
actually traced, or one that is theirs.

#### M2 — RESOLVED

Verified against a live subject holding one active, one archived and one
cancelled binding:

```
active            -> 200        archived          -> 200
cancelled         -> 404        unbound           -> 404
ACTIVE uppercased -> 200        mixed case        -> 200
solana address claimed against an EVM-only identity -> 404
```

`normalize_address` is applied to both sides, and `b["chain"] == req.chain` is
evaluated before it, so an EVM lowercase fold is never applied to a Solana row.
The reasoning in the comment at `backend/app.py:995-1000` is the right one.

One inconsistency survives, in the safe direction: `/api/operator/timeline` still
offers `wallets` filtered to `status == "active"`
(`backend/app.py:930-933`), so an archived binding is reviewable by
`/api/operator/onchain` but is never offered by the panel. Not a hole; the two
endpoints simply disagree about what is askable, in the opposite direction from
last time.

#### M3 — RESOLVED

The 1 MB cap is enforced while streaming and **before** the chunk is appended.
The cap counts *decompressed* bytes (`iter_bytes()` decodes), which is the
correct side to count. Peak heap for one request, measured with `tracemalloc`
against gzip bombs:

```
   16 MB uncompressed /   16.0 KB on the wire -> peak  51.7 MB, status=failure
   64 MB uncompressed /   63.7 KB on the wire -> peak  47.8 MB, status=failure
  256 MB uncompressed /  254.8 KB on the wire -> peak  47.8 MB, status=failure
 1024 MB uncompressed / 1019.2 KB on the wire -> peak  47.8 MB, status=failure
```

Flat — previously 134.6 MB for a 200k-transaction response. Residual amplification
is NEW-4.

#### M4 — RESOLVED

Verified against a query-echoing local stub. The effective request URL:

```
config /api?chainid=1                 -> ?chainid=1&module=account&…&address=0xabab…
config /api?chainid=1&apikey=URLKEY   -> ?chainid=1&apikey=URLKEY&module=…
config /api?apikey=URLKEY + env key   -> ?apikey=ENVKEY&…            (env wins — correct)
config /api?address=0xVICTIM&module=stats
                                      -> ?address=0xabab…&module=account&…
                                         (config cannot redirect the lookup)
```

Parameter pollution via the operator's address is not reachable — every hostile
address is percent-encoded into the `address` value:

```
0x&apikey=X&address=0xdead&z…  -> address=0x%26apikey%3DX%26address%3D0xdead%26z…
0x#?/../evil…                  -> address=0x%23%3F%2F..%2Fevil…
0xa\n\rHost: x…                -> address=0xa%0A%0DHost%3A+x…      (no header injection)
```

Two config-shape residuals, both Low and both listed below (NEW-8 covers the
absence of any test for this fix): `parse_qsl` runs without `keep_blank_values`,
so a configured `?chainid=` (blank value) is silently dropped; and
`dict(parse_qsl(...))` collapses duplicate keys to the last one
(`?tag=a&tag=b` → `tag=b`).

---

### Medium

#### NEW-1 — the C1 reorder plus the M1 disclosure let an operator write a false, permanent, subject-visible record naming a wallet that is not the subject's

`backend/app.py:988-990` writes the access-log row — including
`detail=f"{req.chain}:{req.address}"` — **before** `store.identity_full()` and
before the ownership check at `backend/app.py:998-1003`. That ordering is right;
it is what closed C1. The consequence is that a `view_onchain` row is written for
every *attempt*, including refused ones, and there is no field recording the
outcome. M1 then makes `detail` visible to the subject.

Measured on one subject: **8 `view_onchain` rows for 4 lookups that actually
happened.** The refused attempts — a cancelled address, an unbound address, a
Solana address against an EVM-only identity, and deliberate junk — produced rows
the subject cannot distinguish from real traces.

The junk case is the sharp edge. `looks_like_address` for EVM
(`backend/verify.py:96-97`) is:

```python
if chain == "evm":
    return address.startswith("0x") and len(address) == 42
```

No hex check. So 40 characters of arbitrary operator-chosen text pass. Row
actually written and read back through `access_log_about`:

```json
{"action":"view_onchain","actor_id":"492eb15a-715e-4cdf-b551-23dccb66380f",
 "reason":"framing d86d028d-3b19-4960-a29e-c07067f72562",
 "detail":"evm:0x<script>alert(1)</script>zzzzzzzzzzzzzzz"}
```

**Attack.** An operator who wants to manufacture suspicion against a person posts
`/api/operator/onchain` with that person's `identity_id` and the address of a
sanctioned or notorious wallet, with any plausible reason. The response is
`404 "that wallet is not bound to this identity"` — no data is disclosed — but the
append-only log now permanently records that this operator traced that wallet
under that identity, and the subject's own view says the same. Nothing in the
schema or the API can later distinguish it from a genuine trace. Repeat for as
many addresses as desired; nothing rate-limits it.

- **Invariant strained:** R4 claim 3, which says the ownership check exists so
  "the log entry cannot name an unrelated subject" — it can now name an unrelated
  *address*, which for `view_onchain` is the whole content of the entry. Also
  CLAUDE.md's framing of `/api/me/access-log` as "the only counterweight to a
  capability that otherwise points one way": a counterweight that can be loaded
  with fiction by the party it constrains is a weaker instrument than it appears.
- **Not an XSS today:** `AccessLedger` does not render `detail` (M1 PARTIAL) and
  React escapes; `access_log_all`'s `SELECT *` reaches no rendered surface either.
  That is luck, not a control.
- **Confidence: certain** (reproduced end to end; rows are in the table).
- Direction, not applied: keep the pre-authorization write, then record the
  outcome — a distinct action (`view_onchain_refused`) or an outcome column — so
  an attempt is legible as an attempt; and make the EVM shape check verify hex.

---

### Low

- **NEW-2 — M1 is invisible in the UI.** `Ledgers.jsx:56-96` renders When /
  Action / Stated reason only; `detail` is dropped and `view_onchain` has no label
  case. The person the log exists for still cannot see which wallet was traced
  without reading `/api/me/access-log` by hand.
- **NEW-3 — the effective bound is ~20 s, not `TOTAL_BUDGET_SECONDS = 12`.** The
  deadline at `backend/chain.py:107` is evaluated only after a chunk is yielded, so
  a chunk landing at t=11.9 s buys another full 8 s read timeout. Measured 15.51 s
  for the "one chunk then stall" shape. The ceiling is `TOTAL_BUDGET + read` ≈ 20 s
  (connect is inside the budget — the deadline is set before the client is built).
  Finite and adequate; the constant name and the comment ("absolute wall-clock
  budget … connect through last byte") claim more than the code delivers.
- **NEW-4 — gzip amplification: ~48 MB peak heap per request despite a 1 MB cap.**
  One 64 KB network read decompresses to as much as ~48 MB before the cap can
  observe it (measured flat at 47.8–51.7 MB for bombs from 16 MB to 1 GB). Bounded
  because httpx advertises only `gzip, deflate` here — brotli and zstandard are not
  installed, and installing either would raise this ceiling silently. Worth a
  comment naming the assumption.
- **NEW-5 — a size-cap trip is reported as `provider_unreachable / ValueError`.**
  The provider was reached; it sent too much. Same for the deadline
  (`TimeoutError`). `chain.py` rule 2 is that an operator must be able to tell what
  happened, and `type(e).__name__` is not that. `provider_error` with "response
  exceeded the size cap" costs nothing and leaks nothing.
- **NEW-6 — `/api/me`'s `operator` flag ignores `auth_method`.**
  `backend/app.py:1121` is `store.is_operator(iid)`; `require_operator`
  additionally demands `auth_method == "fayda"` (`backend/app.py:838-841`). An
  operator on a passkey session therefore gets `operator: true`, is shown
  `OperatorPanel`, and every button returns 403. No privilege is granted — verified
  that revocation flips the flag immediately with no caching — but the hint
  disagrees with the server for exactly the case R3 introduced.
- **NEW-7 — `OperatorPanel.jsx` ships to every visitor.** Static import at
  `frontend/src/App.jsx:25`, gated only at render. The three operator paths and
  their exact request bodies are readable in the public bundle by anyone. The
  backend deliberately keeps `/docs` and `/openapi.json` dev-only
  (`backend/app.py:292`) so those routes are not enumerable; the bundle now
  enumerates them anyway. No authorization consequence (all three refuse anonymous
  and non-operator callers), but a dynamic `import()` behind `me.operator` would
  restore the stated posture.
- **NEW-8 — the M4 fix has no test.** `grep` over `backend/t.py`: zero references to
  `chainid`, `parse_qsl`, `MAX_RESPONSE_BYTES` or `_read_bounded`. The
  query-merge behaviour is one refactor back to `httpx.get(url, params=…)` away
  from silently reverting to "we looked at another chain and reported it as this
  one", which is the state M4 described. CLAUDE.md: "New invariants get a test in
  t.py."
- **NEW-9 — no single-flight, and failures are still never cached.** 12 concurrent
  misses on one key produced 12 provider calls. Combined with NEW-3's ~20 s
  ceiling and the deliberate no-cache-on-failure rule, a dead explorer costs one
  worker thread for up to 20 s per click with no backoff. Operator-gated and
  logged, so not the H1 hazard, but the H1 fix is a bound rather than a budget.

### Still open from the previous run (not claimed fixed; re-confirmed)

- **L2** — `backend/t.py:1360`, `assert ats == sorted(ats, reverse=True)` applied to
  the output of a function whose last statement is that sort. Unchanged tautology.
- **L3** — 42(d)'s "nothing is persisted" check still tests `pg_tables` name
  substrings.
- **L4** — 42(b) still asserts `status == "not_configured"`, so the suite fails for
  any developer with `CHAIN_EXPLORER_URL` set, and `real_url` is only captured
  later at (c) — too late to help.
- **L5 — re-confirmed live, and now demonstrated.** `backend/chain.py:199` builds
  `f"{chain}:{address.lower()}"` while `store.normalize_address` leaves base58
  untouched. With `_fetch` returning `ok` for solana (i.e. the day Solana is
  wired), two distinct base58 addresses differing only in case shared one entry —
  the provider was called once and the second caller got the **first address's**
  history with `cached: true`. Inert today only because `_fetch` returns
  `unsupported_chain` for non-EVM and failures are not cached.
- **L6, L7, L8, L9, L10** — not addressed by these fixes; not re-ploughed this run
  beyond L7, which the cache probes re-confirm (the cache is global and keyed on
  `chain:address`, so `cached: true` still discloses another operator's recent
  activity).
- **L11 — half fixed.** CLAUDE.md now carries `chain.py` and `OperatorPanel.jsx`
  rows and the "No blockchain connection anywhere" line is corrected; DEPLOY.md and
  render.yaml document both explorer variables, and DEPLOY.md's example is the
  `?chainid=1` shape M4 now preserves. Still open:
  `CACHE_TTL_SECONDS = int(os.getenv("CHAIN_CACHE_TTL", "300"))` runs at import and
  `app.py:44` imports `chain` unconditionally, so `CHAIN_CACHE_TTL=abc` is a boot
  crash of the entire application (verified: `ValueError` at `chain.py:48`), and a
  negative value silently disables the cache (verified: `cached` never becomes
  true).

---

### Verified safe

Actively attacked this run and could not break. Do not re-plough.

**Authorization**
- Every C1 probe shape, anonymous and authenticated-non-operator, byte-identical
  including headers; zero log rows; no DB query on the anonymous path so no timing
  channel. Malformed-input answers (400/422) are pure functions of the request and
  identical whether the named identity exists or not.
- Route re-enumeration: no operator route reads storage before authorizing. The
  three routes flagged are the pre-existing auth flows.
- Revocation is immediate on `/api/operator/onchain`, `/api/operator/timeline` and
  the new `/api/me` flag — `store.is_operator` is queried per request, uncached.
- `operator: true` grants nothing: it is computed after the authenticated guard,
  is scoped to the caller's own session, and every route it enables re-checks the
  role *and* `auth_method == "fayda"` server-side.
- `OperatorPanel.jsx` calls only `/api/operator/search`, `/api/operator/timeline`
  and `/api/operator/onchain`; it holds no secret, derives `identity_id` from the
  server's own response, and renders nothing the server did not return. `api.js`
  surfaces only `detail` from an error body — no stack traces.

**Egress / SSRF**
- `follow_redirects=False` confirmed behaviourally, not by reading the signature:
  a 302 to `http://169.254.169.254/latest/meta-data/` returns
  `provider_error / "explorer returned HTTP 302"` and issues no second request.
- `file://`, `ftp://`, a non-URL and `http://[::1]:1/` all degrade to
  `provider_unreachable`; none raises.
- No parameter pollution reachable from the operator-controlled address (see M4
  above); config-supplied `address`/`module` are overridden by code.

**Cache**
- 8 threads × 400 lookups over 2000 keys held the cache at exactly
  `_CACHE_MAX = 512` with no exceptions; `_cache_get` and `_cache_put` both hold
  `_CACHE_LOCK`, and eviction is `min()` inside it.
- A failure after a success does not evict (`status: "ok"`, `cached: true`).
- An entry past its TTL is never served as `cached: true`; the expired entry is
  popped and the live failure is returned with `cached: false`.
- Keys are chain-scoped: the same address under `evm` and `solana` produces two
  entries. No cross-identity bleed is constructible — the payload holds only
  `status`/`detail`/`transactions` for a public address, and `wallet` is added by
  the endpoint from the request, outside the cache.

**Parsing**
- Seven hostile response shapes and four stall shapes all become a status; nothing
  raised out of `_fetch` in any test this run.
- The byte cap fires before the chunk is appended, so the accumulated buffer never
  exceeds 1 MB.

**Tests**
- Test 41 is now a real test: three probe shapes, byte-identical answers required,
  and the access-log total pinned. It would fail on the pre-fix ordering.
- 42(e) (cancelled refused / archived reviewable), 42(f) (six hostile shapes),
  42(g) (flood) and 42(g2) (slow drip) all exercise behaviour that did not exist
  before the fixes, and 42(f)'s non-dict-entry case would have passed as
  `status: "ok"` under the old code.

---

**Verdict: yes — safe to build on.** The critical linkage oracle is closed at both
the anonymous and the authenticated-non-operator boundary with no residual
variation I could find, and the two Highs are genuinely bounded rather than
papered over. The one Medium is an integrity defect in the audit trail rather than
a disclosure — it costs an operator role to exploit and leaks nothing — but it
should be fixed before the access log is ever relied on as evidence, because
nothing in the schema can distinguish a fabricated entry from a real one after
the fact.

---
## Audit - 2026-07-26 — R4/F1 (operator timeline + on-chain history)

**Scope:** only what is uncommitted on top of `0f9a9ef`. That is `git diff`
(`backend/app.py` +88, `backend/store.py` +55, `backend/t.py` +135) plus the new
untracked `backend/chain.py`. Concretely: `store.identity_timeline()`,
`POST /api/operator/timeline`, `POST /api/operator/onchain`, all of `chain.py`,
and t.py tests 40-42.

**Method:** routes enumerated programmatically by walking `app.app.routes` and
running `inspect.getsource` on every endpoint, comparing the source line index of
the first authorization call (`require_operator` / `current(`) against the first
`store.*` call — not by grep. A fresh `python app.py` (`APP_ENV=dev`, no reload)
on `127.0.0.1:8000`, rebooted between configurations because `chain.py` reads its
env at import. No third-party API was contacted: `CHAIN_EXPLORER_URL` was pointed
at a local hostile stub on `127.0.0.1:8899` serving ten adversarial response
shapes (non-object JSON top levels, 200k-element arrays, 200k-character fields,
NUL-bearing strings, 2000-deep nesting, and a chunked slow-drip). No code was
modified; the four probe operator grants were revoked and the server was restored
to its unconfigured state.

**Counts: 1 critical / 2 high / 4 medium / 11 low.**

---

### Critical

#### C1 — `/api/operator/onchain` is an unauthenticated, unlogged oracle that maps a wallet address to a Fayda identity

`backend/app.py:978-986` (the check) versus `backend/app.py:988` (the
authorization). `store.identity_full()` and the identity↔address binding test run
**before** `require_operator()`. Every branch above line 988 is reachable with no
session at all.

The three outcomes are distinguishable, which is the entire oracle:

```
anon POST /api/operator/onchain {identity_id, chain, address, reason}
  401 "not authenticated with Fayda"          -> identity exists AND address is bound to it
  404 "that wallet is not bound to this identity" -> identity exists, address is not bound
  404 "no such identity"                      -> identity does not exist
```

Verified against a fresh server:

```
anon bound pair        -> 401 {"detail":"not authenticated with Fayda"}
anon real id, unbound  -> 404 {"detail":"that wallet is not bound to this identity"}
anon bogus id          -> 404 {"detail":"no such identity"}
revoked-op bound       -> 403 {"detail":"this view is restricted to compliance operators"}
revoked-op unbound     -> 404 {"detail":"that wallet is not bound to this identity"}
log entries produced by ALL of the above probes: 0
```

**Attack.** An operator whose grant was revoked (or who never had one, or who is
simply logged out) keeps any `identity_id` they ever saw — from
`/api/operator/search` results, a `/api/registry` listing, a case file, a
screenshot. For each retained id they replay one POST per candidate address taken
from public chain data. A 401 confirms that this specific Ethiopian national
identity controls that specific wallet. The `reason` is never validated on this
path either, so `reason: ""` works. Nothing is written to `access_log` — verified
by counting rows about the subject before and after six probes: delta 0. There is
no rate limit; measured 3.1 req/s serially against managed Postgres, and each
probe runs `store.identity_full()`, two privileged queries, for an anonymous
caller.

This is precisely the join the registry exists to protect, obtained by the one
route that leaves no trace. It also inverts R3's own stated rule, which is written
out 70 lines earlier in the same file at `backend/app.py:899-901` on
`/api/operator/identity`: *"Logged BEFORE the read, and logged even when the
record turns out not to exist: an operator probing for which identities are
present is itself something a reviewer should be able to see."* `/api/operator/onchain`
does the opposite, and probes at a finer grain than the case R3 guarded.

- **Invariants broken:** #8 (no cross-user read without an operator check AND an
  access-log entry — here there is neither), and #9 (the privileged
  `store.conn()` path is executed on behalf of an unauthenticated caller).
- **Note:** R4's own claim 3 says the binding check exists so "the log entry
  cannot name an unrelated subject". Running it before the log is what makes it
  an oracle; the check is right, its position is wrong.
- **Confidence: certain** (reproduced end to end on a fresh server).

---

### High

#### H1 — the on-chain timeout is not a bound; a slow explorer takes the whole application down

`backend/chain.py:38,89-90`. `REQUEST_TIMEOUT_SECONDS = 8` is passed to
`httpx.get` as a scalar, which httpx expands to `Timeout(connect=8, read=8,
write=8, pool=8)`. Those are **per-operation**, not total. A provider that emits
one byte every three seconds resets the read timer forever; httpx has no overall
deadline. Measured directly against the stub: still running after 30 s, no
exception, no return.

Every endpoint in this app is `def`, not `async def`, so each in-flight lookup
holds one anyio worker thread (default limiter: 40).

```
firing 45 concurrent /api/operator/onchain calls against a slow-drip explorer...
   GET  /api/me       -> *** ReadTimeout after 20.0s
   GET  /config.js    -> *** ReadTimeout after 20.0s
   GET  /login        -> *** ReadTimeout after 20.0s
access-log rows about the subject: 40
```

The registry stops serving entirely — not just the compliance panel. Login and a
static JS file both stall. Failures are deliberately not cached
(`backend/chain.py:141`), so retries re-open the connection every time rather than
backing off.

The trigger does not require a malicious explorer, only a degraded one under load,
or anyone able to sit on that TLS connection. It is the exact failure `chain.py`'s
docstring rule 3 says cannot happen: *"Never block on it. Every call is
timeout-bounded."* Note also the 40 access-log rows: each says the operator was
served, and none of them were.

- **Invariant broken:** R4 claim 2 / `chain.py` rule 3. Availability of the whole
  service, from a third-party dependency the module says it does not trust.
- **Confidence: certain** (reproduced end to end).

#### H2 — any non-object JSON from the explorer escapes as an unhandled exception (500), after the access has already been logged

`backend/chain.py:104`. `result = body.get("result")` sits **outside** the
`try/except` that ends at line 100. If the explorer's JSON top level is anything
other than an object, `.get` raises `AttributeError` and nothing catches it. Four
of ten hostile shapes reach it:

```
toplevel_list      *** RAISED AttributeError: 'list' object has no attribute 'get'
toplevel_null      *** RAISED AttributeError: 'NoneType' object has no attribute 'get'
toplevel_string    *** RAISED AttributeError: 'str' object has no attribute 'get'
toplevel_number    *** RAISED AttributeError: 'int' object has no attribute 'get'
deep_nest          *** RAISED AttributeError: 'list' object has no attribute 'get'
```

End to end through the endpoint:

```
HTTP 500 | body: 'Internal Server Error'
leaks traceback: False
access-log entries written by the FAILED lookup: 1
```

A bare JSON array or `null` is what many API gateways, rate limiters and error
proxies return. `backend/app.py:990-991` asserts inline that this cannot happen
(*"Never raises: a slow or broken explorer comes back as a status the panel
renders, not a 500"*) — the comment is wrong about its own code.

Two consequences. The panel breaks on provider misbehaviour instead of degrading,
which is the failure mode R4 was split into two endpoints to avoid. And the
`access_log` row is written at line 988 before the call, so the permanent audit
trail records a successful lookup of that subject's wallet that never returned
anything — the log over-reports, which is the safe direction but is still a false
entry in an append-only table that cannot be corrected.

- **Invariant broken:** R4 claim 2 / `chain.py` rule 3 ("All failures become a
  status, never an exception").
- **Confidence: certain** (reproduced end to end; stack trace captured in the
  server log at `chain.py:104`).

---

### Medium

#### M1 — the subject can never learn which of their wallets was investigated

`backend/store.py:977` sets `cols = "id, at, actor_id, action, reason"` in
`access_log_about()` — the query behind `GET /api/me/access-log`. `detail` is not
selected. `access_log_all()` at `backend/store.py:955-959` uses `SELECT *`, so the
operator console sees it.

R4's claim 5 is that the on-chain entry "names subject_id + the chain:address in
`detail`". It does — into a column only operators can read. Verified: entries
returned to the subject carry exactly `{action, reason, at, actor_id}` and no
`detail` key at all.

CLAUDE.md calls `/api/me/access-log` *"the only counterweight to a capability that
otherwise points one way"*. For R3's actions the omission was arguable (`detail`
held the operator's search string). For `view_onchain` it is not: `detail` holds
*which of the subject's own wallets was traced*, and a person told only that
"someone ran view_onchain about you" cannot tell whether their active wallet, a
wallet they cancelled during a cooling period, or an address they abandoned years
ago was the one pulled into a financial-history file.

- **Invariant strained:** #8's counterweight. The log is written truthfully and
  then shown asymmetrically.
- **Confidence: certain.**

#### M2 — the binding check accepts archived and cancelled bindings, and cancelled is the wrong answer

`backend/app.py:981-984` iterates `record["bindings"]` with no status filter.
Verified on a subject with one active, one archived and one cancelled binding:

```
active   w2    -> 200
archived w1    -> 200
cancelled w3   -> 200
unbound        -> 404
```

Meanwhile `/api/operator/timeline` at `backend/app.py:955-958` offers only
`status == "active"` wallets, with the comment *"Which wallets the caller may then
ask about on-chain"*. The two endpoints disagree about what is askable.

**Archived should stay.** An archived binding is an address the person genuinely
proved control of and later replaced; a compliance review of past activity needs
it, and excluding it would make the feature answer only the present tense.

**Cancelled should not.** Per CLAUDE.md, the cooling period exists *for session
compromise*: "If an attacker with a live session swaps the wallet, the real user
needs a window to cancel." A `cancelled` row is therefore, in the exact scenario
the mechanism was built for, **the attacker's address, which the victim
explicitly repudiated**. R4 currently lets an operator pull that address's full
transaction history, return it under the victim's name in a case file, and write
`view_onchain / <victim> / evm:<attacker address>` into an append-only log that
cannot be amended. The registry never asserted that person controlled it — the
cancellation is the assertion that they did not.

`promote_due` also writes `status='cancelled'` when a pending row loses the sybil
race (`backend/store.py:1414-1418`), so a cancelled address can be one that
**belongs to somebody else entirely**, now queryable under the loser's identity.

Recommendation: accept `active` and `archived`; refuse `cancelled` and `pending`,
or at minimum carry the status in both the response and the `detail`.

- **Confidence: certain** on the behaviour; the active-only argument is a judgement
  call, stated above.

#### M3 — the explorer response is fully buffered and parsed before `MAX_TX` is applied

`backend/chain.py:89-111`. `httpx.get` without `stream=`, no `Content-Length`
ceiling, no byte cap; `r.json()` materialises the whole document, and
`result[:MAX_TX]` truncates only afterwards. Measured with a 200k-transaction
response: **134.6 MB peak Python allocation for one request**, to return 25 rows.

Combined with H1 (workers are held) and the fact that failures are not cached, a
degraded or hostile provider drives repeated multi-hundred-megabyte allocations
across up to 40 concurrent threads. Per-field truncation (H-verified: 80/64/40/20)
protects the *response*, not the *heap*.

- **Invariant strained:** `chain.py` rule 3 and CLAUDE.md's general posture on
  attacker-priced CPU/memory (`verify.py:99-101` gets this right for base58; this
  module does not).
- **Confidence: certain** (measured with `tracemalloc`).

#### M4 — any query string in `CHAIN_EXPLORER_URL` is silently discarded, so the panel can confidently report another chain's history

`backend/chain.py:89`. httpx's `params=` **replaces** the URL's query rather than
merging it. Verified:

```
httpx.Request('GET','http://x/api?chainid=1&apikey=SECRET', params={...}).url
  -> http://x/api?module=account&address=0xab
=> query params baked into CHAIN_EXPLORER_URL are DISCARDED
```

This is not hypothetical: Etherscan's current V2 multichain endpoint selects the
network with `?chainid=`. Deploying
`CHAIN_EXPLORER_URL=https://api.etherscan.io/v2/api?chainid=1` silently drops
`chainid`, and a URL-embedded `apikey` likewise vanishes. The response still comes
back `status: "ok"` with `cached: false` and a list of transactions.

`chain.py`'s rule 2 is *"Never fabricate… an operator reading a compliance screen
must be able to tell 'no transactions' from 'we did not look'."* This produces a
third state the module has no vocabulary for: *we looked somewhere else*, rendered
as a confident answer. There is no startup validation of `EXPLORER_URL` and no
echo of the effective URL anywhere in the payload, so nothing surfaces the
mistake.

- **Confidence: certain** on the httpx behaviour; **likely** on the deployment
  shape (no explorer is configured yet, which is why this is catchable now).

---

### Low

- **L1 — test 41's anonymous probe picks the one input that hides C1.**
  `backend/t.py` test 41 asserts `anon.post(.../onchain, address=w2) == 401`, and
  `w2` is *bound* to `tl_id`. That is the single branch that reaches
  `require_operator`. Any unbound address returns 404 to an anonymous caller and
  the test would have failed. The check that exists to prove the endpoint is
  closed to anonymous callers passes because it avoids the hole.
- **L2 — test 40's ordering assertion is a tautology.** `assert ats == sorted(ats,
  reverse=True)` is applied to the output of a function whose last statement is
  `events.sort(..., reverse=True)`. It cannot fail, and it cannot detect an event
  carrying the wrong `at`.
- **L3 — test 42's "nothing is persisted" check tests table names.** It asserts no
  `pg_tables` row contains the substrings `tx`/`transaction`/`onchain`. It would
  not notice on-chain data written into a new column on `wallet_bindings`, into
  `access_log.detail`, or into a table called anything else.
- **L4 — test 42(b) asserts on the environment, not the code.** It requires
  `status == "not_configured"`, so the suite fails for any developer who has
  `CHAIN_EXPLORER_URL` set — and passes for the wrong reason (no provider) rather
  than because the not-configured branch was exercised deliberately.
- **L5 — the cache key lowercases Solana addresses, contradicting
  `store.normalize_address`.** `backend/chain.py:134` builds
  `f"{chain}:{address.lower()}"`, while `backend/store.py:472` deliberately leaves
  base58 untouched because Solana addresses are case-sensitive. Verified: two
  distinct Solana addresses differing only in case produce an identical cache key.
  Inert today (`_fetch` returns `unsupported_chain` for non-EVM and failures are
  not cached), so this is a mine, not a wound: it becomes one wallet's history
  served for another the day Solana is wired.
- **L6 — the timeline states a cause it cannot know.** `backend/store.py:1039-1041`
  emits `"cancelled during the cooling period"` for any `status == 'cancelled'`
  row. `promote_due` writes that status when a pending row loses the sybil race
  (`backend/store.py:1414-1418`) — reachable when a second identity gets a nonce
  for the address before the first identity's pending row exists, then binds it
  with no incumbent. The case file then reads "this person requested wallet X and
  withdrew" when the truth is "this person requested wallet X and someone else took
  it". An attacker who wins that race writes a false event into a stranger's
  compliance record.
- **L7 — `cached: true` discloses another operator's activity without a log read.**
  The cache is global and keyed on address alone, so the flag at
  `backend/chain.py:137` tells operator B that *somebody* queried that address
  within `CACHE_TTL_SECONDS`. Marginal (operators can read the full log anyway) but
  it is investigative metadata leaking outside the audited path.
- **L8 — the timeline is unbounded.** `identity_timeline` has no `LIMIT` and emits
  up to three events per binding plus one. A user can grow their own
  `wallet_bindings` without bound by cycling request→cancel (each cycle needs one
  signature; trivial via `/api/dev/test-wallet`), so opening that case file becomes
  an arbitrarily large privileged query and response. `identity_full` shares the
  shape; R4 triples the event count on top of it.
- **L9 — NUL bytes from the provider reach the API response.** Verified:
  `{'hash': 'a\x00b', 'counterparty': '0x\x00', ...}`. Harmless to storage (nothing
  on-chain is persisted, which is why this is Low) but it is the exact class
  `_clean_token` at `backend/app.py:727-736` exists to keep out of this service.
- **L10 — the timeline sort inherits a hazard this codebase already documented.**
  `events.sort(key=lambda e: e["at"] or "")` compares ISO strings bytewise, and
  `datetime.isoformat()` omits `.ffffff` when microseconds are zero. `'+'` (0x2B)
  sorts before `'.'` (0x2E), so a whole-second event sorts ahead of a sub-second
  one in the same second. `promote_due` guards exactly this with `COLLATE "C"` and
  a Python re-check (`backend/store.py:1375-1379`); the new sort does not. One in
  10^6, and only within a single second.
- **L11 — docs and boot-time config.** CLAUDE.md still asserts *"No blockchain
  connection anywhere"* and its architecture table has no row for `chain.py`,
  which is now imported unconditionally at `backend/app.py:44`. Separately,
  `CACHE_TTL_SECONDS = int(os.getenv("CHAIN_CACHE_TTL", "300"))` runs at import, so
  a malformed value is a boot crash rather than a config error. (No new dependency
  was added — `httpx` was already pinned for OIDC. Correct.)

---

### Verified safe

Actively attacked and could not break. Do not re-plough these.

**Authorization boundary**
- `/api/operator/timeline` orders correctly: `require_operator` at
  `backend/app.py:940` precedes every `store.*` call, and it logs even when the
  identity does not exist (404 comes after the log). Non-operator with a valid
  session → 403; the log row is still written.
- Route enumeration over `app.app.routes` with `inspect.getsource`, comparing the
  first-authorization-call index to the first-`store.*`-call index across all 30
  routes: `/api/operator/onchain` is the **only** route in the application whose
  store access precedes its authorization. The other flagged routes are the auth
  flows themselves (`/callback`, `/api/passkey/*`), and `/api/me/access-log`
  evaluates `current(request)` as an argument to the store call.
- Operator revocation is immediate on both new routes. `require_operator` calls
  `store.is_operator()` per request with no caching; after
  `revoke_operator`, `/api/operator/timeline` and `/api/operator/onchain` both
  return 403 on an otherwise-live session.
- Passkey-only sessions are refused: `require_operator` checks
  `auth_method != "fayda"` before the role check. (Reachability of C1's oracle by
  such a session is covered by C1, not a separate issue.)
- No R4 data reaches `/api/me`, `/api/registry` or `/config.js`. `/config.js`
  emits only `PRIVY_APP_ID`. `/docs` and `/openapi.json`, which would enumerate the
  two new routes and their request shapes, are `DEV_MODE`-only
  (`backend/app.py:292`).

**Data minimisation**
- `identity_timeline` selects `proof_method` only. Grepped the raw response bodies
  of `/api/operator/timeline` for `fin_hmac`, `proof_sig`, `proof_message`,
  `proof_nonce` — all four absent. `identity_full`'s explicit column list still
  holds under R4.
- No on-chain data is written to Postgres. The only DB work on the `/onchain` path
  is the pre-existing `identity_full` read plus the `access_log` insert.
- `CHAIN_EXPLORER_KEY` does not leak into any response. Error details carry only
  `f"explorer returned HTTP {status}"` or `type(e).__name__` — never the URL, the
  params, or an exception message.
- No stack trace reaches the client on the H2 500 (body is the bare
  `Internal Server Error`).

**SSRF / egress**
- `httpx.get` in 0.28.1 defaults to `follow_redirects=False` (signature confirmed
  in the installed package). A redirecting or compromised explorer cannot pivot
  the fetch to another host or to link-local metadata.
- The operator-controlled `address` cannot smuggle query parameters or alter the
  destination: `params=` percent-encodes, and `looks_like_address` gates EVM input
  to exactly 42 characters starting `0x` before it is used. Tried `&`- and
  `?`-bearing values; all rejected upstream or encoded.

**Hostile response parsing** (ten shapes through the local stub)
- Field truncation is real and per-field: 200k-character values came back as
  `hash` 80, `counterparty` 64, `value_wei` 40, `timestamp` 20, `direction` 2.
- Non-dict entries inside `result` are skipped, not crashed on
  (`[1, "two", null, [3], {...}]` → one transaction, no error).
- A string or dict `result` becomes `provider_error` with a 200-char detail.
- 2000-deep nesting parses without a `RecursionError`; deeper input raises inside
  the `try` and is caught. (It still reaches H2's `AttributeError` because the top
  level is a list — that is H2, not a parsing failure.)

**Cache**
- `cached: true` never accompanies stale-beyond-TTL data. Shortened
  `CACHE_TTL_SECONDS` to 1, slept past it, re-queried with a failing `_fetch`: the
  expired entry was popped and the caller got `cached: false` and the live status.
- Failure statuses are never cached, and a provider blip after a success does not
  evict the good entry (t.py 42(d) is correct about this, and it reproduces).
- Cross-identity cache confusion is not reachable: the key is `chain:address`, and
  the same address resolves to the same public data regardless of which identity's
  case file requested it. Eviction is `min()` over ≤512 entries under
  `_CACHE_LOCK`; both `_cache_get` and `_cache_put` hold it.

**Timeline correctness**
- The `activated_at == requested_at` immediate-bind heuristic is sound *in
  practice*: `create_binding` (`backend/store.py:1296-1298`) writes both from the
  same `t`, so the strings are byte-identical for a first bind, and `promote_due`
  always writes a strictly later `activated_at`. Fragile — it couples a lifecycle
  decision to timestamp-formatting equality — but I could not produce a
  misclassification.
- Full lifecycle (immediate bind → replacement → promotion → archive → replacement
  → cancel) produced exactly seven events, newest first, each naming its wallet,
  with no duplication and nothing omitted. Unknown identity returns `[]`.
- Case variance on the address is handled correctly by the ownership check
  (uppercase and mixed-case spellings of a bound address both resolve via
  `normalize_address`), and the logged `detail` matches the address actually sent
  to the explorer — the operator's own casing, byte for byte, in both places. No
  log/lookup mismatch was reachable.

---

**Verdict: no — not safe to build on.** C1 makes the flagship privacy join
(national identity ↔ wallet address) confirmable by an unauthenticated caller with
no access-log entry, which is the single failure R3 was built to prevent and
invariant #8 forbids in both of its clauses; H1 lets one slow third party stop the
whole service. C1 is a two-line move of `require_operator` above the lookup, and
H2 is a `try` boundary — the design is right and the ordering is wrong. Re-audit
after those move.

---

## Fix review — R3, 2026-07-26 (operator-gated registry, keyset paging, per-result search logging, ALWAYS triggers, Fayda-gated operators, operator tombstones)

**Scope:** only the deltas applied on top of the R3 audit immediately below —
`POST /api/registry` behind `require_operator`, the `auth_method == "fayda"`
check in `require_operator`, the per-result `search_result` entries in
`/api/operator/search`, `find_identities` losing `birthdate`, `identity_full`
moving to explicit columns, the `(at, id)` keyset cursor plus `total` in
`access_log_all` / `access_log_about` and the `?before=` parameters,
`trg_access_log_no_truncate`, the two `ENABLE ALWAYS` statements,
`ix_access_log_at (at COLLATE "C" DESC, id DESC)`, the `operators.revoked_at`
tombstone with logged grant/revoke, and t.py tests 28 and 33-38.

**Method:** re-ran every probe that produced an original finding, plus new ones
aimed at the fixes themselves. Two cautions, because both changed answers
mid-flight. First, **the tree was edited under me**: my first pass read a
`git diff` in which the cursor was `at` alone, and the live code had already
moved to a composite `at|id`. Everything below was therefore re-verified against
a snapshot (`store.py` sha256 `d5797219…`, `app.py` `97f87962…`) and a **fresh
uvicorn booted from it** on `127.0.0.1:8323`. Second, **a t.py run overlapped my
first trigger battery** and its `reset()` produced transient `UndefinedTable`
results plus row-count drift; the entire battery was re-run with one dedicated
`psycopg` connection per probe, explicit rollback, and the trigger catalog
(`pg_trigger.tgenabled`) and row count re-read from a separate connection after
each probe. Routes were enumerated programmatically from `app.app.routes` with
`inspect.getsource` rather than by grep. No code was modified; the probe grants
I created were revoked.

**Counts (new this review): 0 critical / 0 high / 2 medium / 4 low.**
**Prior findings: 6 RESOLVED, 2 PARTIAL, nothing OPEN at High or above.**

---

### Status of the R3 findings

| # | Finding | Status |
|---|---|---|
| High #1 | `/api/registry` unaudited cross-user visibility | **RESOLVED** (residual: new Medium #2) |
| High #2 | `LIMIT 200` eviction from every review surface | **RESOLVED** |
| High #3 | Search logged the query, not who it returned | **RESOLVED** |
| Medium #1 | No Fayda provenance, no freshness for operators | **PARTIAL** |
| Medium #2 | Grant/revoke outside the log; revoke erased the record | **RESOLVED** |
| Medium #3 | `TRUNCATE` and `session_replication_role` bypassed the trigger | **RESOLVED** |
| Medium #4 | Unbounded log, no index on `at`, unrate-limited reader | **PARTIAL** |
| Medium #5 | `fin_hmac` and proof material handed to operators | **RESOLVED** |
| L1 | Reason gate is length-only | **OPEN** |
| L2 | Vacuous "no route grants operator" test | **RESOLVED** |
| L3 | `operators` has no RLS | **OPEN** |
| L4 | `subject_id` is unvalidated free text | **OPEN** |
| L5 | No UI for `/api/me/access-log`; actor is an opaque UUID | **PARTIAL** |
| L6 | `DEMO_MODE` makes the operator role publicly claimable | **OPEN** |
| L7 | `t.py` grants an operator and never revokes it | **OPEN** |
| L8 | `at` sorted without `COLLATE "C"` | **RESOLVED** |

---

#### High #1 — RESOLVED

The endpoint is now `POST`, operator-only, and logged. Verified against the
fresh server:

```
anonymous POST /api/registry            -> 401
non-operator POST /api/registry         -> 403
GET /api/registry (the old unaudited route) -> 405
operator POST /api/registry             -> 200, 1 log row, action=list_registry
```

Route enumeration was redone exhaustively — walking `app.app.routes` and reading
each endpoint's source rather than grepping — and it is now clean. Every route
that can return another identity's data carries `require_operator`:

```
POST /api/operator/search      OPERATOR+LOGGED
POST /api/operator/identity    OPERATOR+LOGGED
POST /api/operator/access-log  OPERATOR+LOGGED
POST /api/registry             OPERATOR+LOGGED
```

Everything else is own-identity or unauthenticated-by-design: `/api/me`,
`/api/me/access-log`, `/api/wallet/{nonce,bind,cancel}`, `/api/passkey/{list,
revoke}` scope to `current(request)`; `/api/passkey/login/{begin,complete}`,
`/login`, `/callback`, `/logout`, `/config.js` are the login surface and return
only the caller's own display name; `/api/dev/*` is dev-gated and own-identity
except `reset`, which is additionally disposable-marker-gated. **The R3
acceptance criterion is met.** The residual is attribution, not authorization —
new Medium #2.

#### High #2 — RESOLVED

The cursor is composite and the ordering, the predicate and the index all agree:

```
_ORDER  = ORDER BY at COLLATE "C" DESC, id DESC
_KEYSET = (at COLLATE "C" < %s OR (at COLLATE "C" = %s AND id < %s))
index   = ix_access_log_at (at COLLATE "C" DESC, id DESC)
```

This is the part I most expected to break and could not. I planted five rows at
one byte-identical timestamp and walked the pager at every page size where the
boundary can fall inside the tie group:

```
planted 5 rows all at at = 2026-07-27T00:05:18.551396+00:00
limit=1: reached 5/5    limit=2: 5/5    limit=3: 5/5    limit=4: 5/5
subject's own view (RLS-scoped), limit=1: total 5, 5 reachable
```

I confirmed the old form really would have lost them — `count(*) WHERE at
COLLATE "C" < <cursor>` returns 0 for the tie group, so an `at`-only cursor
skips all four survivors. `total` is reported and is RLS-correct in the subject
view (counts only that subject's rows). The index is genuinely used: page 1
plans as `Index Scan using ix_access_log_at` with **no Sort node**, which is the
`COLLATE "C"` mismatch the R1 review caught on the sweep indexes, avoided here.

#### High #3 — RESOLVED

```
search "Zzsearchable" -> 1 result,  2 log rows (search + search_result)
search "%"            -> 5 results, 6 log rows
subject's own /api/me/access-log gained exactly 1 entry, action=search_result
result fields: ['id','display_name','verified_at']   birthdate: absent   fin_hmac: absent
zero-result query    -> 1 log row (the query itself is still recorded)
```

Suppression attempts failed. The per-result loop runs before the response is
returned, so a failure mid-loop 500s the request with some subjects already
logged — over-logging, the safe direction. A query matching nothing still writes
the `search` entry, so probing for absence stays visible. `%` no longer buys
un-attributed disclosure: every surfaced person now gets a row naming them.

#### Medium #1 — PARTIAL

Provenance is enforced; freshness is not. Both halves reproduced on one session:

```
auth_method=passkey -> POST /api/operator/identity   403
auth_method=passkey -> POST /api/registry            403
auth_method=fayda, auth_at=2020-01-01 -> POST /api/operator/identity  200
same session        -> POST /api/passkey/register/begin  403 "verify with Fayda again"
```

So the asymmetry is narrowed but inverted rather than closed: a six-year-stale
Fayda session is still too weak to add a passkey and strong enough to read a
stranger's record. A stolen operator cookie retains full compliance powers for
the session's 12 hours. I am not asking for `FRESH_AUTH_SECONDS` on every
lookup — that would make a day of compliance work unusable — but the gap between
the two gates is now a deliberate choice that should be written down, and a
step-up on the bulk routes (`/api/registry`, `%` searches) would cost little.

#### Medium #2 — RESOLVED

```
after revoke_operator -> POST /api/operator/identity   403   (per-request, no caching)
tombstone row: {granted_by: 'audit-r3', revoked: True}       (the row survives)
after re-grant        -> 200,  revoked_at back to NULL
grant + revoke        -> 2 access_log rows (grant_operator, revoke_operator)
```

Authority is now part of the same trail as the lookups. Two residual nits, both
Low and both below: the grant is committed before it is logged, and `actor_id`
carries free text for these two actions.

#### Medium #3 — RESOLVED

Re-run with one isolated connection per probe and the catalog re-read after each.
Both triggers are `tgenabled='A'`. Every non-DDL vector is refused:

```
UPDATE                                        refused (append-only)
DELETE                                        refused (append-only)
TRUNCATE                                      refused (append-only)
TRUNCATE CASCADE                              refused (append-only)
session_replication_role=replica + DELETE     refused (append-only)   <- was the bypass
session_replication_role=replica + UPDATE     refused (append-only)
session_replication_role=replica + TRUNCATE   refused (append-only)
INSERT ... ON CONFLICT DO UPDATE              refused (append-only)
MERGE ... WHEN MATCHED THEN DELETE            refused (append-only)
DELETE / TRUNCATE as fayda_app                refused (InsufficientPrivilege)
fayda_app SET session_replication_role        refused (InsufficientPrivilege)
TRUNCATE identities CASCADE                   succeeded, access_log untouched (no FK path)
```

`MERGE` and `TRUNCATE identities CASCADE` are mine, not in the test suite, and
both hold. Only DDL still gets through — `ALTER TABLE ... DISABLE TRIGGER`
(named, `ALL`, and `USER`), `DROP TRIGGER`, `DROP FUNCTION ... CASCADE`,
`CREATE RULE ... DO INSTEAD NOTHING`, `DROP TABLE` — which is exactly the line
the code comment draws. Worth one sentence in that comment: the `CREATE RULE`
variant is the only bypass that is **silent**, since the `DELETE` reports success
and the rows are gone with no exception raised, whereas every other route leaves
either an error or a visibly altered catalog.

#### Medium #4 — PARTIAL

The index half is fixed and is genuinely effective (see High #2 — `Index Scan`,
no `Sort`). The growth half moved sideways rather than forward:

```
EXPLAIN SELECT count(*) FROM access_log
  Aggregate -> Seq Scan on access_log
```

Both readers now run that unindexed `count(*)` on **every** call, including
`GET /api/me/access-log`, which any authenticated session can hit in a loop with
no rate limit. Previously the cost was one seq-scan-plus-sort of a page; now the
page itself is an index scan but every call additionally counts the whole table,
and under `access_log_about` that count evaluates the RLS policy per row. On a
never-swept table the cost still grows without bound, and it now grows on the
cheapest, least-privileged endpoint.

On the explicit question of deferring retention to R6: **deferring retention is
right and I would not change it** — a log that prunes itself is not an audit log,
and the R3 rationale ("a compromised app cannot quietly erase its own tracks")
argues against a sweeper. But retention and this are different decisions.
Rate-limiting `/api/me/access-log`, or replacing the exact `count(*)` with an
approximate or cached total, needs no retention policy and is what actually
bounds the cost. Note also that reading the log writes to the log
(`read_access_log`), so paging a large log is self-amplifying — bounded and by
design, but it means the table's growth rate is not purely a function of
lookups.

#### Medium #5 — RESOLVED

`identity_full` selects explicit columns and `find_identities` dropped
`birthdate`. Verified over HTTP: the operator record carries
`id, display_name, birthdate, verified_at, last_seen_at, bindings` with no
`fin_hmac`, and bindings carry no `proof_sig` / `proof_message` / `proof_nonce`.
Search results carry `id, display_name, verified_at` only. A future column added
to `identities` can no longer leak in via `*`.

#### L2 — RESOLVED

The replacement walks `app.app.routes` and `inspect.getsource`, so a route
calling `store.grant_operator(...)` now fails it — I re-confirmed the old form
passed that exact case. One limitation worth knowing: it inspects only the
endpoint function's own source, so a route calling a module-level helper that
grants would still slip through. One level deep, not transitive.

#### L5 — PARTIAL

`frontend/src/App.jsx` now fetches `/api/me/access-log` and renders entries and
total, so the control is reachable from the product. The second half stands: the
subject sees `actor_id`, a bare identity UUID, so they learn *that* someone
looked and never *who*.

#### L1, L3, L4, L6, L7 — OPEN, unchanged

`MIN_REASON_CHARS` is still 8 and length-only (`"aaaaaaaa"` passes).
`operators` still has no `ENABLE ROW LEVEL SECURITY` and is still
`GRANT SELECT`-ed to `fayda_app`. `subject_id` is still unvalidated free text.
Nothing refuses an operator grant on a `DEMO_MODE` deploy where any visitor can
claim a persona. `t.py:1046` still grants `me_id` with no teardown (test 38 does
revoke its own `newbie`, but not this one).

---

### New this review

#### Medium #1 (new) — `revoked_at` is never added to an existing `operators` table, so any database that ran the earlier R3 cut breaks on every operator route

**Location:** `backend/store.py:115-125` (the `CREATE TABLE IF NOT EXISTS`),
`backend/store.py:811` (`is_operator`), against
`backend/store.py:490` (the `address_norm` precedent).
**Confidence:** certain — reproduced.
**Invariant strained:** the schema's own in-place-migration rule.

`CREATE TABLE IF NOT EXISTS operators (... revoked_at TEXT)` adds nothing to a
table that already exists, and no `ALTER TABLE operators ADD COLUMN IF NOT
EXISTS revoked_at` was added beside it. Reproduced by simulating the previous
shape inside a rolled-back transaction:

```
simulated old-shape operators: ['identity_id','granted_at','granted_by','note']
after _create_schema():        ['identity_id','granted_at','granted_by','note']
revoked_at restored?  False
is_operator's query:  UndefinedColumn: column "revoked_at" does not exist
```

Every operator route then 500s, and `grant_operator`'s `ON CONFLICT DO UPDATE
SET revoked_at = NULL` fails too — so the fix for Medium #2 is what breaks. It
fails closed (no data is served), which is why this is Medium and not High, but
it is an outage on any database carrying the intermediate schema, and it is
silent until someone tries to use compliance access.

The codebase already solved exactly this, one screen away: `address_norm` is
added by a separate `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` whose comment
says "Adding it separately (rather than in the CREATE TABLE) is what lets a
database created before this change migrate in place." The same two lines are
what `revoked_at` needs. Today's dev database only has the column because
`t.py`'s `reset()` drops and recreates the table.

#### Medium #2 (new) — `/api/registry` discloses every name↔wallet pair under a single `subject_id = NULL` entry; High #3's fix was not applied to its sibling

**Location:** `backend/app.py` (`api_registry` calls `require_operator(...,
"list_registry")` with no `subject_id`), `backend/store.py:1238` (`registry()`
does not select `i.id`).
**Confidence:** certain — reproduced.
**Invariant strained:** R3 claim 4 ("a subject sees who looked at them").

High #3 was raised because search returned N people under one subject-less log
line. That is now fixed for search and left in place on the route that discloses
strictly more — `registry()` returns every bound identity's `display_name`,
`verified_at` and both active wallet addresses, which is the name↔wallet join
itself.

```
operator POST /api/registry -> 200, identities disclosed with ['display_name','verified_at','evm','solana']
log rows written: 1     entry: action=list_registry  subject_id=None
that person's own /api/me/access-log, entries mentioning it: []
```

So an operator wanting the full mapping without notifying anyone now has exactly
one route left, and it is the one that returns the most. The reviewer can still
see "operator X listed the registry at time T for reason R", which is why this is
Medium and not a re-raise of High #1 — but the subject-visibility control is
defeated for the most sensitive field set in the system, and R4 attaches money to
that field set. The fix is the same shape as the search fix: add `i.id` to
`registry()`'s projection and write one `list_registry_result` row per identity
returned.

#### Low (new) — a malformed cursor silently rewinds to page 1 instead of erroring

`backend/store.py:884-888`. `_cursor_parts` returns `None` whenever either half
is empty, and both readers then fall through to the unfiltered branch. Verified:

```
before='garbage'  -> 200, newest page   before='abc|'  -> 200, newest page
before='|'        -> 200, newest page   before='|abc'  -> 200, newest page
before="'; DROP TABLE access_log;--" -> 200, newest page   (no injection; parameterised)
before='9999-99-99|zzz' -> 200, correct (parses, matches everything)
NUL in cursor     -> 400
```

A reviewer or client paging with `while cursor:` and a truncated cursor loops on
the head of the log forever and never reaches the older entries — which is the
same "cannot reach the old entry" outcome High #2 existed to prevent, arrived at
by a different route. A 400 on an unparseable cursor is the right failure.

#### Low (new) — `grant_operator` commits the grant before it logs it

`backend/store.py:817-833`. The `with conn()` block closes (and commits) and
*then* `log_access` is called. Every other path in R3 deliberately logs first and
lets the write fail the operation; this one inverts it, so a `log_access` failure
leaves a granted operator with no record of the grant. `revoke_operator` has the
same shape. Low because the CLI is the only caller and a failure is visible on
the console, but it is the one place the diff's own stated rule is not followed.

#### Low (new) — `actor_id` now carries free text, and the CLI actor is still unidentified

`backend/store.py:830,841`. `log_access(actor_id=granted_by, ...)` writes the
literal `"cli"` (or `"t.py"` under test) into a column that holds identity UUIDs
everywhere else. Confirmed in the live log: `actor=t.py`. A reviewer filtering or
joining on `actor_id` gets a mixed-domain column, and "who ran the CLI" — the
original half of Medium #2 — is still unanswerable.

#### Low (new) — the route-source test is one level deep

`backend/t.py:1055-1064`. See L2 above: it reads each endpoint's own source only.
A granting route that delegates to a helper passes.

---

### Verified safe (re-attacked this round, held)

- **Exhaustive route enumeration** by walking `app.app.routes` with
  `inspect.getsource`: four cross-user routes, all `require_operator`-gated and
  logged; everything else own-identity or login surface. No gap.
- **Keyset paging under exact timestamp ties** at limits 1-4, in both the
  operator view and the RLS-scoped subject view; `total` is honest and
  RLS-correct.
- **The append-only guarantee against every non-DDL vector**, including
  `session_replication_role=replica` for all three verbs, `MERGE ... WHEN
  MATCHED THEN DELETE`, `INSERT ... ON CONFLICT DO UPDATE`, `TRUNCATE CASCADE`,
  and `TRUNCATE identities CASCADE` (no FK path to `access_log`, confirmed).
  `fayda_app` cannot even set `session_replication_role`.
- **Per-request operator revocation** — a revoked operator's live session is
  refused on the next call; re-granting restores it; the tombstone survives both.
- **Search cannot be made to disclose without attribution** — zero-result
  queries still log, `%` logs every surfaced subject, and a mid-loop failure
  over-logs rather than under-logs.
- **Passkey sessions are refused operator powers** on both `/api/operator/*` and
  `/api/registry`.
- **No injection through the cursor** — `before` is parameterised; a SQL payload
  is treated as an unparseable cursor, and a NUL is a 400.
- **R1/R2 untouched**: the three original RLS policies are unchanged, the new
  `FOR SELECT` policy still confines a subject to their own rows, and `reset()`
  still drops both new tables inside the one `CASCADE` statement.

---

### Verdict

All three Highs are genuinely fixed, and two of them — the composite-cursor
paging and the `ENABLE ALWAYS` triggers — are fixed properly rather than
narrowly: I attacked them with cases the test suite does not cover (`MERGE`,
`TRUNCATE ... CASCADE`, four page sizes against a planted timestamp collision,
cascade from a parent table) and they held. The route surface is now exhaustively
accounted for, which was the R3 acceptance criterion.

What is left is smaller and of a different kind. One is an outage waiting on any
database that carried the intermediate schema (`revoked_at` never migrates in
place) — fail-closed, but silent until someone needs compliance access. The other
is that the fix for High #3 was applied to search and not to `/api/registry`,
which discloses more; the reviewer still sees the access, but the subject does
not. Neither blocks R4, and both are small changes.

**Verdict: yes — safe to build R4 on, once the `revoked_at` migration is added.
New criticals: 0, new highs: 0.**

---
## Audit — 2026-07-26 (R3: operator/compliance role + append-only access log)

**Scope:** the uncommitted working tree on top of `5809c04` only — `git diff` of
`backend/app.py` (`require_operator`, `/api/operator/search`,
`/api/operator/identity`, `/api/operator/access-log`, `/api/me/access-log`),
`backend/store.py` (the `operators` and `access_log` tables, the
`access_log_append_only()` trigger, the `p_access_log_subject` policy, the new
GRANT/REVOKE lines, `is_operator` / `grant_operator` / `revoke_operator` /
`log_access` / `access_log_all` / `access_log_about` / `find_identities` /
`get_identity_privileged` / `identity_full`, the extended `reset()` DROP list,
the `grant-operator` and `revoke-operator` CLI), and `backend/t.py` tests 33-36.
R1 and R2 are committed; I re-attacked them only where R3 touches them.

**Method:** read every hunk, then attacked a **fresh uvicorn booted from the
current tree** on `127.0.0.1:8322` (`APP_ENV=dev`, real Supabase dev project) —
the long-running :8000 server has no `--reload` and can serve stale code. Three
personas were signed in through the real Fayda mock flow; one was granted
operator via `store.grant_operator` exactly as the CLI does. Database-layer
claims (the trigger, the policy, the GRANTs) were attacked with raw `psycopg` as
both the connected owner role (`current_user=postgres`, `rolbypassrls=true`) and
as `fayda_app`, with savepoints so destructive probes rolled back. Log
completeness was tested by comparing what each probe *returned* against what
landed in `access_log` and what the subject could then see. Plans were taken
with `EXPLAIN ANALYZE` on the live database. No code was modified; the dev
database carries probe residue (~230 log rows, one `reason` rewritten to prove
Medium #3, and the operator grant `t.py` itself leaves behind). Every grant I
created was revoked.

**Counts (this review): 0 critical / 3 high / 5 medium / 8 low.**

The authorization half of R3 holds, and I want that on the record before the
findings: I could not become an operator through the app, could not read another
identity's record without the role, could not forge, alter or delete a log row,
and could not make a refused request write one. What does not hold is the
**completeness of the trail** — which is the half R4 inherits.

---

### High #1 — `GET /api/registry` returns the identity↔wallet mapping to every authenticated session with no log entry, so an operator just uses it instead of the audited path

**Location:** `backend/app.py:897-907`, `backend/store.py:1238-1266`.
**Confidence:** certain — reproduced.
**Invariant broken:** R3 claim 3 ("nothing cross-user without a log entry") and
the diff's own header comment at `app.py:806-814` ("the only place in the app
where one person can see another's record").

`/api/registry` predates R3 and contradicts both sentences. It requires only
`current(request)` — any session, operator or not — and returns, for every
identity holding an active binding, `display_name`, `verified_at`, and the
active EVM and Solana addresses. It writes nothing to `access_log`. Reproduced
against the fresh server:

```
operator GET /api/registry -> 200
rows returned: 2
[{"display_name": "Tesfaye Bekele", "verified_at": "2026-07-26T23:31:17…",
  "evm": "0x78E814758240D3c4B613289d29E3Ae815A610ae5", "solana": null}, …]
access_log delta: 0             <-- unlogged cross-user read
ordinary (non-operator) user -> 200, same 2 rows
anonymous                    -> 401
```

The attack is one HTTP GET. An operator who wants to know which wallet a named
person controls never touches `/api/operator/*`: `/api/registry` gives the
*name → wallet* join directly, and that join is strictly more sensitive than what
the audited `/api/operator/search` returns — search has no addresses in it at
all. The person is never told, because no row bearing their `subject_id` exists.

This is the residual disclosure the R2 fix review accepted as "by design", and in
R2 it was defensible: every reader was a peer. R3 changes the frame. It creates a
privileged class whose reads are supposed to be accountable and then leaves the
most sensitive cross-user join reachable outside the mechanism — so the audited
path is the *slower* way to do the same thing, which is the one property an audit
trail cannot survive. R4 attaches financial history to exactly this mapping.

Compounding case: under `DEMO_MODE` any visitor clicks a persona and holds a
session, so on the demo deploy this directory is effectively public.

---

### High #2 — an operator cannot delete a log entry, but 210 requests push it out of *every* review surface the product has

**Location:** `backend/store.py:823-842` (`access_log_all(limit=200)`,
`access_log_about(limit=200)`), consumed at `backend/app.py:884` and
`backend/app.py:894`.
**Confidence:** certain — reproduced end to end.
**Invariant broken:** R3 claims 3 and 4. The rows survive; the accountability
does not.

Neither route takes an offset, a cursor, a date range, or returns a total. The
only way to read the log through the application is "the newest 200 rows". Only
operators can write rows, and every write is one cheap POST.

Reproduced: the operator performed one sensitive lookup, confirmed it was visible
in both views, then issued 210 innocuous lookups of the same subject:

```
sensitive lookup -> 200, log row 13deb40f-1cd8-47d7-b71b-7a6e5568b97c
before flooding: operator view (found=True, 16 entries)   subject view (found=True, 6 entries)
flooded 210 innocuous lookups in 294.7s
after  flooding: operator view (found=False, 200 entries) subject view (found=False, 200 entries)
row still in the DB? True          total rows in access_log now: 230
```

The trigger did its job — the row is still there, byte-identical — and that is
what makes this worth reporting rather than dismissing: the storage guarantee is
fully intact while the thing the guarantee exists to provide is gone. Both R3
claims land on it. Claim 3: the entry exists but no product surface can reach it.
Claim 4: the subject's own `/api/me/access-log` is capped identically, and the
flood that buries the entry is aimed at *that same subject*, so it evicts their
view in the same motion.

Five minutes of a shell loop defeats it, from the one role the entire feature
exists to hold accountable. Recovering the buried entry needs direct SQL against
Supabase — precisely the privilege level R3 was built so a reviewer would not
need.

---

### High #3 — `/api/operator/search` discloses up to 25 complete identity rows per call under a single `subject_id = NULL` log line, and `%` matches everyone

**Location:** `backend/app.py:847-854`, `backend/store.py:845-858`.
**Confidence:** certain — reproduced.
**Invariant broken:** R3 claims 3 and 4. The discovery step is structurally
invisible to the people being discovered.

`find_identities` runs `display_name ILIKE '%' || query || '%'` and returns `id`,
`display_name`, `birthdate`, `verified_at`, `last_seen_at` for up to 25 people.
`require_operator` is called with `subject_id=None` and `detail=f"query={q}"`, so
the log records the *search term* and never the *people returned*.

```
query='%'   -> 200  results=8  ['Hiwot Girma','Tesfaye Bekele','Meseret Alemu','Unwatched Person', …]
query='_'   -> 200  results=8  (same)
query='a%b' -> 200  results=2
log line: action=search | detail=query=a%b | subject_id=None
does u1 see the search in their own /api/me/access-log?  []
```

Two distinct problems:

1. `_clean_token` (`app.py:715`) rejects only NUL and length, so LIKE
   metacharacters pass straight into the pattern. This is **not** injection — the
   statement is parameterised — but `query="%"` is a whole-table dump bounded
   only by `limit=25`, and substring paging covers the remainder. Names and
   **birthdates** for the entire registry are reachable in a handful of calls,
   each leaving one uninformative log line.
2. Search is the *discovery* step: the `id` it returns is exactly the input
   `/api/operator/identity` requires. So the phase in which an operator decides
   whom to look at leaves no per-subject trace, and `/api/me/access-log` can
   never show it — rows with `subject_id IS NULL` fall outside its RLS predicate
   by construction, not by oversight.

The gap is real, not theoretical: an operator profiling a list of names learns
name + birthdate + internal id for each, and every one of those people sees
nothing. Logging the returned ids — one row per result, or the id list in
`detail`, which is already 500 chars wide — is what closes it.

---

### Medium #1 — operator access requires no Fayda provenance and no freshness, so a stolen cookie or a passkey-only session carries full compliance powers for 12 hours

**Location:** `backend/app.py:819-821` — `require_operator` calls `current()`,
not `require_fayda_session()`.
**Confidence:** certain — reproduced.
**Invariant strained:** non-negotiable #7 and the cooling-period reasoning
("compromise stays recoverable").

R2 set this project's own rule for a high-consequence action: `app.py:465` gates
passkey registration on `auth_method == "fayda"` **and** an authentication newer
than `FRESH_AUTH_SECONDS` (900s). Reading a stranger's national-identity record
and dumping the entire access log are higher-consequence than adding a
credential, and they inherit neither gate.

Reproduced on one session, downgraded in place to exactly what a passkey
return-login produces (`auth_method="passkey"`, no `auth_at`; cookie untouched):

```
/api/me auth_method now = passkey
POST /api/passkey/register/begin              -> 403 "verify with Fayda again to add a passkey"
POST /api/operator/identity (another person)  -> 200  name: Tesfaye Bekele
POST /api/operator/access-log                 -> 200  (entire log)
```

The same session is judged too weak to add a passkey to its own account and
strong enough to read a stranger's record. An attacker holding a stolen session
cookie — or who has compromised the operator's device passkey — gets the full
surveillance capability for the session's 12 hours without ever facing Fayda, and
the victims cannot be warned because of High #3 (search is subject-less) and High
#2 (volume evicts).

---

### Medium #2 — granting and revoking the operator role happen outside the append-only log, and `revoke_operator` deletes the only evidence the role ever existed

**Location:** `backend/store.py:789-804`; `operators` table at
`backend/store.py:115-120`.
**Confidence:** certain — reproduced.
**Invariant strained:** R3 claim 2 — the log is append-only about the *use* of
the privilege and entirely mutable about the *grant* of it.

`access_log` records who looked at whom. Nothing records **who was permitted to
look**. `grant_operator` writes to `operators` (mutable, no RLS, no trigger) and
`revoke_operator` hard-`DELETE`s the row. Neither writes to `access_log`:

```
access_log rows written by grant + revoke: 0
operators table after grant -> revoke:     []
```

A full grant → look → revoke cycle therefore leaves `access_log` rows pointing at
an `actor_id` with no recorded authority, and no way for a reviewer to establish
that the actor was an operator at the time or when they ceased to be one.
`granted_at` and `granted_by` vanish with the row, and `granted_by` is in any case
the hardcoded literal `"cli"` (`store.py:1288`), which identifies nobody.
`ON CONFLICT DO NOTHING` in `grant_operator` also means a re-grant silently keeps
the original `granted_at`/`note`.

`operators` is likewise the natural target for anyone who reaches the database:
adding yourself is a single INSERT that leaves no trace anywhere.

---

### Medium #3 — the append-only trigger is row-level only: `TRUNCATE` and `session_replication_role = replica` both get through, as the very role the trigger was written to constrain

**Location:** `backend/store.py:238-258`.
**Confidence:** certain — every line below was executed against the live
database (destructive probes inside savepoints, rolled back).
**Invariant strained:** R3 claim 2 and the comment's own words — "This raises for
every caller, owner included."

The first clause of that comment is true, the second is not. As the connected
role (`postgres`, `rolbypassrls=true`, and the table's owner):

```
UPDATE as owner                            [refused ] RaiseException: access_log is append-only; UPDATE is not permitted
DELETE as owner                            [refused ] RaiseException: access_log is append-only; DELETE is not permitted
INSERT … ON CONFLICT (id) DO UPDATE        [refused ] RaiseException: … UPDATE is not permitted
UPDATE/DELETE/TRUNCATE as fayda_app        [refused ] InsufficientPrivilege
ALTER TABLE … DISABLE TRIGGER (owner)      [SUCCEEDED] -> UPDATE then set reason='covered up'
SET LOCAL session_replication_role=replica [SUCCEEDED] -> UPDATE then set reason='replica-rewrite'
TRUNCATE access_log (owner)                [SUCCEEDED] 230 rows -> 0 in-txn
DROP TABLE access_log CASCADE (owner)      [SUCCEEDED]
```

`ALTER TABLE … DISABLE TRIGGER` is acknowledged in the comment and is a fair
stated limit. The other two are not acknowledged and are materially cheaper:

- **`TRUNCATE` does not fire `FOR EACH ROW` triggers.** One statement, no DDL, no
  catalog change, and the entire audit trail is gone. A
  `BEFORE TRUNCATE … FOR EACH STATEMENT` trigger closes it in three lines.
- **`SET session_replication_role = replica`** suppresses non-`ALWAYS` triggers
  for the session. It is a plain `SET`, needs no DDL, and reverts at commit — the
  tidiest possible erasure. `ALTER TABLE … ENABLE ALWAYS TRIGGER` closes it.

Also worth stating: `reset()` (`store.py:648-651`) legitimately `DROP`s
`access_log`. That path is correctly gated on `APP_ENV=dev` *and* the disposable
marker, but it means the schema's own recreation path is a supported way to erase
the log — one more reason the storage guarantee should not be treated as
absolute. Not reachable through any HTTP route today (nothing runs
attacker-controlled SQL), which is why this is Medium and not High. It is a gap
in exactly the defence-in-depth the diff claims to have built.

---

### Medium #4 — `access_log` grows without bound and is never swept, and both read paths seq-scan and sort it; `/api/me/access-log` hands that cost to every authenticated user with no rate limit

**Location:** `backend/store.py:823-842`, `backend/app.py:887-894`; index
definitions at `backend/store.py:138-139`.
**Confidence:** certain — `EXPLAIN ANALYZE` on the live database.
**Invariant strained:** the DoS posture, and the project's own lesson at
`store.py:175-177` ("the defence gets more expensive the more it is needed").

`sweep_expired` (`store.py:752`) covers `sessions` and `auth_nonces`.
`access_log` is deliberately never pruned — correct for an audit log — but it was
given indexes on `subject_id` and `actor_id` and **none on `at`**, which is the
column both queries order by:

```
indexes: access_log_pkey(id), ix_access_log_subject(subject_id), ix_access_log_actor(actor_id)

SELECT * FROM access_log ORDER BY at DESC LIMIT 200
  Limit -> Sort (Sort Key: at DESC) -> Seq Scan on access_log

SELECT at, actor_id, action, reason FROM access_log ORDER BY at DESC LIMIT 200    [as fayda_app]
  Limit -> Sort (Sort Key: at DESC) -> Seq Scan on access_log
             Filter: (subject_id = NULLIF(current_setting('app.identity_id', true), ''))
             Rows Removed by Filter: 12
```

Both plans read and sort the whole table; the subject query does not even use
`ix_access_log_subject`. `/api/me/access-log` is a `GET` reachable by **any**
authenticated session (in `DEMO_MODE`, by any visitor who clicks a persona), it
is unrate-limited, and its cost grows monotonically with the size of the audit
trail forever. Same shape as the R1 finding that produced `ix_sessions_expires` /
`ix_auth_nonces_expires`, now applied to the one table that by design can never
be trimmed. An index on `at` (in the collation the query actually uses — see L8)
fixes the sort; `(subject_id, at)` would serve the subject path.

---

### Medium #5 — the operator view hands over another person's `fin_hmac`, the exact field `registry()` withholds by name, plus the full proof material

**Location:** `backend/store.py:872-885` (`identity_full` uses `SELECT *` on both
tables), returned verbatim at `backend/app.py:875`.
**Confidence:** certain — reproduced.
**Invariant strained:** not #1 — the raw FIN is still nowhere, and a user already
receives their *own* `fin_hmac` via `/api/me`. R3 is the first place one person
receives *another* person's.

```
identity keys: ['id','fin_hmac','display_name','birthdate','verified_at','last_seen_at','bindings']
fin_hmac present: True = 3f51d4a1416f30a318a48288…
binding keys:  [… 'proof_nonce','proof_sig','proof_message','proof_method','address_norm']
```

`registry()`'s docstring (`store.py:1240-1245`) states the rule this breaks:
"fin_hmac is deliberately absent — it cannot re-derive the FIN, but it is a
stable pseudonymous key that lets any reader correlate one person across every
row". That is the join key that survives name changes and lets an operator
correlate this registry against any other dataset derived from the same pepper —
including R4's transaction history. A compliance operator has no use for it.

`SELECT *` is also why this happened and why it will keep happening: any column a
future migration adds to `identities` or `wallet_bindings` is disclosed to
operators automatically, with no diff to review. `registry()` enumerates its
columns for exactly that reason; the operator path should too.

---

### Low

**L1 — the reason gate is a length check, so `"aaaaaaaa"` is a valid audit
justification.** `app.py:816-834`. Reproduced: `reason="aaaaaaaa"` → 200,
`reason="........"` → 200, a multi-line reason is stored verbatim. The comment
calls this "the difference between an audit trail and a hit counter", and test 34
(`t.py:1044-1048`) probes only `""`, `"   "` and `"why"` — all of which fail on
length alone, so the test cannot distinguish a real justification from eight dots.
Not a security boundary; the finding is that the trail's usefulness rests
entirely on operator goodwill and neither the code nor the test says so. A
structured `case_ref` would be the honest version.

**L2 — test 33's "no HTTP route grants operator" assertion cannot fail for the
case it names.** `t.py:1034`:
`assert "grant_operator" not in routes.replace("store.grant_operator", "")`. It
strips the exact substring a real granting route would contain. Verified by
appending a hypothetical `@app.post("/api/admin/grant")` handler calling
`store.grant_operator(...)` to the source in memory: the assertion still passes.
It can only catch a bare `grant_operator(` with no `store.` prefix. Against
"a test that cannot fail is not a test" (CLAUDE.md conventions). The property
itself does hold — I enumerated every `store.*` call site in `app.py` by hand —
which is what the test should do instead.

**L3 — `operators` is the only table in the schema with no RLS, and `fayda_app`
can read it.** `store.py:259` grants `SELECT ON operators`, and no
`ALTER TABLE operators ENABLE ROW LEVEL SECURITY` is ever issued (confirmed:
`relrowsecurity=false` in `pg_class`). Reproduced: under `user_conn(u1)` the
unprivileged role read the entire operator roster. No current query does this, so
it is latent — but every other table gained RLS precisely so a forgotten `WHERE`
could not leak, and the roster of who may surveil is not an obvious exception.
Writes are correctly refused (`InsufficientPrivilege` on INSERT and DELETE).

**L4 — `subject_id` is unvalidated free text, so an operator can seed the
permanent log with fabricated subjects.** `app.py:864-871` checks length ≤ 64 and
NUL only. Reproduced: `identity_id="../../etc/passwd"` → 404 to the caller and a
permanent `access_log` row with `subject_id='../../etc/passwd'`. Logging
non-existent subjects is deliberate and right (probing should be visible); the
gap is that the column is never reconciled against `identities`, so the log can
be filled with noise nobody can remove — the flip side of append-only.

**L5 — `/api/me/access-log` has no UI, and shows an opaque UUID where a name
belongs.** Nothing under `frontend/src/` references `operator` or `access-log`.
The countervailing control that justifies the whole feature ships as an endpoint
unreachable from the product, and when reached it returns `actor_id` — a bare
identity UUID — so a subject learns *that* someone looked, never *who*. It is
also the first place an ordinary user is handed another identity's internal id,
which `registry()` refuses to do by name (`store.py:1263-1266`: "it is the RLS
scoping key … it does not belong in a list handed to other users"). Not
exploitable — RLS binds from the session, never from client input, and I
confirmed a supplied id grants nothing — but it is the same principle decided
both ways inside one diff.

**L6 — on a `DEMO_MODE` deploy the operator role is publicly claimable.**
Identity there is whichever persona button the visitor clicks
(`mock_esignet.py:248-258` matches the posted `fin` against `PERSONAS`), so
granting operator to a persona identity — the obvious way to demo R3 — hands
compliance powers to every visitor. `grant_operator` has no equivalent of
`mark_disposable`'s target check and no `DEMO_MODE` refusal. Worth a guard
before R3 is ever demoed.

**L7 — `t.py` grants an operator and never revokes it.** `t.py:1027` grants to the
first persona's identity with no teardown; the dev database still carried
`granted_by='t.py'` when I finished. Self-limiting only because test 32's
`reset()` drops the table on the next run. A suite that leaves a live privilege
behind on the database it ran against is not the pattern R4 should copy.

**L8 — `at` is TEXT sorted without `COLLATE "C"`, against this codebase's own
hard-won precedent.** `store.py:827,840`. `promote_due` and `sweep_expired` both
carry comments explaining that the default collation does not order ISO-8601
chronologically below one second. The new queries omit it. Checked on live data
(`datcollate=en_US.UTF-8`): default and `COLLATE "C"` produced identical order
over 230 rows, and every timestamp carried microseconds, so there is no live
defect. The latent one: `datetime.isoformat()` drops the microsecond field when
it is exactly zero (~1 in 10^6 writes), and `'+'` (0x2B) sorts before `'.'`
(0x2E), so such a row sorts fractionally out of position — invisible except at
the `LIMIT 200` boundary, which High #2 already makes load-bearing.

---

### Verified safe (actively attacked, held)

These are what I tried hardest to break and could not. Next run should spend its
budget elsewhere.

- **Nobody becomes an operator through the app.** Enumerated every `store.*` call
  site in `app.py`: `is_operator`, `log_access`, `find_identities`,
  `identity_full`, `access_log_all`, `access_log_about` — no grant path, no write
  to `operators`, no route accepting an identity id for privilege, nothing
  reachable over HTTP that mutates membership. The property holds; only the test
  of it is vacuous (L2).
- **Non-operators and anonymous callers get nothing, and cost nothing.** All
  three operator routes returned 403 to an ordinary authenticated session and 401
  to an anonymous one; four sub-threshold reasons returned 400. Across all eight
  refusals `access_log` grew by **0 rows** — outsiders cannot flood the audit
  table, and a refused lookup leaves no trace claiming it happened.
- **Revocation takes effect immediately on a live session.** `is_operator` is
  queried per request: after `revoke_operator` the same cookie got 403 on the
  next call, and 200 again after re-granting. No caching, no role carried in the
  session.
- **`fayda_app` cannot touch the log or the roster.** `UPDATE`, `DELETE` and
  `TRUNCATE` on `access_log`, and `INSERT`/`DELETE` on `operators`, all returned
  `InsufficientPrivilege`. The `REVOKE` is real, not decorative.
- **The trigger blocks every row-level rewrite as the owner**, including the
  `INSERT … ON CONFLICT (id) DO UPDATE` smuggling route, and the target row was
  byte-identical afterwards. (Its limits are Medium #3.)
- **RLS on `access_log` is real and fails closed.** Under `user_conn(u1)` with no
  `WHERE` clause at all, the user saw 5 of 10 rows — only rows whose `subject_id`
  was their own. A user's attempt to INSERT a forged entry naming a different
  `actor_id` was refused: *"new row violates row-level security policy for table
  access_log"*. One user cannot read another's entries and cannot fabricate their
  own. The `FOR SELECT` policy plus RLS default-deny is doing the work.
- **Log-before-read ordering is correct, and its failure direction is safe.**
  `log_access` runs in its own transaction and commits before `require_operator`
  returns; the handler reads afterwards on a separate connection. There is no
  interleaving in which data is returned and the row is rolled back. The only
  reachable failure is the opposite — an entry for an access that then 500s —
  which over-logs rather than under-logs. No attacker-controlled input can make
  `log_access` fail: `reason` is length- and NUL-checked before the write and
  `detail` is app-constructed.
- **Concurrency does not lose entries.** 20 simultaneous `/api/operator/identity`
  calls returned 20 records and wrote exactly 20 log rows in 64.8s, no 500s and
  no pool exhaustion, despite three sequential pool checkouts per request
  (`is_operator`, `log_access`, `identity_full`) against `max_size=12`.
- **R1/R2 were not regressed.** The new `FOR SELECT` policy lives on a new table
  and does not interact with the existing `FOR ALL` policies; `p_identities_own`,
  `p_bindings_own` and `p_credentials_own` are unchanged and still
  `nullif`-guarded. `reset()`'s DROP list now covers `access_log` and `operators`
  in the same single `CASCADE` statement, so no foreign key is silently lost (the
  R2 Medium #2 failure mode), and the disposable-marker gate is untouched.
- **No cross-origin read of operator responses.** No CORS middleware is
  registered anywhere in `app.py`; the cookie is `SameSite=Lax` and all three
  operator routes are `POST`.
- **The SPA catch-all neither shadows nor exposes the new routes** — not
  registered in dev at all, and outside dev it 404s everything under `api/`
  before touching the filesystem.
- **`at` ordering is correct on live data** — default (`en_US.UTF-8`) and
  `COLLATE "C"` produced identical orderings over 230 rows (latent caveat: L8).
- **Every other route was checked for cross-user reach and is genuinely
  per-identity.** `/api/me`, `/api/wallet/{nonce,bind,cancel}`, `/api/passkey/*`,
  `/api/dev/fast-forward` and `/api/dev/test-wallet` all scope to
  `current(request)`. `/api/dev/reset` destroys everyone's data but is dev-gated
  *and* disposable-marker-gated. `store.credential_by_id` on the passkey login
  path is cross-identity by necessity (R2, unchanged). `/api/registry` is the
  sole exception, and it is High #1.

---

### Verdict

The boundary R3 set out to build is sound. Membership is genuinely out of band,
the check is enforced on every operator route and re-read per request, the
database refuses to let anyone rewrite or forge a row, and one user cannot see
another's entries. If the question were only "can someone read a record they
should not", the answer is no, and the RLS work carried over from R2 is why.

But R3's stated purpose is that *nothing cross-user happens without a trace*, and
three things break that, all reproduced. An unlogged route returns the same
identity↔wallet mapping to anyone holding a session. Search discloses up to 25
people per call while recording none of them. And 210 cheap requests evict any
entry from both the operator's and the subject's only view of the log. Each is
individually trivial to execute, and together they mean an operator who wants to
look at someone unobserved has more than one way to do it — while the honest
operator's lookups are the ones that show up. R4 hangs financial history off this
exact boundary, so the trail has to be complete before it is built on, not after.

**Verdict: no — not safe to build R4 on as it stands. New criticals: 0, new
highs: 3.**

---

## Fix review — R2, 2026-07-26 (Fayda-gated registration, passkey revoke, `nullif` policies, reset FK, registry minimised, UV at registration, `_json_body`)

**Scope:** only the deltas applied on top of the R2 audit immediately below —
`require_fayda_session` and the explicit `auth_method` write in `/callback`,
`POST /api/passkey/revoke` + `store.delete_credential`, the `nullif(...,'')`
policy predicates, `webauthn_credentials` in `reset()`'s DROP list, the
`registry()` projection and `WHERE EXISTS` filter,
`require_user_verification=True`, `_json_body` + the `credential`/`label` type
checks, `cryptography==49.0.0`, and the frontend passkey list/revoke UI.

**Method:** re-ran every probe that produced an original finding, plus new ones
aimed at the fixes themselves. Two cautions about this run, because they changed
answers mid-flight: the file was edited under me (my first pass caught an
earlier cut of `require_fayda_session` that used a `"fayda"` default and did not
write `auth_method` in `/callback`), and the long-running dev server on :8000 is
started without `--reload`, so it can serve stale code. Everything reported
below was therefore re-verified against a **fresh uvicorn booted from the
current tree** on :8222 with `BASE_URL`/`PUBLIC_URL` pinned to it. RLS was
re-checked against the live catalog and with raw `psycopg` connections in both
the virgin (GUC never set) and reused (GUC `''`) states. Dependency resolution
was re-run with `--ignore-installed`. No code was modified.

**Counts (new this review): 0 critical / 0 high / 1 medium / 2 low.**
**Prior findings: 6 RESOLVED, 1 PARTIAL, nothing OPEN at High or above.**

---

### Status of the R2 findings

| # | Finding | Status |
|---|---|---|
| High 1 | Unrevokable passkey persistence | **PARTIAL** |
| High 2 | `requirements.txt` unresolvable | **RESOLVED** |
| Medium 1 | RLS not fail-closed on `WITH CHECK` | **RESOLVED** |
| Medium 2 | `reset()` orphans credentials, drops FK | **RESOLVED** |
| Medium 3 | Registry disclosure | **RESOLVED** (residual by design) |
| Medium 4 | UV not enforced at registration | **RESOLVED** |
| Medium 5 | Unauthenticated 500s | **RESOLVED** |

---

#### High 1 — PARTIAL

*Resolved half.* Everything the fix set out to do, it does:

```
passkey session -> /api/passkey/register/begin      403
passkey session -> /api/passkey/register/complete   403
legacy session (auth_method key deleted from the row) -> 403, /api/me reports "unknown"
legacy session -> /api/passkey/revoke               404 (reachable, correctly ungated)
Fayda re-login in place -> auth_method "fayda", register/begin 200
owner revokes own key -> 200, revoked key then fails login (400)
another identity revokes it -> 404, key still present
```

`auth_method` is not client-forgeable: the session lives in the `sessions`
table and the cookie is `sid.HMAC` only; a forged cookie reads as
unauthenticated, and a header or body field named `auth_method` changes nothing
(403 either way). The default direction is right, and better than the cut I
first tested — `app.py:396` now writes `auth_method = "fayda"` explicitly in
`/callback` and `app.py:447` uses a bare `get("auth_method") != "fayda"`, so a
session predating the change is *denied* rather than trusted. Fail-closed, and I
confirmed it by deleting the key from a live session row. The comment's claim
that a security gate should not rest on a default is correct and is now
honoured. I also confirmed the remedy the 403 message prescribes works **in
place**, no logout required, by tracing the session row through
`/login → /authorize → confirm → /callback` and watching `auth_method` flip from
`passkey` to `fayda` at the callback.

*Residual.* The gate is on how the session was **created**, not on who is
holding it now — and a stolen cookie is, by construction, a session Fayda
created. The original attack's first three steps are untouched. Re-verified
against the current tree:

```
victim auth_method: fayda
attacker (victim's cookie) register/begin      -> 200
attacker register/complete, label "iPhone"     -> 200
victim POST /logout
attacker /api/passkey/login/complete           -> 200, back in as Meseret Alemu
what the victim then sees: [('iPhone', '2026-07-26T21:46:03')]
```

What changed is the *ending*, and that matters: the credential is now listed in
the UI with label, created and last-used, and one click removes it. That was one
of the two remedies I named, and it converts "permanent and unrevokable" into
"visible and reversible". It is why this is PARTIAL rather than OPEN.

Two things keep it from RESOLVED. First, nothing signals that a passkey was
added — no notification, no `/api/me` flag, no audit line; the victim has to go
looking. Second, `label` is entirely attacker-supplied (I registered one called
"iPhone"), so the only field distinguishing an attacker's key from the victim's
own is `created_at`. Someone with three devices will not reliably spot a fourth.
Closing this properly means either a step-up — re-run Fayda *at the moment of
registration*, not merely "this session once came from Fayda" — or an
out-of-band signal when a credential is added.

*Other persistence paths, checked and clear.* A nonce issued by the attacker
does not survive logout in any useful form: `/api/wallet/bind` still requires a
session and returns 401 without one. `/logout` deletes the session row, so a
shared cookie dies with it. A pending binding does survive, but that is the
cooling period working as designed — it is exactly the window the victim cancels
in. A passkey session retains full wallet powers (`/api/wallet/nonce` 200),
which is a deliberate choice covered by that same cooling period.

#### High 2 — RESOLVED

`cryptography==49.0.0` (`requirements.txt:8`) with a comment naming the floor.
Re-resolved from scratch, not against the local venv:

```
python -m pip install --dry-run --ignore-installed -r backend/requirements.txt
Would install ... cryptography-49.0.0 ... webauthn-3.0.0 ...   (no ResolutionImpossible)
```

Crypto re-verified under 49.0.0 through the app's own code paths, not by version
inspection: EVM sign → `vf.verify` True, wrong address rejected, tampered
message rejected; Solana ed25519 verify True, tampered rejected; the RS256
client assertion round-trips through `mock_esignet.generate_client_keypair` and
a wrong key raises `InvalidSignatureError`. As expected — `eth-account` reaches
secp256k1 through `eth-keys` and `PyNaCl` goes through libsodium; neither
touches `cryptography`.

#### Medium 1 — RESOLVED

The catalog now reads
`(id = NULLIF(current_setting('app.identity_id'::text, true), ''::text))` on all
three policies, `USING` and `WITH CHECK`. Verified in both connection states,
read and write:

```
virgin connection (current_setting -> None):  READ 0 rows;  INSERT id=''  -> InsufficientPrivilege
reused connection (current_setting -> ''):    READ 0 rows on identities / wallet_bindings /
                                              webauthn_credentials;  INSERT identity=''
                                              -> InsufficientPrivilege on all three
GUC explicitly set to '':                     READ 0 rows;  INSERT -> InsufficientPrivilege
properly bound:                               A sees only A;  cross-identity INSERT
                                              -> InsufficientPrivilege
```

The exact write that succeeded in the original finding now fails. Fail-closed on
both sides, on a fresh connection and a recycled one.

#### Medium 2 — RESOLVED

`webauthn_credentials` is in the DROP list (`store.py:580-582`) with a comment
naming the CASCADE / `IF NOT EXISTS` interaction that caused it. Live catalog
after the change: `webauthn_credentials_identity_id_fkey` present, orphan count
0. The 8 orphans my original run produced are gone.

#### Medium 3 — RESOLVED, with a residual I agree can stay documented

`registry()` returns `['display_name', 'evm', 'solana', 'verified_at']` — no
`id`, no `fin_hmac` — and the `WHERE EXISTS` filter behaves correctly across the
tiers. Built four identities and checked each:

```
HAS-ACTIVE      listed  (expected)
PENDING-ONLY    absent  (expected — nothing to disclose yet)
ARCHIVED-ONLY   absent  (expected)
NO-WALLET       absent  (expected)
```

Both halves of my objection are gone: the RLS scoping key is no longer handed to
readers, and people who completed Fayda but bound nothing are no longer
disclosed at all.

*On the DEMO_MODE question asked directly: I agree, documentation is enough.* A
public demo IdP whose whole purpose is "click a persona, be signed in" cannot
also be an authentication gate, and the rows behind it are fictional. What is
worth writing down is the invariant that makes it safe — **DEMO_MODE and real
Fayda credentials must never be set on the same deploy** — because nothing in the
code enforces it, and the day someone points `FAYDA_AUTHORIZE_URL` at production
while `DEMO_MODE=1` is still in `render.yaml`, the registry is one click from
public again. A startup refusal (`DEMO_MODE=1` together with any `FAYDA_*_URL`
override → refuse to boot) would make it structural rather than remembered, and
it is the same shape as the existing secrets guard.

The standing design note from the original finding remains true and remains a
judgement call, not a defect: the endpoint is a *list*, so any signed-in user can
enumerate every bound person's name against their wallet addresses in one
request. A *lookup* — "is this address claimed, and by whom" — answers the
product question without enabling bulk correlation. Worth revisiting when the
registry holds real identities rather than four personas.

#### Medium 4 — RESOLVED

`require_user_verification=True` at `app.py:474`. A registration whose
authenticator data clears the UV flag is now rejected —
`400 {"detail":"passkey registration failed"}` — where it previously returned 200
and stored a credential that could never be used.

#### Medium 5 — RESOLVED

`_json_body` plus the `credential` / `label` type checks close every path I
found, and `label` now goes through the file's own `_clean_token`. Sixteen
malformed bodies across all three endpoints, zero 5xx:

```
login/complete:    not-json | [1,2] | "hello" | 5           -> 400 expected a JSON object
                   {"credential": "nope" | {"id":12345} | null}
                                                            -> 400 malformed credential
register/complete: not-json | [1,2]                         -> 400 expected a JSON object
                   label with NUL | 900 chars | a dict      -> 400 malformed label
revoke:            not-json | [1,2] | id as int | missing   -> 400
```

The NUL label that produced a 500 in the original finding is now a clean 400.
This also closes original **Low 3** (an unhandled 500 leaving the challenge
unconsumed) as a side effect: with no unhandled path left, every failure runs
through the response wrapper and burns the challenge.

---

### New this review

#### Medium (new) — revoking a passkey does not terminate the sessions it established

**Location:** `backend/app.py:466-483` (`passkey_revoke`) and
`store.delete_credential`; nothing touches the `sessions` table.
**Confidence:** certain — reproduced against the current tree.
**Invariant strained:** the endpoint's own docstring — *"The escape hatch... a
passkey registered by an attacker holding a live session would outlive the
victim's logout with nothing the victim could do"* — and, behind it, CLAUDE.md's
requirement that a compromise stay recoverable.

```
attacker signs in with the key                -> 200
victim revokes that credential                -> 200
attacker's existing session /api/me           -> authenticated: True, auth_method: passkey
attacker still acts: /api/wallet/nonce        -> 200
attacker cannot sign in again                 -> 400
```

Revocation removes the *future* login and leaves the *present* one running for
the remainder of `SESSION_TTL_HOURS` (12). The victim performs the documented
remedy, the UI says "That device can no longer sign in", and the attacker keeps
working for up to half a day — long enough to start a wallet swap, which then
costs the victim another 72-hour cancel race. Same class of gap as the original
High 1, one layer in: the escape hatch is not quite an escape.

The fix is small and local. There is no link from a session row to the
credential that created it today, so it needs either a `credential_id` recorded
in the session at `passkey_login_complete` (then delete matching rows on
revoke), or the blunter and arguably better "revoke signs this identity out
everywhere" — which is what users expect from a revoke button and what most
passkey implementations do. Either way it should be what the UI copy promises.

#### Low (new) — a stolen session can revoke the victim's own passkeys

`/api/passkey/revoke` is gated on `current()` alone, deliberately and correctly:
a passkey session must be able to revoke. The consequence is that an attacker
holding a live session can, in one visit, delete the victim's keys and register
their own, leaving a list that looks untouched in count. Impact is bounded —
Fayda is the root authority and always restores access, so this is denial of a
convenience, not of the account. Worth knowing that `revoke` is not a privileged
operation the way `register` now is.

#### Low (new) — `cbor2` and `pyOpenSSL` remain unpinned

Both are hard requirements of `webauthn`, and `backend/t.py` now imports `cbor2`
directly (test 29's software authenticator) without it appearing in
`requirements.txt`. A fresh environment gets whatever pip resolves. Small, but
this is a file whose first line is "Versions as tested."

---

### Carried forward from the original review, unchanged

- **Low 1** (`RESET ROLE` escapes the role from inside a `user_conn` block) — OPEN.
  Still no injection surface; still a caveat on the "the filter is the
  database's" claim.
- **Low 2** (one `passkey_challenge` session key for both ceremonies) — OPEN.
  Re-verified: a challenge minted by `/login/begin` still completes a
  registration (200). No escalation — `clientData.type` still binds the ceremony
  — but the two flows still clobber each other.
- **Low 4** (no cap on credentials per identity) — PARTIAL. Still uncapped, but a
  user can now remove them, which was most of the concern.
- **Low 5** (`/api/passkey/login/begin` mints unauthenticated session rows; no
  rate limit anywhere) — OPEN.
- **Low 6** (`RP_ID` from `urlparse(PUBLIC).hostname`, no startup guard against an
  IP literal or a `PUBLIC` carrying a path) — OPEN. Both still fail closed.
- **Low 7** (`touch_credential` privileged though `identity_id` is in hand) — OPEN.
- **Low 8** (registry disclosed the internal identity UUID) — RESOLVED by
  Medium 3's fix.
- **Low 9** (`credential_id` and the `navigator.platform` label in `/api/me`) —
  now justified rather than open: the revoke UI needs both.

---

### Verdict

**Yes — safe to build on. New criticals: 0, new highs: 0.**

Both blockers are genuinely gone: the tree builds from a clean environment, and
the passkey is no longer a one-way door. The RLS fix is the strongest of the
set — fail-closed on the write side as well as the read side, verified in both
the virgin and recycled connection states, with the exact write that succeeded
before now refused. What is left is one Medium of the same shape as the original
High, one layer in (revocation cuts off the next login but not the current
session), plus the residual that a stolen Fayda session can still mint a passkey
the victim must notice in order to remove. Neither blocks further work; both
should close before this carries real Fayda identities rather than four
personas.

---

## Audit — 2026-07-26 (R2: Postgres RLS, WebAuthn passkey return-login, de-publicised registry)

**Scope:** the uncommitted working tree on top of `d858953` only — `git diff` of
`backend/app.py`, `backend/store.py`, `backend/requirements.txt`, `backend/t.py`,
`frontend/src/App.jsx`, `frontend/src/components/{IdentityRecord,VerifyGate}.jsx`,
plus the new untracked `frontend/src/passkey.js`. R1 (Supabase Postgres) is HEAD
and was re-attacked only where R2 changed its behaviour (the `FOR UPDATE` paths
that now run as a different role, and `reset()`).

**Method:** read every hunk first, then attacked. Against the live dev Supabase
project I probed the catalog directly (`pg_roles`, `pg_class.relrowsecurity`,
`pg_policies`, `information_schema.role_table_grants`, `pg_constraint`) rather
than trusting the DDL string; drove `store.user_conn` by hand with unfiltered
`SELECT`s, a deliberate mid-transaction exception, and role/GUC re-reads across
three subsequent pool checkouts; and tried to escape the role from inside a
scoped transaction. Against the dev server on 127.0.0.1:8000 I built an ES256
software authenticator (real CBOR/COSE, real client-data and authenticator-data
byte layouts, real signatures, controllable UV flag and sign counter) and ran
registration and assertion ceremonies with the flags, challenges, sessions,
origins and body shapes deliberately wrong. I booted a second instance on :8111
in the *shipped* posture (`APP_ENV=production DEMO_MODE=1`, secrets supplied) to
test the registry gate and the dev surface as they will actually exist on
Render. Dependency resolvability was checked with a real `pip install --dry-run
--ignore-installed`. No code was modified. No credential was printed.

*Database side effects of this run, on the throwaway dev project only:* probing
`/api/dev/reset` through a passkey session wiped the dev registry (it is marked
disposable and `t.py` wipes it on every run anyway) — that wipe is itself
evidence for Medium #2 below. Probe identities and 8 passkey rows remain. One
`identities` row with `id = ''` was created to demonstrate Medium #1 and was
deleted immediately afterwards; the table was re-counted to confirm.

**Counts (this review): 0 critical / 2 high / 5 medium / 9 low.**

> **Superseded.** All seven of these were addressed; see the fix review
> above for per-finding RESOLVED/PARTIAL status and re-verification evidence.
> High 1 is PARTIAL; everything else at Medium and above is RESOLVED.

The RLS is **not** theatre. `SET LOCAL ROLE` really does take effect (psycopg is
not in autocommit, so the `set_config` starts a real transaction), the role is
`NOBYPASSRLS`, an unfiltered `SELECT` sees exactly one identity, and neither the
role nor the GUC survives a pool checkout — including after an exception thrown
mid-transaction. What it does *not* do is what its own comment claims about the
unset case, and the deliberate privileged/unscoped list is defensible except for
one entry. Details below.

---

### High #1 — a passkey turns a temporary session compromise into permanent, unrevokable control of a Fayda identity

**Location:** `backend/app.py:427-456` (`/api/passkey/register/begin`),
`:459-485` (`/register/complete`), `:506-555` (`/login/complete`); no delete
route exists anywhere in the file (`grep -n "@app\." backend/app.py` lists 21
routes; none removes a credential).
**Confidence:** certain — every step reproduced end to end against the running
server.
**Invariant broken:** CLAUDE.md, *"Cooling period exists for session compromise,
not user convenience. If an attacker with a live session swaps the wallet, the
real user needs a window to cancel."*

The threat model this codebase already writes down is *attacker holds a live
session*. R2 hands that attacker a way to make the cancel window permanently
irrelevant, and gives the victim no way to undo it.

Reproduced:

1. With a stolen session cookie, `POST /api/passkey/register/begin` →
   `POST /api/passkey/register/complete` with an authenticator the attacker
   controls. Nothing gates this on a *fresh* Fayda authentication — only on
   `current(request)`, which the stolen cookie satisfies.
2. The victim logs out. Every session row dies. The attacker's credential row
   does not.
3. `POST /api/passkey/login/begin` → `/complete` at any later time returns a
   fresh 12-hour session (`SESSION_TTL_HOURS`, the same TTL a real Fayda login
   earns). Confirmed: `auth_method: passkey`, `/api/registry` 200,
   `/api/wallet/nonce` 200 — full binding powers.
4. From *that* passkey session, `register/begin` returns 200 again. I chained
   seven credentials onto one identity without touching Fayda after the first
   login. So the attacker can also rotate their own persistence.
5. There is no revocation. `/api/me` and `/api/passkey/list` *display* the
   credentials — the UI even prints "N registered on this identity" — but no
   endpoint deletes one. The victim can see the attacker's key and cannot remove
   it without direct database access.

Net effect on the cooling period: the attacker re-initiates the wallet swap
whenever they like. The victim must notice and win the cancel race every 72
hours, forever. The window that was supposed to be the user's advantage becomes
a treadmill.

Two things would each break the chain and neither is present: requiring a fresh
Fayda authentication (not merely a session) to register a credential, and a
`DELETE /api/passkey/{id}` scoped through `user_conn`.

---

### High #2 — `pip install -r backend/requirements.txt` cannot resolve; every clean build of R2 fails

**Location:** `backend/requirements.txt:8` (`cryptography==46.0.6`) against
`:19` (`webauthn==3.0.0`, which declares `cryptography>=49.0.0`);
consumed by `Dockerfile:21` (`RUN pip install --no-cache-dir -r
backend/requirements.txt`), which is the Render build (`render.yaml`,
`runtime: docker`).
**Confidence:** certain — reproduced.
**Invariant broken:** DEPLOY/CLAUDE.md's "deterministic build"; and the R2 diff
adds a dependency without updating the pin it invalidates.

```
ERROR: Cannot install -r backend/requirements.txt (line 19) and cryptography==46.0.6
       because these package versions have conflicting dependencies.
  The user requested cryptography==46.0.6
  webauthn 3.0.0 depends on cryptography>=49.0.0
ERROR: ResolutionImpossible
```

The local venv already carries `cryptography 49.0.0` (installed out of band —
`pip show` confirms 49.0.0 while the file still pins 46.0.6), which is why
29/29 passes locally and why nothing in the suite notices. The file as committed
describes an environment that cannot be built. The first `docker build` after
this lands dies at layer 21.

Secondary, same file: `cbor2` and `pyOpenSSL` (both hard requirements of
`webauthn`, and `cbor2` is imported directly by `t.py:` test 29) are untracked,
so their versions float — against a file whose first line is "Versions as
tested."

*On the dependency question asked directly:* the `cryptography 46 → 49` bump is
safe for the rest of the stack. `eth-account` does not depend on `cryptography`
at all (it signs through `eth-keys`/`coincurve`), `PyNaCl` depends only on
`cffi`, and `PyJWT[crypto]` needs `>=3.4.0`. I ran a full OIDC login through the
RS256 client assertion under 49.0.0 — it works. The problem is the pin, not the
library.

---

### Medium #1 — RLS does **not** fail closed on `WITH CHECK`; `current_setting(..., true)` returns `''`, not NULL, on every reused pooled connection

**Location:** `backend/store.py:185-201` — the comment and all three policies.
**Confidence:** certain — demonstrated, including the write.
**Invariant strained:** the comment's own claim, verbatim: *"current_setting(...,
true) yields NULL when the GUC is unset, and `id = NULL` matches nothing: a
transaction that forgets to name an identity sees an empty registry rather than
all of it. Fails closed."*

That is true exactly once per physical connection. After `set_config('app.
identity_id', …, true)` has run and the transaction has ended, the GUC is
*defined* and resets to the empty string, not to undefined. Measured on a
virgin connection versus a used one:

```
virgin connection            current_setting -> None
after one local set + commit current_setting -> ''
```

Since the pool recycles connections, every connection in steady state is in the
second state. The policy predicate is therefore `id = ''`, not `id IS NULL`.
On the read side that still returns zero rows — which is why test 27's "unset
identity sees zero rows" passes, and it passes for a reason the test does not
state. On the **write** side it fails open:

```
SET LOCAL ROLE fayda_app;                        -- no set_config
SELECT current_setting('app.identity_id', true);  -- ''
INSERT INTO identities (id, …) VALUES ('', …);    -- SUCCEEDS: '' = '' passes WITH CHECK
```

and the row that lands is then visible **and writable** to every other unbound
`fayda_app` transaction:

```
unbound fayda_app SELECT sees: [{'id': '', 'display_name': 'y'}]
and can UPDATE it: 1 row
```

I deleted the row afterwards. This is not reachable from application code today:
`user_conn` raises `ValueError` on a falsy identity, and `current()` 401s on an
empty `identity_id`. So the severity is Medium, not High. But the property the
comment asserts — and that the next person writing a `user_conn`-shaped helper
will rely on — is not the property the database has. The only thing preventing a
shared cross-tenant row is the unenforced convention that no identity id is ever
`''`; there is no `CHECK (id <> '')` and the policies do not say
`current_setting(...) IS NOT NULL AND …`.

---

### Medium #2 — `reset()` leaves `webauthn_credentials` behind and permanently drops its foreign key; the Wipe button does not wipe passkeys

**Location:** `backend/store.py:576-579` (the `DROP TABLE … identities CASCADE`)
against `:99-109` (the `CREATE TABLE IF NOT EXISTS webauthn_credentials … REFERENCES
identities(id) ON DELETE CASCADE`).
**Confidence:** certain — observed in the live catalog, then reproduced by
triggering `/api/dev/reset`.
**Invariant broken:** CLAUDE.md, *"Prefer database constraints over application
checks"*, and the schema comment that promises `ON DELETE CASCADE`.

`reset()` drops `wallet_bindings, auth_nonces, sessions, identities CASCADE`.
The CASCADE takes the FK constraint on `webauthn_credentials` with it, because
that constraint depends on `identities`. The table itself is not in the DROP
list, so `_create_schema`'s `CREATE TABLE IF NOT EXISTS` is a no-op and the FK
is **never re-added**. The live dev database right now:

```
FK constraints on webauthn_credentials: ['webauthn_credentials_pkey']   -- pkey only
```

After I triggered `/api/dev/reset`:

```
identities: 0   wallet_bindings: 0   webauthn_credentials: 8   orphans: 8
labels retained: 'sc', 'reused-after-500', 'noUV', ''  (created_at/last_used_at intact)
```

Three consequences:

- The dev/demo "Wipe registry" button deletes identities and bindings but leaves
  every passkey — public key, credential id, device label (the frontend sets it
  from `navigator.platform`), creation and last-use timestamps — for people the
  registry claims to have forgotten. That is a data-deletion promise the code
  does not keep.
- `webauthn_credentials` grows monotonically across every reset, unbounded.
- `ON DELETE CASCADE` is gone for the life of the database, so any future
  identity deletion silently orphans credentials rather than removing them.

No authentication consequence: `passkey_login_complete` calls
`store.get_identity(stored["identity_id"])` and raises the uniform `denied` when
it returns `None`. I confirmed against the 8 live orphans that they cannot log
in. And identity ids are uuid4, so an orphan cannot be re-adopted by a new
identity. That is why this is Medium and not High.

---

### Medium #3 — the registry is not de-publicised in the configuration that actually ships

**Location:** `backend/app.py:670-680` (`current(request)` is the whole gate),
`backend/store.py:1030-1047`, against `render.yaml` (`APP_ENV: production`,
`DEMO_MODE: "1"`) and `backend/app.py:265-266` (`if DEV_MODE or DEMO_MODE:
app.include_router(mock_esignet.router)`).
**Confidence:** certain — reproduced against a production-posture DEMO_MODE
instance on :8111.
**Invariant strained:** the change's own stated goal — *"over real Fayda
identities it is a directory of verified Ethiopians and the wallets they
control, which is not something to hand an anonymous caller."*

The gate is "holds any session". In the posture `render.yaml` ships, a session
costs one click on a persona card:

```
boot /api/me            -> authenticated: False, demo: True, dev: False
anon  /api/registry     -> 401                      (correct)
GET /login -> pick persona -> /callback -> /api/registry -> 200, every identity
/api/dev/reset|fast-forward|test-wallet -> 404       (correct — DEMO_MODE never arms these)
```

So the anonymous-caller property holds for exactly as long as it takes to press
a button. On the demo deploy the rows are fictional personas, which caps the
harm — but the property being claimed is not the property being enforced, and
the moment real Fayda credentials are configured beside `DEMO_MODE=1` (nothing
in the code forbids that combination) the directory is public again.

**On the deliberate decision you asked me to challenge — I think it is wrong as
built, for a reason narrower than "it's a directory".** `store.registry()`
selects `FROM identities`, unconditionally. It lists *everyone who has ever
authenticated with Fayda here*, including people with `evm: null, solana: null`
who have bound no wallet at all. I confirmed this: my "Probe B" identity, which
never bound anything, appears in full to every other signed-in user with
`display_name`, `verified_at`, and its internal UUID.

The product justification for a registry is "which wallet does this verified
person control". A row with no wallet answers nothing and only discloses "this
named person holds a Fayda ID and used this service on this date". For an
Ethiopian national-ID-linked service that is the sensitive half without the
useful half. Two changes would keep the feature and drop most of the exposure:
`WHERE EXISTS (an active binding)`, and dropping `i.id` from the projection —
which is the RLS key handed to every reader, and the one value in the row that
has no display purpose whatsoever. Removing `fin_hmac` was right; `id` is the
same argument one step weaker, and it went untouched.

---

### Medium #4 — registration does not enforce user verification, so the RP accepts a credential that violates its own stated policy

**Location:** `backend/app.py:467-472` — `wa.verify_registration_response(...)`
omits `require_user_verification`, which defaults to `False` in py_webauthn
3.0.0 (`inspect.signature` confirms), while `:448-451` asks the client for
`UserVerificationRequirement.REQUIRED`.
**Confidence:** certain — reproduced.
**Invariant strained:** `authenticator_selection` is a *request* to the client,
not a check; the verification step is where the RP enforces it, and here it does
not. `/login/complete` gets this right (`require_user_verification=True`).

```
options authenticatorSelection: {'residentKey':'required','userVerification':'required'}
register a credential with the UV flag CLEARED -> 200 accepted
login with that credential, UV cleared        -> 400 rejected
login with that credential, UV asserted       -> 200 accepted
```

Two effects. First, a credential that genuinely cannot do user verification is
happily stored and then can never be used — a silent, unrecoverable lockout made
worse by there being no way to delete it (High #1). Second, the RP's UV policy
is enforced only at assertion time, which means the RP never actually learns
whether the authenticator can do UV; it only learns what the authenticator
claims each time. Asserting the requirement at registration is the point where
that is checkable.

---

### Medium #5 — three unauthenticated 500s on `/api/passkey/login/complete`, plus an authenticated one on `/register/complete`

**Location:** `backend/app.py:511-515` — `body = await request.json()`,
`body.get("credential")` and `credential.get("id")` all sit *outside* the
try/except; `:465` and `:481` for the register side.
**Confidence:** certain — reproduced.
**Invariant strained:** the file's own boundary discipline. `_clean_token`
(`:579-588`) and `_strip_nul` (`:292-305`) exist precisely because "a NUL byte is
unrepresentable in Postgres text (it would become a 500 instead of the 400 this
is)". The new R2 fields skipped both.

Unauthenticated, no prior `/login/begin` state needed beyond one call:

| body | result |
|---|---|
| `not-json` | **500** |
| `[1,2,3]` | **500** (`body.get` on a list) |
| `{"credential":"abc"}` | **500** (`.get` on a str) |
| `{"credential":null}` | 400 (correct) |

Authenticated: `{"label": "dev\x00ice"}` on `/register/complete` → **500**, from
psycopg rejecting the NUL inside `store.add_credential`; app.py catches only
`UniqueViolation` there. (`{"label": {"a": 1}}` is accepted and stored as the
Python repr `"{'a': 1}"` — harmless, but it shows the field is unvalidated.)

Each 500 also tears the keep-alive connection: the next request on the same
socket got `ECONNRESET` in my client. The server itself stays healthy (three
subsequent `/api/me` calls returned 200), and no traceback reaches the client,
so this is noise and log spam rather than a breach. It is on the unauthenticated
surface, which is why it is Medium rather than Low.

---

### Low

1. **RLS is escapable from inside a `user_conn` block.** `RESET ROLE` inside the
   scoped transaction restores `postgres` and full bypass — measured: `RESET ROLE
   -> postgres | identities visible: 3`. So does `SET LOCAL ROLE postgres`, and
   so does a second `set_config('app.identity_id', <other id>, true)`, which
   re-points the scope to another identity (measured: it then returned Probe B's
   row while bound to Probe A). None of this is reachable today — every query in
   `store.py` is parameterized and there is no injection surface — but the
   comment at `store.py:350-356` says the filter "is the database's, not a WHERE
   clause someone can forget to write", and that guarantee is conditional on the
   scoped block never issuing DDL-ish session commands. Worth stating so the next
   reader does not over-trust it. `backend/store.py:345-369`.

2. **One session key for two ceremonies.** `passkey_challenge`
   (`app.py:455, 462, 502, 508`) is shared by registration and login. A challenge
   minted by `/login/begin` completes a registration and vice versa — both
   confirmed 200. No escalation: py_webauthn pins `clientData.type` per ceremony,
   so a `webauthn.get` assertion can never satisfy a registration. But a login
   attempt silently destroys an in-flight registration challenge and the reverse,
   and the ceremony separation the spec asks for is absent.

3. **An unhandled 500 does not burn the challenge.** Because the exception
   escapes past `ServerSideSessionMiddleware.send_wrapper`, the session is never
   re-saved and the popped challenge survives in the database. Reproduced: I
   crashed `/register/complete` with a non-JSON body, then successfully completed
   the *same* challenge afterwards (200). Combined with Medium #5 this means the
   single-use property holds on every handled path and not on the crash paths.

4. **No cap on credentials per identity, no revocation.** Registered seven onto
   one identity in a loop; `excludeCredentials` in every subsequent
   `/register/begin` grew to seven entries and `/api/me` returns the whole list
   on every dashboard load. Self-inflicted, but it is an authenticated,
   unbounded, durable table with no ceiling and no delete.
   `app.py:444-447, 725-727`.

5. **A second unauthenticated session-minting endpoint.** `/api/passkey/login/begin`
   (`app.py:493-503`) writes a pre-auth session row per call, like `/login`.
   Bounded by `PRE_AUTH_SESSION_TTL_HOURS` and the sweeper, so it is the R1
   posture rather than a regression — but there is still no rate limit anywhere
   in the process, and R2 widened that surface.

6. **RP_ID derivation has no guard.** `RP_ID = urlparse(PUBLIC).hostname or
   "localhost"` (`app.py:419`). With `PUBLIC_URL` and `RENDER_EXTERNAL_URL` both
   unset outside dev, `PUBLIC` falls back to `BASE` and `RP_ID` becomes the IP
   literal `127.0.0.1`, which browsers reject as an RP ID (`SecurityError`); if
   `PUBLIC_URL` carries a path (`https://gov.et/fayda`), `expected_origin` can
   never equal the browser's origin. Both fail closed — passkeys simply stop
   working — and both are silent at startup. The app already refuses to boot on
   missing secrets; this deserves the same treatment.

7. **`touch_credential` runs privileged unnecessarily.** `store.py:729-735` uses
   `conn()`, but `stored["identity_id"]` is in hand at the call site
   (`app.py:538`), so it could go through `user_conn` and be covered by the
   policy. The other two entries on the privileged list I checked and agree with:
   `credential_by_id` genuinely has no identity to scope to yet, and `sessions` /
   `promote_due` / `address_claimed_by_other` are correctly cross-identity
   (test 27(b) makes the case for the last one well).

8. **`/api/registry` discloses the RLS key.** Every signed-in user receives
   `i.id`, the exact value the policies compare against. No endpoint currently
   accepts an identity id from the client, so nothing is exploitable — but it is
   a strange value to publish given the change's own reasoning about `fin_hmac`.
   See Medium #3.

9. **Device fingerprint stored at rest.** `frontend/src/passkey.js` is called as
   `registerPasskey(navigator.platform || 'this device')` (`App.jsx`), so the
   label column holds e.g. `MacIntel` and is echoed to the browser in `/api/me`.
   Minor, and arguably useful to the user, but it is PII the schema comment does
   not mention.

---

### Verified safe

Actively attacked and could not break. Do not re-plough these.

**RLS mechanics.** `user_conn` genuinely binds: inside the block `current_user`
is `fayda_app` (catalog confirms `rolbypassrls = false`, `rolcanlogin = false`),
psycopg is **not** in autocommit (`autocommit: False`, `transaction_status`
INTRANS at the `yield`), so `SET LOCAL ROLE` is inside a real transaction rather
than a discarded warning. An unfiltered `SELECT count(*) FROM identities`
returned 1 of 3. `sessions` and `auth_nonces` are refused outright
(`InsufficientPrivilege`) because the grants list only the three scoped tables.
`WITH CHECK` does refuse a cross-identity INSERT when the GUC is bound.

**No leak across pooled connections.** After a clean `user_conn` exit *and*
after a `DivisionByZero` thrown mid-transaction, three consecutive `conn()`
checkouts each reported `{'u': 'postgres', 'g': ''}`. The `SET LOCAL` /
`is_local=true` pair genuinely dies with the transaction, and psycopg's pool
rollback covers the exception path. (The `''` rather than `NULL` is Medium #1;
the *isolation* is sound.)

**`search_path` survives the role switch** — `SHOW search_path` inside
`user_conn` returns `public`. This now matters more than R1's comment says:
Supabase's `auth` schema owns tables named `identities`, `sessions` **and**
`webauthn_credentials` (all three confirmed in `pg_class`, owner
`supabase_auth_admin`). R2 added a third name collision and the existing pin
covers it.

**Sybil holds under RLS.** The unique index still rejects a claim on a row RLS
hides (confirmed: `BindingConflict` with a `UniqueViolation` cause, and
`e.diag.constraint_name` is still populated for a non-owner role, so the
`_chain_address` vs `_identity_chain` discrimination survives).
`address_claimed_by_other` correctly stayed on `conn()`; scoping it would have
made it report every taken address as free, and the cross-tier case
(pending-against-active, which no single partial index arbitrates) is exactly
where that would have bitten. The HTTP path 409s.

**R1 concurrency work still intact under the new role.** `consume_nonce`'s
`FOR UPDATE`, `promote_due`'s `ORDER BY id … FOR UPDATE SKIP LOCKED` and its
per-promotion savepoints all still run privileged; `cancel_pending` moved to
`fayda_app` but row locks are role-independent, and `promote_due`'s `SKIP LOCKED`
still yields to a cancel holding the lock. `create_binding`'s two `user_conn`
checkouts are sequential, not nested, so `max_size=12` is not at risk of
self-deadlock.

**A passkey cannot mint an identity Fayda did not verify.** Both registration
endpoints require `current(request)`; anonymous `register/begin` → 401.
`login/complete` derives the identity *only* from the credential row and denies
uniformly when `get_identity` returns `None` — proved against the 8 orphan
credentials Medium #2 left behind, none of which can log in.

**A passkey cannot be registered for another identity.** Completing A's
registration challenge from B's session → 400; completing a registration with a
third party's `login/begin` challenge → 400. The challenge is session-scoped and
the `identity_id` written is `current(request)`'s, re-checked by the policy's
`WITH CHECK`.

**Credential-id substitution does not work.** py_webauthn 3.0.0 enforces
`bytes_to_base64url(raw_id) == id` in both ceremonies, so presenting the
victim's `id` (which selects the stored public key) beside an attacker's `rawId`
is rejected before any crypto runs.

**Origin and RP-ID pinning work.** An otherwise-valid assertion carrying
`origin: https://evil.example.com` → 400. `expected_rp_id` is hashed and compared
against `authData.rp_id_hash` in both ceremonies.

**Sign-count / cloned-authenticator handling is correct.** A replayed counter is
rejected (400); the library skips the check only when both stored and presented
counts are 0, which is what keeps Apple/iCloud passkeys (always 0) working.
`touch_credential` persists the advance.

**No enumeration oracle on login.** Unknown credential and valid-credential-bad-
signature return byte-identical bodies. There is a residual timing difference
(unknown = one DB lookup; known = lookup plus an ECDSA verify) but it is well
inside network noise against a remote Postgres.

**The reduced-claims passkey session creates no authorization difference.**
`kebele`/`woreda`/`residenceStatus` are genuinely absent from a passkey session
(`claims: {'name': …, 'birthdate': …}` only), and nothing anywhere in `app.py`
branches on `claims` for authorization — it is read once, in `/api/me`, and
echoed. `auth_method` is reported honestly.

**FIN handling is untouched by R2.** Nothing in the passkey path reads `sub`.
`user_id` is the internal uuid4, never the FIN or its HMAC — correct, since the
user handle is stored on the authenticator and surfaces in account pickers.
`fin_hmac` is genuinely gone from `/api/registry` (checked the raw response body,
not just the SELECT list); it remains in `/api/me`, which is the caller's own row
only. No new logging of session, claims or FIN anywhere in the diff.

**The dev surface is absent in the shipped demo posture.** On the
`APP_ENV=production DEMO_MODE=1` instance, `/api/dev/reset`,
`/api/dev/fast-forward` and `/api/dev/test-wallet` all 404 while the mock IdP
mounts. The `DEV_MODE` / `DEMO_MODE` split holds exactly as documented.

**The dependency bump is safe for the existing crypto.** See High #2 — the
`cryptography 49.0.0` runtime is fine for `eth-account` (no dependency),
`PyNaCl` (cffi only) and `PyJWT[crypto]` (`>=3.4.0`); the RS256 client assertion
was exercised end to end. Only the *pin* is broken.

---

**Verdict: no — not safe to build on as it stands. New criticals: 0, new highs: 2.**
The RLS is real and the WebAuthn verification is done properly, but the tree
cannot be built (High #2 kills every clean `docker build`), and the passkey adds
unrevokable persistence that directly undercuts the cooling period's stated
reason for existing (High #1). Both are additive fixes — a pin bump and a
`DELETE /api/passkey/{id}` plus a fresh-Fayda gate on registration — with no
redesign implied; the RLS and passkey verification work underneath them stands.

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
