import re, httpx, sys, base64, subprocess, os, time, json, uuid
B="http://127.0.0.1:8000"
# 30s, not 10: every store call is a network round trip to managed Postgres,
# so a bind is seconds, not milliseconds. This is a transport timeout, never
# an assertion — nothing in the suite passes *because* it is generous.
c=httpx.Client(follow_redirects=False, timeout=30)

def step(n): print(f"\n--- {n}")

HERE=os.path.dirname(os.path.abspath(__file__))

# R1 made storage durable: the database persists across suite runs, so the
# suite must start from a known-empty registry or test 4's first-time bind
# meets last run's bindings. Reset directly through the store — the HTTP
# endpoint needs an authenticated session that does not exist yet.
#
# This file must NOT set APP_ENV itself. An earlier cut did, two lines above
# this call, which satisfied reset()'s own guard and turned the most-run
# command in the repo into a one-command wipe of whatever SUPABASE_DB_URL
# happened to name. Both gates now have to be cleared from outside: the human
# passes APP_ENV=dev, and the target database must itself carry the disposable
# marker. Point .env at production and this refuses instead of destroying it.
sys.path.insert(0, HERE)
import store as st
try:
    st.reset()
except RuntimeError as e:
    print(f"\nCannot prepare a clean registry: {e}\n\n"
          f"Run the suite as:  APP_ENV=dev python backend/t.py\n"
          f"against a throwaway database, not the production project.")
    sys.exit(2)

def server(port, env_extra):
    env=dict(os.environ); env.update(env_extra)
    return subprocess.Popen(
        [sys.executable,"-m","uvicorn","app:app","--host","127.0.0.1",
         "--port",str(port),"--log-level","warning"],
        env=env, cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def wait_up(port, tries=100):
    for _ in range(tries):
        try: httpx.get(f"http://127.0.0.1:{port}/", timeout=1); return True
        except Exception: time.sleep(0.1)
    return False

step("1. OIDC login redirect")
r=c.get(f"{B}/login"); assert r.status_code==307, r.status_code
pre_login_cookie=c.cookies.get("session")
loc=r.headers["location"]; print("  -> /authorize", "client_id=" in loc)
r=c.get(loc); assert r.status_code==200
fins=re.findall(r'name="fin" value="(\d+)"', r.text); print("  personas:", fins)
state=re.search(r'name="state" value="([^"]*)"', r.text).group(1)

step("2. persona -> code")
r=c.post(f"{B}/authorize/confirm", data={"fin":fins[0],"redirect_uri":f"{B}/callback",
        "state":state,"nonce":"n"})
code=re.search(r"code=([^&]+)", r.headers["location"]).group(1); print("  code ok")

step("3. callback: token exchange w/ RS256 client assertion + userinfo")
r=c.get(f"{B}/callback", params={"code":code,"state":state})
assert r.status_code==307, (r.status_code, r.text[:300])
me=c.get(f"{B}/api/me").json()
assert me["authenticated"]
print("  identity:", me["identity"]["display_name"])
print("  fin_hmac:", me["identity"]["fin_hmac"][:24], "...")
assert "301884729166" not in str(me["identity"]), "RAW FIN LEAKED"
print("  raw FIN not in stored identity: ok")

step("3b. C1: raw FIN must appear NOWHERE in /api/me nor the session cookie")
raw_fin=fins[0]
full=c.get(f"{B}/api/me").text
assert raw_fin not in full, "RAW FIN in /api/me response body"
assert '"sub"' not in full, "raw sub (== FIN) in /api/me"
assert me["claims"].get("name"), "whitelisted claim dropped — UI would be empty"
# The session is server-side: the cookie must be an opaque id + HMAC carrying
# no data at all. Decode every segment the way any cookie holder would and
# confirm nothing readable is inside.
cookie=c.cookies.get("session"); assert cookie, "no session cookie"
assert cookie!=pre_login_cookie, "session id must rotate at login (fixation)"
assert raw_fin not in cookie, "RAW FIN in session cookie"
for seg in cookie.split("."):
    try: blob=base64.urlsafe_b64decode(seg+"="*(-len(seg)%4))
    except Exception: continue
    assert raw_fin.encode() not in blob, "RAW FIN decodable from session cookie"
    assert b"identity_id" not in blob and b"claims" not in blob, \
        "session data readable client-side — cookie must hold only an opaque id"
print("  raw FIN absent from response body; cookie is opaque: ok")

step("3c. confirmed schema: picture and phone never reach /api/me")
assert '"picture"' not in full and '"phone"' not in full, "picture/phone claim leaked"
# values too, not just names: every persona phone starts +2519, every picture
# stub carries the data-URI prefix
assert "+2519" not in full and "base64,/9j/" not in full, "sensitive claim value leaked"
# residenceStatus must survive the whitelist — B2's citizenship distinction
# lives there and the UI displays it. Its value set is unconfirmed (NIDP).
me=c.get(f"{B}/api/me").json()
assert me["claims"].get("residenceStatus"), "residenceStatus dropped by the whitelist"
assert "kebele" in me["claims"].get("address", {}), "address is not the confirmed shape"
print("  picture/phone stripped, residenceStatus surfaced: ok")

step("4. bind EVM via throwaway key")
t=c.post(f"{B}/api/dev/test-wallet", json={"chain":"evm"}).json()
r=c.post(f"{B}/api/wallet/bind", json={"chain":"evm","address":t["address"],
        "nonce":t["nonce"],"signature":t["signature"]})
print("  ", r.status_code, r.json()); assert r.json()["status"]=="active"
evm1=t["address"]

step("5. bind Solana")
t=c.post(f"{B}/api/dev/test-wallet", json={"chain":"solana"}).json()
r=c.post(f"{B}/api/wallet/bind", json={"chain":"solana","address":t["address"],
        "nonce":t["nonce"],"signature":t["signature"]})
print("  ", r.status_code, r.json()); assert r.json()["status"]=="active"

step("6. bad signature must be rejected")
t=c.post(f"{B}/api/dev/test-wallet", json={"chain":"evm"}).json()
bad="0x"+"11"*65
r=c.post(f"{B}/api/wallet/bind", json={"chain":"evm","address":t["address"],
        "nonce":t["nonce"],"signature":bad})
print("  ", r.status_code, r.json().get("detail","")[:70]); assert r.status_code==400

step("7. nonce replay must be rejected")
t=c.post(f"{B}/api/dev/test-wallet", json={"chain":"evm"}).json()
c.post(f"{B}/api/wallet/bind", json={"chain":"evm","address":t["address"],
        "nonce":t["nonce"],"signature":t["signature"]})
r=c.post(f"{B}/api/wallet/bind", json={"chain":"evm","address":t["address"],
        "nonce":t["nonce"],"signature":t["signature"]})
print("  ", r.status_code, r.json().get("detail","")); assert r.status_code==400

step("8. replacement goes pending, incumbent stays active")
me=c.get(f"{B}/api/me").json()
print("  active evm:", me["active"]["evm"]["address"][:14],
      "| pending:", me["pending"]["evm"]["address"][:14] if me["pending"]["evm"] else None)
assert me["active"]["evm"]["address"]==evm1
assert me["pending"]["evm"] is not None

step("9. fast-forward cooling -> promotes, old archived")
c.post(f"{B}/api/dev/fast-forward", json={"chain":"evm","address":""})
me=c.get(f"{B}/api/me").json()
print("  active evm now:", me["active"]["evm"]["address"][:14])
assert me["active"]["evm"]["address"]!=evm1
assert any(b["status"]=="archived" for b in me["history"])
print("  old binding archived: ok")

step("10. SYBIL: second identity cannot claim the same wallet")
taken=me["active"]["evm"]["address"]
c2=httpx.Client(follow_redirects=False, timeout=30)
r=c2.get(f"{B}/login"); loc=r.headers["location"]
r=c2.get(loc); state=re.search(r'name="state" value="([^"]*)"', r.text).group(1)
r=c2.post(f"{B}/authorize/confirm", data={"fin":fins[2],"redirect_uri":f"{B}/callback",
         "state":state,"nonce":"n"})
code=re.search(r"code=([^&]+)", r.headers["location"]).group(1)
c2.get(f"{B}/callback", params={"code":code,"state":state})
print("  second identity:", c2.get(f"{B}/api/me").json()["identity"]["display_name"])
r=c2.post(f"{B}/api/wallet/nonce", json={"chain":"evm","address":taken})
print("  ", r.status_code, r.json().get("detail","")); assert r.status_code==409

step("11. cross-chain: EVM sig must not validate as Solana")
t=c.post(f"{B}/api/dev/test-wallet", json={"chain":"solana"}).json()
r=c.post(f"{B}/api/wallet/bind", json={"chain":"solana","address":t["address"],
        "nonce":t["nonce"],"signature":"0x"+"22"*64})
print("  ", r.status_code, r.json().get("detail","")[:60]); assert r.status_code==400

step("12. H1: /api/dev/reset rejects an unauthenticated caller")
anon=httpx.Client(follow_redirects=False, timeout=30)
r=anon.post(f"{B}/api/dev/reset")
print("  ", r.status_code, r.json().get("detail","")); assert r.status_code==401, r.status_code

step("13. H1/H2/M3: the whole dev surface 404s when APP_ENV != dev")
P=8099
# A production relying party needs its registered client key; the app now
# refuses to start without one (R5 readiness). Supply one here, as a real
# deployment would — this test is about the DEV SURFACE being absent, not about
# the key guard, which test 45 covers.
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa0
from cryptography.hazmat.primitives import serialization as _ser0
PROD_CLIENT_KEY = _rsa0.generate_private_key(
    public_exponent=65537, key_size=2048).private_bytes(
    encoding=_ser0.Encoding.PEM, format=_ser0.PrivateFormat.PKCS8,
    encryption_algorithm=_ser0.NoEncryption()).decode()
srv=server(P, {"APP_ENV":"production","SESSION_SECRET":"s"*32,
               "FIN_PEPPER":"p"*32,"BASE_URL":f"http://127.0.0.1:{P}",
               "FAYDA_CLIENT_PRIVATE_KEY":PROD_CLIENT_KEY,
               # Issued with the key; the app refuses the demo default
               # alongside a registered key (test 45 covers that guard).
               "FAYDA_CLIENT_ID":"et-partner-0013"})
try:
    assert wait_up(P), "production-mode server never came up"
    pb=f"http://127.0.0.1:{P}"
    for route in ("/api/dev/reset","/api/dev/fast-forward","/api/dev/test-wallet"):
        r=httpx.post(f"{pb}{route}", json={"chain":"evm"}, timeout=5)
        assert r.status_code==404, (route, r.status_code)
    # the mock IdP is part of the dev surface and must not be mounted either
    r=httpx.get(f"{pb}/authorize", params={"client_id":"x"}, timeout=5,
                follow_redirects=False)
    assert r.status_code==404, ("/authorize", r.status_code)
    # The interactive docs enumerate every route and request shape, the
    # operator endpoints included. FastAPI serves them openly by default;
    # production must not publish a map of the compliance API. Assert on the
    # CONTENT, not the status: unmatched GETs fall through to the SPA
    # catch-all, so these paths legitimately answer 200 with index.html — the
    # requirement is that no route table comes back, not that nothing does.
    for route in ("/docs", "/redoc", "/openapi.json"):
        r=httpx.get(f"{pb}{route}", timeout=5, follow_redirects=False)
        body=r.text.lower()
        assert "swagger" not in body and "redoc" not in body, \
            ("interactive API docs served in production", route)
        assert "/api/operator/" not in r.text, \
            ("the route table is published in production", route)
    print("  dev routes, mock IdP, and API docs all absent in production: ok")
finally:
    srv.terminate()
    try: srv.wait(timeout=10)
    except Exception: srv.kill()

step("14. H3: app refuses to start in production without SESSION_SECRET/FIN_PEPPER")
env=dict(os.environ); env["APP_ENV"]="production"
env.pop("SESSION_SECRET", None); env.pop("FIN_PEPPER", None)
p=subprocess.run([sys.executable,"-c","import app"], env=env, cwd=HERE,
                 capture_output=True, text=True, timeout=30)
out=p.stdout+p.stderr
assert p.returncode!=0, "app started in production with no secrets"
assert "refusing to start" in out, out[-300:]
print("  production start without secrets refused: ok")

step("15. M2: raced cross-identity pending cannot wedge the registry")
# The app-level sybil check is check-then-insert, so two identities racing the
# window can both park a claim on one address. The index (step 16) closes the
# pending-vs-pending case; the un-indexable variant — active for one identity,
# pending for another — must survive promotion without wedging every read.
# Plant that state directly through the store, as the race would.
import secrets
import psycopg
import store as st
def rnd_addr(): return "0x"+secrets.token_hex(20)
A=st.upsert_identity(secrets.token_hex(16), "Race Winner", "")
Bi=st.upsert_identity(secrets.token_hex(16), "Race Loser", "")
X=rnd_addr(); W=rnd_addr()
st.create_binding(A["id"], "evm", X, secrets.token_hex(8), "sig", "msg", 72)   # A: active on X
st.create_binding(Bi["id"], "evm", W, secrets.token_hex(8), "sig", "msg", 72)  # B: incumbent on W
st.create_binding(Bi["id"], "evm", X, secrets.token_hex(8), "sig", "msg", 72)  # B: raced pending on X
st.force_due(Bi["id"], "evm")
# Before the fix the first read after cooling elapsed raised IntegrityError
# inside promote_due and every subsequent read 500'd. Reads must stay healthy.
# Drive the REGISTRY-WIDE promotion directly: it used to be reachable via
# GET /api/registry, but R3 moved that behind the operator role, and the
# invariant under test is promote_due()'s, not the endpoint's.
for _ in range(3):
    st.promote_due()
r=c.get(f"{B}/api/me"); assert r.status_code==200, ("api/me wedged", r.status_code)
r=c.get(f"{B}/api/me"); assert r.status_code==200, ("api/me wedged on repeat", r.status_code)
assert st.active_binding(A["id"], "evm")["address"]==X, "winner's active binding lost"
inc=st.active_binding(Bi["id"], "evm")
assert inc and inc["address"]==W, "loser's incumbent was archived by the failed promotion"
assert any(b["address"]==X and b["status"]=="cancelled" for b in st.history(Bi["id"])), \
    "conflicting pending row not cancelled — it would re-detonate on every read"
print("  reads healthy, loser cancelled, both incumbents intact: ok")

step("16. M2: DB refuses a second cross-identity pending on one address")
Ci=st.upsert_identity(secrets.token_hex(16), "Race C", "")
Di=st.upsert_identity(secrets.token_hex(16), "Race D", "")
Y=rnd_addr()
st.create_binding(Ci["id"], "evm", rnd_addr(), secrets.token_hex(8), "s", "m", 72)
st.create_binding(Di["id"], "evm", rnd_addr(), secrets.token_hex(8), "s", "m", 72)
st.create_binding(Ci["id"], "evm", Y, secrets.token_hex(8), "s", "m", 72)  # C: pending on Y
try:
    st.create_binding(Di["id"], "evm", Y, secrets.token_hex(8), "s", "m", 72)
    raise AssertionError("second cross-identity pending on one address was accepted")
except st.BindingConflict as e:
    # the rejection must come from the DB index, not an application check
    assert isinstance(e.__cause__, psycopg.errors.UniqueViolation), e.__cause__
    print("  ux_pending_chain_address rejects the duplicate pending: ok")

step("17. M1: raced first-time binds of one address -> one wins, loser 409s, never 500")
# Two first-time binders race the check-then-insert window on the same address.
# Both must be first-time so both INSERTs target status='active' and the loser
# hits ux_active_chain_address — the raced-replacement variant is test 15's
# ground. c2 (step 10) never bound anything; log the third persona in fresh.
import threading
from eth_account import Account
from eth_account.messages import encode_defunct
c3=httpx.Client(follow_redirects=False, timeout=30)
r=c3.get(f"{B}/login"); loc=r.headers["location"]
r=c3.get(loc); state=re.search(r'name="state" value="([^"]*)"', r.text).group(1)
r=c3.post(f"{B}/authorize/confirm", data={"fin":fins[1],"redirect_uri":f"{B}/callback",
         "state":state,"nonce":"n"})
code=re.search(r"code=([^&]+)", r.headers["location"]).group(1)
c3.get(f"{B}/callback", params={"code":code,"state":state})
for _ in range(10):
    acct=Account.create(); addr=acct.address
    def payload(cl):
        n=cl.post(f"{B}/api/wallet/nonce", json={"chain":"evm","address":addr}).json()
        sig=Account.sign_message(encode_defunct(text=n["message"]), acct.key).signature.hex()
        return {"chain":"evm","address":addr,"nonce":n["nonce"],"signature":sig}
    p2,p3=payload(c2),payload(c3)
    gate=threading.Barrier(2); res={}
    def fire(k, cl, p):
        gate.wait(); res[k]=cl.post(f"{B}/api/wallet/bind", json=p)
    ths=[threading.Thread(target=fire,args=("a",c2,p2)),
         threading.Thread(target=fire,args=("b",c3,p3))]
    for th in ths: th.start()
    for th in ths: th.join()
    codes=sorted(v.status_code for v in res.values())
    assert codes==[200,409], ("raced bind broke the contract", codes,
                              [v.text[:120] for v in res.values()])
    # archive the winner's row so the next round is a first-time bind again
    with st.conn() as sc:
        sc.execute("UPDATE wallet_bindings SET status='archived', archived_at=%s WHERE address=%s",
                   (st.iso(st.now()), addr))
print("  10 raced rounds, every loser got 409 and no 500 ever: ok")

step("18. M1: a losing INSERT raises BindingConflict with the right flavor")
# This is the loser's exact state: past every app check, INSERT collides with a
# unique index. Pre-fix this was a raw sqlite3.IntegrityError — the 500.
E=st.upsert_identity(secrets.token_hex(16), "Race E", "")
F=st.upsert_identity(secrets.token_hex(16), "Race F", "")
Z=rnd_addr()
st.create_binding(E["id"], "evm", Z, secrets.token_hex(8), "s", "m", 72)  # E: active on Z
try:
    st.create_binding(F["id"], "evm", Z, secrets.token_hex(8), "s", "m", 72)
    raise AssertionError("second active binding on one address was accepted")
except st.BindingConflict as e:
    assert "different Fayda identity" in str(e), str(e)
# The other index flavor: one identity double-submitting on one chain.
st.create_binding(E["id"], "evm", rnd_addr(), secrets.token_hex(8), "s", "m", 72)  # pending
try:
    st.create_binding(E["id"], "evm", rnd_addr(), secrets.token_hex(8), "s", "m", 72)
    raise AssertionError("second pending for one identity+chain was accepted")
except st.BindingConflict as e:
    assert "reload and retry" in str(e), str(e)
print("  both unique-index flavors translate to BindingConflict: ok")

step("19. provenance: a dev test-key binding is recorded as such, server-side")
# The nonce records how the proof will be produced at ISSUE time; the binding
# copies it at commit. A client cannot claim 'wallet' for a test-key proof —
# and a marker that silently defaults to 'wallet' is a test-shaped hole, so
# assert the persisted value, not the code path.
me=c.get(f"{B}/api/me").json()
methods={b["proof_method"] for b in me["history"]}
assert methods=={"dev-test-key"}, ("every binding here came from the dev endpoint", methods)
print("  all", len(me["history"]), "bindings persisted proof_method=dev-test-key: ok")

step("20. DEMO_MODE: mock IdP mounts, /api/dev/* stays 404, cookie is Secure")
# The shared-demo posture: a visitor can log in with a persona but can never
# wipe the DB (H1) or collapse cooling (H2). The public origin derives from
# the platform env (RENDER_EXTERNAL_URL), and the session cookie is Secure.
P=8098
srv=server(P, {"APP_ENV":"production","DEMO_MODE":"1","SESSION_SECRET":"s"*32,
               "FIN_PEPPER":"p"*32,"BASE_URL":f"http://127.0.0.1:{P}",
               "RENDER_EXTERNAL_URL":"https://demo.example.com/"})
try:
    assert wait_up(P), "demo-mode server never came up"
    pb=f"http://127.0.0.1:{P}"
    r=httpx.get(f"{pb}/login", timeout=5, follow_redirects=False)
    sc=r.headers.get("set-cookie","")
    assert "Secure" in sc and "HttpOnly" in sc and "SameSite=Lax" in sc, sc
    assert r.headers["location"].startswith("https://demo.example.com/authorize"),         r.headers["location"]
    print("  Secure cookie set; authorize URL derives from RENDER_EXTERNAL_URL: ok")
    r=httpx.get(f"{pb}/authorize", params={"client_id":"fayda-wallet-demo",
                "redirect_uri":f"{pb}/callback","state":"s","nonce":"n"}, timeout=5)
    assert r.status_code==200 and 'name="fin"' in r.text, r.status_code
    print("  mock IdP mounted in demo mode, personas served: ok")
    for route in ("/api/dev/reset","/api/dev/fast-forward","/api/dev/test-wallet"):
        r=httpx.post(f"{pb}{route}", json={"chain":"evm"}, timeout=5)
        assert r.status_code==404, (route, r.status_code)
    print("  every /api/dev/* route 404s in demo mode: ok")
    r=httpx.get(f"{pb}/api/me", timeout=5).json()
    assert r["demo"] is True and r["dev"] is False, r
    assert r["public_origin"]=="https://demo.example.com", r["public_origin"]
    print("  /api/me: demo=True dev=False, public_origin from platform env: ok")
finally:
    srv.terminate()
    try: srv.wait(timeout=10)
    except Exception: srv.kill()

step("21. mock IdP: reflected params escaped, redirect_uri constrained to /callback")
# DEMO_MODE publishes the mock on a real origin, so its reflected inputs must
# not be an XSS or open-redirect surface. Runs against the dev server (mock mounted).
xss='"><script>alert(document.domain)</script>'
r=c.get(f"{B}/authorize", params={"client_id":"fayda-wallet-demo",
        "redirect_uri":f"{B}/callback","state":xss,"nonce":"n","scope":xss})
assert r.status_code==200, r.status_code
assert "<script>alert" not in r.text, "reflected state/scope not escaped — XSS live"
assert "&lt;script&gt;" in r.text, "expected escaped payload in output"
print("  reflected state/scope HTML-escaped: ok")
# Open redirect: a non-/callback target is rejected at authorize and at confirm.
r=c.get(f"{B}/authorize", params={"client_id":"fayda-wallet-demo",
        "redirect_uri":"https://evil.example.com/phish","state":"s","nonce":"n"})
assert r.status_code==400, ("authorize accepted foreign redirect_uri", r.status_code)
r=c.post(f"{B}/authorize/confirm", data={"fin":fins[0],
        "redirect_uri":"https://evil.example.com/phish","state":"s","nonce":"n"})
assert r.status_code==400, ("confirm accepted foreign redirect_uri", r.status_code)
print("  redirect_uri outside /callback rejected at authorize and confirm: ok")

step("22. SYBIL under case variance: two identities racing one wallet, different case")
# The sybil unique indexes compare exact strings, but EVM hex is
# case-insensitive: '0xAbC…' and '0xabc…' are the same wallet and were two
# different rows to Postgres. Two identities racing the check-then-insert
# window with different-cased spellings of ONE address therefore both landed
# active — non-negotiable #3 broken with no luck required. Addresses are
# normalised at every write now; this asserts the race resolves.
for _ in range(4):
    acct=Account.create()
    cs=acct.address                      # EIP-55 checksummed
    lc=cs.lower()
    assert cs!=lc, "need a mixed-case checksum address for this test to mean anything"
    def payload_cased(cl, a):
        n=cl.post(f"{B}/api/wallet/nonce", json={"chain":"evm","address":a}).json()
        sig=Account.sign_message(encode_defunct(text=n["message"]), acct.key).signature.hex()
        return {"chain":"evm","address":a,"nonce":n["nonce"],"signature":sig}
    p2,p3=payload_cased(c2,cs),payload_cased(c3,lc)
    gate=threading.Barrier(2); res={}
    def fire2(k, cl, p):
        gate.wait(); res[k]=cl.post(f"{B}/api/wallet/bind", json=p)
    ths=[threading.Thread(target=fire2,args=("a",c2,p2)),
         threading.Thread(target=fire2,args=("b",c3,p3))]
    for th in ths: th.start()
    for th in ths: th.join()
    codes=sorted(v.status_code for v in res.values())
    assert codes==[200,409], ("case-variant race broke the sybil contract", codes,
                              [v.text[:120] for v in res.values()])
    with st.conn() as sc:
        live=sc.execute(
            "SELECT identity_id, address FROM wallet_bindings "
            "WHERE chain='evm' AND LOWER(address)=%s AND status IN ('active','pending')",
            (lc,)).fetchall()
    assert len(live)==1, ("one wallet, two live identities — sybil broken", live)
    with st.conn() as sc:
        sc.execute("UPDATE wallet_bindings SET status='archived', archived_at=%s "
                   "WHERE LOWER(address)=%s", (st.iso(st.now()), lc))
print("  4 case-variant races, exactly one live claim every time: ok")

step("23. cooling: a committed cancel is never reverted by a concurrent promotion")
# promote_due runs on every read of /api/me, and registry-wide for operators,
# so it races the user's cancel. Without a row lock and a status guard, a
# promotion holding a stale snapshot re-activated the row the user had just
# cancelled — the attacker's swap goes live even though the victim cancelled
# it in time, which is exactly what the cooling period exists to prevent.
# The mirror failure is as bad: rolling the incumbent's archival forward while
# the replacement is cancelled leaves the identity with NO active wallet.
for rnd in range(6):
    ident=st.upsert_identity(secrets.token_hex(16), f"Cooling {rnd}", "")
    incumbent, replacement = rnd_addr(), rnd_addr()
    st.create_binding(ident["id"], "evm", incumbent, secrets.token_hex(8), "s", "m", 72)
    st.create_binding(ident["id"], "evm", replacement, secrets.token_hex(8), "s", "m", 72)
    st.force_due(ident["id"], "evm")
    gate=threading.Barrier(2); out={}
    def do_cancel():
        gate.wait(); out["cancelled"]=st.cancel_pending(ident["id"], "evm")
    def do_promote():
        gate.wait(); st.promote_due()
    ths=[threading.Thread(target=do_cancel), threading.Thread(target=do_promote)]
    for th in ths: th.start()
    for th in ths: th.join()
    rows={r["address"]: r["status"] for r in st.history(ident["id"])}
    if out["cancelled"]:
        assert rows[replacement]=="cancelled", \
            ("cancel returned True but the promotion revived the row", rows)
        assert rows[incumbent]=="active", \
            ("cancel succeeded but the incumbent was archived anyway", rows)
    else:
        assert rows[replacement]=="active", \
            ("cancel returned False so the promotion must have won", rows)
        assert rows[incumbent]=="archived", rows
    # Either way the identity must end with exactly one active wallet.
    act=[a for a,s in rows.items() if s=="active"]
    assert len(act)==1, ("identity left without exactly one active wallet", rows)
print("  6 cancel-vs-promote races, cancel always honoured, never zero active: ok")

step("24. junk-priced junk: oversized or malformed bind inputs rejected before any decode")
# b58decode is quadratic in input length. Without a length gate an oversized
# "address" (or any unrecognized chain string falling through to the base58
# branch) buys seconds of GIL-held CPU per request, unauthenticated-adjacent
# DoS on a sync endpoint. All three probes below must be refused by shape
# checks alone — fast — and a NUL-bearing address must 400 at the boundary,
# not 500 inside Postgres. 'z', not '1': leading '1's are base58 zero-bytes
# and decode in linear time — only non-zero digits exercise the quadratic
# big-integer path (measured: 'z'*60000 = 5.6s, '1'*100000 = 0.00s).
big = "z" * 60_000
small = "z" * 40                       # plausible length, still not a real key


def probe(payload):
    t0 = time.time()
    r = c.post(f"{B}/api/wallet/bind", json=payload)
    return r, time.time() - t0


# Every probe must be refused, whatever its size or chain.
for chain, addr in (("solana", big), ("not-a-chain", big), ("solana", small)):
    r, _ = probe({"chain": chain, "address": addr, "nonce": "n", "signature": "s"})
    assert r.status_code == 400, (chain, len(addr), r.status_code, r.text[:120])
r = c.post(f"{B}/api/wallet/nonce", json={"chain": "solana", "address": big})
assert r.status_code == 400, (r.status_code, r.text[:120])

# The real assertion is a COMPARISON, not a wall-clock budget: an oversized
# address must cost no more than a small one. Both requests do identical
# session work, so the round trips to the managed database cancel out and what
# remains is decode cost — which is what regressed here. An absolute bound
# measured DB latency instead, and drifted when RLS added statements per
# request. Pre-fix the 60 KB payload was ~3.5 s against a few ms; a 4x ratio
# separates that from noise without being sensitive to how slow the DB is.
oversized = min(probe({"chain": "solana", "address": big,
                       "nonce": "n", "signature": "s"})[1] for _ in range(3))
baseline = min(probe({"chain": "solana", "address": small,
                      "nonce": "n", "signature": "s"})[1] for _ in range(3))
ratio = oversized / max(baseline, 1e-6)
assert ratio < 4.0, (f"a 60 KB address cost {ratio:.1f}x a 40-char one "
                     f"({oversized:.2f}s vs {baseline:.2f}s) — it is being decoded")
elapsed = oversized
r = c.post(f"{B}/api/wallet/nonce", json={"chain": "evm", "address": "0x" + "a" * 39 + "\x00"})
assert r.status_code == 400, ("NUL address must 400 at the boundary", r.status_code)
print(f"  oversized/foreign-chain/NUL inputs all 400; 60KB costs "
      f"{ratio:.2f}x a 40-char address (not decoded): ok")

step("25. R1 durability hygiene: expired sessions and nonces are reclaimed, live ones kept")
# Storage no longer resets on redeploy, so TTL-dead rows must be deleted by
# the sweep or the tables grow forever from unauthenticated traffic.
from psycopg.types.json import Json
dead_sid, live_sid = "t25-dead-" + secrets.token_hex(4), "t25-live-" + secrets.token_hex(4)
dead_nonce, live_nonce = "t25-dn-" + secrets.token_hex(4), "t25-ln-" + secrets.token_hex(4)
with st.conn() as sc:
    for sid, delta in ((dead_sid, -1), (live_sid, +1)):
        sc.execute(
            "INSERT INTO sessions (sid, data, created_at, expires_at) VALUES (%s,%s,%s,%s)",
            (sid, Json({}), st.iso(st.now()),
             st.iso(st.now() + st.timedelta(hours=delta))))
    for nn, delta in ((dead_nonce, -1), (live_nonce, +1)):
        sc.execute(
            "INSERT INTO auth_nonces (nonce, address, chain, message, expires_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (nn, "0x0", "evm", "m", st.iso(st.now() + st.timedelta(hours=delta))))
swept_s, swept_n = st.sweep_expired()
assert swept_s >= 1 and swept_n >= 1, (swept_s, swept_n)
with st.conn() as sc:
    sids = {r["sid"] for r in sc.execute(
        "SELECT sid FROM sessions WHERE sid IN (%s,%s)", (dead_sid, live_sid)).fetchall()}
    nonces = {r["nonce"] for r in sc.execute(
        "SELECT nonce FROM auth_nonces WHERE nonce IN (%s,%s)",
        (dead_nonce, live_nonce)).fetchall()}
assert sids == {live_sid}, ("sweep must delete exactly the expired session", sids)
assert nonces == {live_nonce}, ("sweep must delete exactly the expired nonce", nonces)
# The signed-in session driving this suite has a future expiry — it must survive.
assert c.get(f"{B}/api/me").json()["authenticated"], "sweep destroyed a live session"
with st.conn() as sc:
    sc.execute("DELETE FROM sessions WHERE sid = %s", (live_sid,))
    sc.execute("DELETE FROM auth_nonces WHERE nonce = %s", (live_nonce,))
print("  expired rows reclaimed, live session survives the sweep: ok")

# The sweep's predicate and its index must share a collation. They did not on
# the first cut: expires_at is TEXT, the sweep compares COLLATE "C" (the
# default collation does not order ISO-8601 chronologically below one second),
# and an index built in the default collation is UNUSABLE by that comparison —
# so the sweep silently seq-scanned the one table an attacker grows. Assert
# the planner can actually reach the index, not merely that one exists.
with st.conn() as sc:
    for idx in ("ix_sessions_expires", "ix_auth_nonces_expires"):
        d = sc.execute("SELECT indexdef FROM pg_indexes WHERE schemaname='public' "
                       "AND indexname=%s", (idx,)).fetchone()
        assert d, f"{idx} is missing — the sweep would scan the whole table"
        assert 'COLLATE "C"' in d["indexdef"], \
            (f"{idx} collation does not match the sweep predicate", d["indexdef"])
    sc.execute("SET enable_seqscan = off")
    for tbl in ("sessions", "auth_nonces"):
        plan = " ".join(r["QUERY PLAN"] for r in sc.execute(
            f'EXPLAIN DELETE FROM {tbl} WHERE expires_at COLLATE "C" < %s',
            (st.iso(st.now()),)).fetchall())
        assert "Index" in plan, (f"sweep on {tbl} cannot use its index", plan)
print("  sweep predicate and index share a collation; planner reaches it: ok")

step("26. destruction is gated on the TARGET database, not the caller's environment")
# R1 made the database durable, which made reset() capable of irreversible
# loss. A guard reading the caller's own APP_ENV is not a guard — the caller
# sets it. Both gates must refuse independently, and the marker must name the
# database it was written for so a dev dump restored onto production does not
# carry permission to wipe it.
saved_env = os.environ.get("APP_ENV")
os.environ.pop("APP_ENV", None)
try:
    st.reset()
    raise AssertionError("reset() dropped tables with APP_ENV unset")
except RuntimeError as e:
    assert "dev-only" in str(e), e
if saved_env is not None:
    os.environ["APP_ENV"] = saved_env
else:
    os.environ["APP_ENV"] = "dev"
print("  gate 1: refuses when the caller is not dev: ok")

with st.conn() as sc:
    marker = sc.execute(
        "SELECT value FROM registry_meta WHERE key='disposable_registry'").fetchone()
assert marker, "suite ran against a database with no disposable marker"
original_marker = marker["value"]
with st.conn() as sc:
    sc.execute("UPDATE registry_meta SET value=%s WHERE key='disposable_registry'",
               ("db.some-other-project.supabase.co:5432/postgres",))
try:
    st.reset()
    raise AssertionError("reset() honoured a marker naming a different database")
except RuntimeError as e:
    assert "marker names" in str(e), e
print("  gate 2: refuses when the marker names another database: ok")

with st.conn() as sc:
    sc.execute("DELETE FROM registry_meta WHERE key='disposable_registry'")
try:
    st.reset()
    raise AssertionError("reset() dropped an unmarked database")
except RuntimeError as e:
    assert "not marked disposable" in str(e), e
print("  gate 2: refuses when the database is unmarked: ok")

# Restore the marker so the next run can prepare a clean registry.
with st.conn() as sc:
    sc.execute("INSERT INTO registry_meta (key,value,set_at) VALUES "
               "('disposable_registry',%s,%s) ON CONFLICT (key) DO UPDATE SET "
               "value=excluded.value, set_at=excluded.set_at", (original_marker, st.iso(st.now())))
assert st.disposable()[0], "failed to restore the disposable marker"
print("  marker restored; both gates verified independent: ok")

step("27. R2 RLS: the DATABASE refuses cross-identity reads and writes")
# The requirement is row policies, not app-side WHERE clauses — "one missed
# WHERE clause = full leak" is the threat. So every assertion here uses a query
# with NO identity predicate at all: whatever filtering happens is Postgres's.
rls_a = st.upsert_identity(secrets.token_hex(16), "RLS Alice", "")
rls_b = st.upsert_identity(secrets.token_hex(16), "RLS Bob", "")
addr_a, addr_b = rnd_addr(), rnd_addr()
st.create_binding(rls_a["id"], "evm", addr_a, secrets.token_hex(8), "s", "m", 72)
st.create_binding(rls_b["id"], "evm", addr_b, secrets.token_hex(8), "s", "m", 72)

with st.user_conn(rls_a["id"]) as uc:
    ids = uc.execute("SELECT id FROM identities").fetchall()          # no WHERE
    bind = uc.execute("SELECT identity_id FROM wallet_bindings").fetchall()
assert [r["id"] for r in ids] == [rls_a["id"]], \
    ("an unfiltered SELECT saw other identities", len(ids))
assert bind and all(r["identity_id"] == rls_a["id"] for r in bind), \
    "an unfiltered SELECT saw other identities' bindings"
print("  unfiltered SELECT returns only the bound identity's rows: ok")

# WITH CHECK: writing a row belonging to someone else must be refused.
try:
    with st.user_conn(rls_a["id"]) as uc:
        uc.execute("""INSERT INTO wallet_bindings (id,identity_id,chain,address,status,
                      proof_nonce,proof_sig,proof_message,requested_at)
                      VALUES (%s,%s,'evm',%s,'active','n','s','m',%s)""",
                   (secrets.token_hex(8), rls_b["id"], rnd_addr(), st.iso(st.now())))
    raise AssertionError("wrote a binding on another identity's behalf")
except psycopg.errors.InsufficientPrivilege:
    print("  INSERT for another identity refused by the row policy: ok")

# Fails CLOSED: no identity bound means no rows, never all rows.
with st.conn() as sc:
    sc.execute(f"SET LOCAL ROLE {st.APP_ROLE}")
    n = sc.execute("SELECT count(*) AS n FROM identities").fetchone()["n"]
assert n == 0, ("RLS fails OPEN when app.identity_id is unset", n)
print("  unset identity sees zero rows, not every row: ok")

# The role and the identity are transaction-scoped: a pooled connection handed
# to the next request must come back as the privileged role, or one user's
# scope would silently become another's.
with st.conn() as sc:
    who = sc.execute("SELECT current_user AS u").fetchone()["u"]
    guc = sc.execute("SELECT current_setting('app.identity_id', true) AS g").fetchone()["g"]
assert who != st.APP_ROLE and not guc, ("RLS context leaked across pooled connections", who, guc)
print("  role and identity do not leak across pooled connections: ok")

# SYBIL vs RLS. This is the interaction that matters: RLS hides other
# identities' rows, so anything that depended on SEEING them to stay correct
# would now silently fail open. Both halves of the sybil defence are checked
# against a row the querying identity cannot read.
with st.user_conn(rls_b["id"]) as uc:
    vis = uc.execute("SELECT count(*) AS n FROM wallet_bindings WHERE address=%s",
                     (addr_a,)).fetchone()["n"]
assert vis == 0, "RLS should hide A's binding from B"

# (a) The unique index. Indexes are not RLS-filtered, so a same-tier collision
# is still detected. rls_c has no incumbent, so its bind is ACTIVE — the same
# tier as A's — which is what ux_active_chain_address arbitrates.
rls_c = st.upsert_identity(secrets.token_hex(16), "RLS Carol", "")
try:
    st.create_binding(rls_c["id"], "evm", addr_a, secrets.token_hex(8), "s", "m", 72)
    raise AssertionError("RLS hid A's row and the sybil index was lost with it")
except st.BindingConflict as e:
    assert isinstance(e.__cause__, psycopg.errors.UniqueViolation), e.__cause__
print("  unique index still rejects a claim on a row RLS hides: ok")

# (b) The cross-tier case the index cannot cover (B already holds a wallet, so
# its second bind would be PENDING against A's ACTIVE — different partial
# indexes, no collision). That gap is why address_claimed_by_other exists, and
# why it must keep running privileged: an RLS-scoped version would see nothing
# and cheerfully report the address free. Assert the check AND the endpoint.
assert st.address_claimed_by_other("evm", addr_a, rls_b["id"]), \
    "the cross-identity sybil check must still see other identities"
r = c2.post(f"{B}/api/wallet/nonce", json={"chain": "evm", "address": addr_a})
assert r.status_code == 409, ("HTTP path let a second identity claim a taken wallet",
                              r.status_code, r.text[:120])
print("  cross-tier claim refused by the privileged check and by HTTP: ok")

step("28. R2/R3: the registry is neither public nor reachable without an audit entry")
# The registry IS the sensitive cross-user join — every verified person mapped
# to the wallets they control. R2 put it behind a session; R3 makes it
# operator-only and logged, because "some session" let an operator read the
# whole mapping by the one route that left no trace.
anon2 = httpx.Client(follow_redirects=False, timeout=30)
r = anon2.post(f"{B}/api/registry", json={"reason": "just having a look"})
assert r.status_code == 401, ("registry served an anonymous caller", r.status_code)
r = c.post(f"{B}/api/registry", json={"reason": "just having a look"})
assert r.status_code == 403, ("registry served a non-operator", r.status_code)
# And the old unaudited GET must be gone, not merely unused by the frontend.
assert c.get(f"{B}/api/registry").status_code in (404, 405), \
    "the unaudited GET /api/registry still exists"
print("  registry refuses anonymous, non-operator, and the old unaudited GET: ok")

step("29. R2 passkey return-login: register with Fayda, return without it")
# A software authenticator: real ES256 keys, real client-data and
# authenticator-data byte layouts, real signatures. The server code under test
# is the same code a hardware key drives — only the key custody differs, so a
# passing run means the WebAuthn verification path actually works rather than
# that a mock agreed with itself.
import cbor2, hashlib as _hl, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes as _hh
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature)

RP_ID = "127.0.0.1"
ORIGIN = B


def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64ud(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """Minimal CTAP2-shaped authenticator: ES256, resident key, UV set."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.sign_count = 0

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1,
                            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _auth_data(self, attested: bool):
        # flags: UP | UV | (AT when attesting)
        flags = 0x01 | 0x04 | (0x40 if attested else 0)
        d = _hl.sha256(RP_ID.encode()).digest() + bytes([flags]) + \
            struct.pack(">I", self.sign_count)
        if attested:
            d += b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + \
                 self.cred_id + self._cose()
        return d

    def register(self, challenge_b64):
        cd = json.dumps({"type": "webauthn.create", "challenge": challenge_b64,
                         "origin": ORIGIN, "crossOrigin": False},
                        separators=(",", ":")).encode()
        ad = self._auth_data(True)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "attestationObject": b64u(att)}}

    def assert_(self, challenge_b64, *, bump=True, origin=None):
        if bump:
            self.sign_count += 1
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge_b64,
                         "origin": origin or ORIGIN, "crossOrigin": False},
                        separators=(",", ":")).encode()
        ad = self._auth_data(False)
        sig = self.key.sign(ad + _hl.sha256(cd).digest(), ec.ECDSA(_hh.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad),
                             "signature": b64u(sig), "userHandle": None}}


auth = SoftAuthenticator()

# Registration requires a Fayda-verified session. Anonymous must be refused —
# otherwise a passkey could mint an identity Fayda never proved.
assert anon.post(f"{B}/api/passkey/register/begin").status_code == 401, \
    "anonymous caller could begin passkey registration"
print("  registration refused without a Fayda session: ok")

me_before = c.get(f"{B}/api/me").json()
opts = c.post(f"{B}/api/passkey/register/begin").json()
r = c.post(f"{B}/api/passkey/register/complete",
           json={"credential": auth.register(opts["challenge"]), "label": "test key"})
assert r.status_code == 200, (r.status_code, r.text[:200])
assert len(r.json()["passkeys"]) >= 1, r.json()
print("  passkey registered against the Fayda-verified identity: ok")

# The return-login: a brand-new client with no cookie from the Fayda flow.
ret = httpx.Client(follow_redirects=False, timeout=30)
assert not ret.get(f"{B}/api/me").json()["authenticated"], "new client started authenticated"
opts = ret.post(f"{B}/api/passkey/login/begin").json()
r = ret.post(f"{B}/api/passkey/login/complete",
             json={"credential": auth.assert_(opts["challenge"])})
assert r.status_code == 200, (r.status_code, r.text[:200])
back = ret.get(f"{B}/api/me").json()
assert back["authenticated"], "passkey sign-in did not establish a session"
assert back["identity"]["id"] == me_before["identity"]["id"], \
    ("passkey signed in as the wrong identity", back["identity"]["id"])
print(f"  returned as {back['identity']['display_name']} without re-running Fayda: ok")

# A passkey proves device control, not a fresh Fayda authentication: it must
# not resurrect neighbourhood-level claims from the earlier session.
assert "address" not in back["claims"] and "residenceStatus" not in back["claims"], \
    ("passkey session exposed kebele/woreda claims", list(back["claims"]))
assert back["claims"].get("name"), "passkey session lost the display name"
print("  passkey session carries name/birthdate only, no kebele/woreda: ok")

# Challenge is single-use: replaying the same assertion must fail.
replayed = auth.assert_(opts["challenge"], bump=False)
r2 = httpx.Client(follow_redirects=False, timeout=30)
r2.post(f"{B}/api/passkey/login/begin")
r = r2.post(f"{B}/api/passkey/login/complete", json={"credential": replayed})
assert r.status_code == 400, ("a replayed assertion was accepted", r.status_code)
print("  replayed assertion rejected (challenge is single-use): ok")

# Wrong origin must fail even with a valid signature — this is the property
# that makes a passkey phishing-resistant, so it has to be pinned.
r3 = httpx.Client(follow_redirects=False, timeout=30)
opts = r3.post(f"{B}/api/passkey/login/begin").json()
r = r3.post(f"{B}/api/passkey/login/complete",
            json={"credential": auth.assert_(opts["challenge"],
                                             origin="https://evil.example.com")})
assert r.status_code == 400, ("an assertion from a foreign origin was accepted",
                              r.status_code)
print("  assertion from a foreign origin rejected: ok")

# An unknown credential must be INDISTINGUISHABLE from a bad signature — a
# credential id is not secret, so a differing message turns this endpoint into
# "is this passkey registered here?" for any caller. Compare both answers.
r4 = httpx.Client(follow_redirects=False, timeout=30)
opts = r4.post(f"{B}/api/passkey/login/begin").json()
ghost = SoftAuthenticator()
unknown = r4.post(f"{B}/api/passkey/login/complete",
                  json={"credential": ghost.assert_(opts["challenge"])})
assert unknown.status_code == 400, unknown.status_code

r5 = httpx.Client(follow_redirects=False, timeout=30)
opts = r5.post(f"{B}/api/passkey/login/begin").json()
forged = auth.assert_(opts["challenge"], bump=False)       # real, registered id...
forged["response"]["signature"] = b64u(secrets.token_bytes(70))   # ...bad signature
badsig = r5.post(f"{B}/api/passkey/login/complete", json={"credential": forged})
assert badsig.status_code == 400, badsig.status_code
assert unknown.text == badsig.text, \
    ("unknown credential is distinguishable from a bad signature — enumeration oracle",
     unknown.text[:90], badsig.text[:90])
print("  unknown credential and bad signature answer identically: ok")

# RLS covers the credential table too: one identity must not see another's.
with st.user_conn(rls_a["id"]) as uc:
    n = uc.execute("SELECT count(*) AS n FROM webauthn_credentials").fetchone()["n"]
assert n == 0, ("another identity's passkeys were visible under RLS", n)
print("  webauthn_credentials is RLS-scoped per identity: ok")

step("30. a stolen session must not buy PERMANENT access via a passkey")
# The cooling period exists because a live session can be compromised, and the
# real user must be able to recover. A passkey outlives logout, so if a stolen
# session could mint one — or if one passkey could mint another — a temporary
# compromise would become permanent and unrecoverable. Two rules make it
# recoverable: only a Fayda-established session may register, and the owner can
# always revoke.
pk_session = ret          # the client that signed in with a passkey in test 29
assert pk_session.get(f"{B}/api/me").json()["auth_method"] == "passkey"
# The Fayda-established session must say so explicitly rather than relying on
# the key's absence — this field is what gates passkey registration.
assert c.get(f"{B}/api/me").json()["auth_method"] == "fayda", \
    "a Fayda session must record auth_method explicitly"
r = pk_session.post(f"{B}/api/passkey/register/begin")
assert r.status_code == 403, \
    ("a passkey was able to register another passkey — compromise becomes permanent",
     r.status_code)
print("  a passkey session cannot chain-register another passkey: ok")

# The owner (Fayda-verified) can revoke. Register a second key, then remove it.
extra = SoftAuthenticator()
opts = c.post(f"{B}/api/passkey/register/begin").json()
r = c.post(f"{B}/api/passkey/register/complete",
           json={"credential": extra.register(opts["challenge"]), "label": "attacker key"})
assert r.status_code == 200, (r.status_code, r.text[:160])
before = {p["credential_id"] for p in c.get(f"{B}/api/me").json()["passkeys"]}
assert b64u(extra.cred_id) in before, "the second passkey was not registered"

r = c.post(f"{B}/api/passkey/revoke", json={"credential_id": b64u(extra.cred_id)})
assert r.status_code == 200, (r.status_code, r.text[:160])
after = {p["credential_id"] for p in c.get(f"{B}/api/me").json()["passkeys"]}
assert b64u(extra.cred_id) not in after, "revoke did not remove the passkey"
print("  the owner can revoke a passkey: ok")

# A revoked passkey must stop working, not merely disappear from the list.
gone = httpx.Client(follow_redirects=False, timeout=30)
opts = gone.post(f"{B}/api/passkey/login/begin").json()
r = gone.post(f"{B}/api/passkey/login/complete",
              json={"credential": extra.assert_(opts["challenge"])})
assert r.status_code == 400, ("a revoked passkey still signs in", r.status_code)
assert not gone.get(f"{B}/api/me").json()["authenticated"]
print("  a revoked passkey no longer signs in: ok")

# One identity must not revoke another's credential, even knowing its id.
still_mine = {p["credential_id"] for p in c.get(f"{B}/api/me").json()["passkeys"]}
victim_cred = next(iter(still_mine))
r = c2.post(f"{B}/api/passkey/revoke", json={"credential_id": victim_cred})
assert r.status_code == 404, ("one identity revoked another's passkey", r.status_code)
assert victim_cred in {p["credential_id"] for p in c.get(f"{B}/api/me").json()["passkeys"]}
print("  another identity cannot revoke it: ok")

step("30b. revocation ends the session the passkey opened, not just the next one")
# An attacker who registered a passkey on a compromised session is ALREADY
# signed in. If revoking only blocked the next sign-in, the attacker keeps
# working for the rest of a 12-hour TTL and the escape hatch is decorative.
tmp = SoftAuthenticator()
opts = c.post(f"{B}/api/passkey/register/begin").json()
assert c.post(f"{B}/api/passkey/register/complete",
              json={"credential": tmp.register(opts["challenge"]),
                    "label": "session-kill"}).status_code == 200
live = httpx.Client(follow_redirects=False, timeout=30)
opts = live.post(f"{B}/api/passkey/login/begin").json()
assert live.post(f"{B}/api/passkey/login/complete",
                 json={"credential": tmp.assert_(opts["challenge"])}).status_code == 200
assert live.get(f"{B}/api/me").json()["authenticated"], "the passkey session did not open"
r = c.post(f"{B}/api/passkey/revoke", json={"credential_id": b64u(tmp.cred_id)})
assert r.status_code == 200 and r.json()["sessions_ended"] >= 1, r.text[:160]
assert not live.get(f"{B}/api/me").json()["authenticated"], \
    "revoking the passkey left its session alive"
r = live.post(f"{B}/api/wallet/nonce", json={"chain": "evm", "address": rnd_addr()})
assert r.status_code == 401, ("the revoked session can still act", r.status_code)
print("  revoking a passkey signs out the session it created: ok")

step("30c. a stale session cannot mint a passkey, even one Fayda established")
# Gating on how the session was CREATED still lets a stolen cookie register at
# any point in the session's 12 hours — the theft inherits the victim's Fayda
# login. Registration therefore also requires a RECENT verification. Backdate
# this session's auth_at through the store to test it deterministically rather
# than by waiting.
sid_now = c.cookies.get("session").rsplit(".", 1)[0]
with st.conn() as sc:
    row = sc.execute("SELECT data FROM sessions WHERE sid=%s", (sid_now,)).fetchone()
    stale = dict(row["data"])
    fresh_at = stale["auth_at"]
    stale["auth_at"] = st.iso(st.now() - st.timedelta(hours=3))
    sc.execute("UPDATE sessions SET data=%s WHERE sid=%s", (Json(stale), sid_now))
r = c.post(f"{B}/api/passkey/register/begin")
assert r.status_code == 403, ("a 3-hour-old session could still add a passkey",
                              r.status_code)
# Restore, and confirm a fresh session is still allowed — otherwise this test
# would pass just as well against a route that always refuses.
with st.conn() as sc:
    stale["auth_at"] = fresh_at
    sc.execute("UPDATE sessions SET data=%s WHERE sid=%s", (Json(stale), sid_now))
assert c.post(f"{B}/api/passkey/register/begin").status_code == 200, \
    "a freshly verified session must still be able to register"
print("  registration requires a recent Fayda verification, not just any: ok")

step("31. malformed passkey bodies are client errors, never 500s")
# These routes are reachable unauthenticated, so an unhandled shape is a free
# server error for anybody who asks.
for body in ('not json at all', '[]', '"hello"', '{"credential": "nope"}',
             '{"credential": {"id": 12345}}'):
    r = httpx.post(f"{B}/api/passkey/login/complete", content=body,
                   headers={"Content-Type": "application/json"}, timeout=30)
    assert r.status_code < 500, (f"malformed body produced {r.status_code}", body[:40])
r = c.post(f"{B}/api/passkey/register/complete",
           json={"credential": {"id": "x"}, "label": "bad\x00label"})
assert r.status_code < 500, ("a NUL in the label reached storage", r.status_code)
print("  malformed and NUL-bearing bodies all answered without a 500: ok")

step("32. R2 hygiene: fail-closed policy, reset keeps the FK, registry minimised")
# (a) An unbound transaction must match NOTHING, including on INSERT. On a
# REUSED pooled connection current_setting returns '' rather than NULL, so a
# bare comparison becomes `id = ''` — an ordinary predicate an unbound
# transaction can satisfy, and then share with every other unbound transaction.
with st.conn() as sc:
    sc.execute("SELECT set_config('app.identity_id', 'someone', true)")
with st.conn() as sc:
    sc.execute(f"SET LOCAL ROLE {st.APP_ROLE}")
    try:
        sc.execute("""INSERT INTO identities (id, fin_hmac, display_name,
                      verified_at, last_seen_at) VALUES ('','ghost','Ghost',%s,%s)""",
                   (st.iso(st.now()), st.iso(st.now())))
        raise AssertionError("an unbound RLS transaction inserted a row (fails OPEN)")
    except psycopg.errors.InsufficientPrivilege:
        pass
print("  an unbound transaction can neither read nor write: ok")

# (b) reset() must not leave orphaned passkeys or silently drop the FK.
st.reset()
with st.conn() as sc:
    fk = sc.execute(
        """SELECT 1 FROM pg_constraint
           WHERE conrelid='webauthn_credentials'::regclass AND contype='f'""").fetchone()
    orphans = sc.execute("SELECT count(*) AS n FROM webauthn_credentials").fetchone()["n"]
assert fk, "reset() dropped the credentials foreign key and never restored it"
assert orphans == 0, ("reset() left passkeys for identities it erased", orphans)
print("  reset recreates the FK and leaves no orphaned passkeys: ok")

# (c) The registry hands other users the least that still answers the question.
ident_r = st.upsert_identity(secrets.token_hex(16), "Registry Visible", "")
st.upsert_identity(secrets.token_hex(16), "No Wallet Yet", "")
st.create_binding(ident_r["id"], "evm", rnd_addr(), secrets.token_hex(8), "s", "m", 72)
listed = st.registry()
names = {e["display_name"] for e in listed}
assert "Registry Visible" in names, "an identity with an active wallet is missing"
assert "No Wallet Yet" not in names, \
    "an identity with no wallet is disclosed — sensitive half without the useful half"
assert all("id" not in e and "fin_hmac" not in e for e in listed), \
    ("registry leaks the internal id or the FIN HMAC", listed[0].keys())
print("  registry lists only wallet-holders, without internal id or HMAC: ok")

# (d) DEMO_MODE publishes a login anyone can perform, so it must never sit in
# front of real Fayda identities. Documentation does not enforce that; a
# startup refusal does.
p = server(8112, {"APP_ENV": "production", "DEMO_MODE": "1",
                  "SESSION_SECRET": "x" * 32, "FIN_PEPPER": "y" * 32,
                  "FAYDA_TOKEN_URL": "https://partner.fayda.et/v1/token"})
out = p.communicate(timeout=60)[0]
assert p.returncode != 0, "DEMO_MODE started against a real Fayda endpoint"
assert "refusing to start" in out, out[-400:]
print("  DEMO_MODE + a real Fayda endpoint refuses to boot: ok")

step("33. R3 operator role: no cross-user visibility without an operator")
# Test 32 reset the schema, which drops sessions — everyone is signed out.
# Sign back in through the real Fayda flow rather than reaching into the DB,
# so the operator below holds a session the app actually issued.
def fayda_login(cl, fin):
    loc = cl.get(f"{B}/login").headers["location"]
    page = cl.get(loc).text
    stt = re.search(r'name="state" value="([^"]*)"', page).group(1)
    rr = cl.post(f"{B}/authorize/confirm",
                 data={"fin": fin, "redirect_uri": f"{B}/callback",
                       "state": stt, "nonce": "n"})
    cd = re.search(r"code=([^&]+)", rr.headers["location"]).group(1)
    cl.get(f"{B}/callback", params={"code": cd, "state": stt})
    return cl.get(f"{B}/api/me").json()

assert fayda_login(c, fins[0])["authenticated"], "could not re-establish a session"

# c is a signed-in ordinary user. Every operator route must refuse it — the
# whole point of R3 is that "authenticated" is not "allowed to read other
# people".
subject = st.upsert_identity(secrets.token_hex(16), "Audited Subject", "1990-01-01")
for path, payload in (("/api/operator/search", {"query": "Audited", "reason": "checking things"}),
                      ("/api/operator/identity", {"identity_id": subject["id"],
                                                  "reason": "checking things"}),
                      ("/api/operator/access-log", {})):
    r = c.post(f"{B}{path}", json=payload)
    assert r.status_code == 403, (f"{path} served a non-operator", r.status_code)
r = anon.post(f"{B}/api/operator/search", json={"query": "x", "reason": "checking things"})
assert r.status_code == 401, ("operator route served an anonymous caller", r.status_code)
print("  ordinary users and anonymous callers are refused: ok")

# Grant through the store, as the CLI does — never over HTTP.
me_id = c.get(f"{B}/api/me").json()["identity"]["id"]
st.grant_operator(me_id, granted_by="t.py", note="test operator")
assert st.is_operator(me_id)
# There must be no HTTP route that grants this. Check the actual route table,
# not the source text — an earlier version of this assertion stripped
# "store.grant_operator" before searching, so a route that called exactly that
# would have passed it. Vacuous.
import app as _app
for _r in _app.app.routes:
    _fn = getattr(_r, "endpoint", None)
    if _fn is None:
        continue
    _src = ""
    try:
        import inspect as _inspect
        _src = _inspect.getsource(_fn)
    except Exception:
        pass
    assert "grant_operator" not in _src, \
        (f"route {getattr(_r, 'path', '?')} can grant the operator role", _fn.__name__)
print("  operator granted out of band; no route in the app can grant it: ok")

step("34. R3: every operator lookup is logged BEFORE the data is returned")
before = st.access_log_all(limit=1)["total"]
# A reason is mandatory and must be substantive.
for bad in ("", "   ", "why"):
    r = c.post(f"{B}/api/operator/identity",
               json={"identity_id": subject["id"], "reason": bad})
    assert r.status_code == 400, ("a lookup without a real reason was allowed", bad)
assert st.access_log_all(limit=1)["total"] == before, \
    "a refused lookup still wrote a log entry"
print("  a lookup without a substantive reason is refused: ok")

r = c.post(f"{B}/api/operator/identity",
           json={"identity_id": subject["id"], "reason": "AML review case 4471"})
assert r.status_code == 200, (r.status_code, r.text[:160])
assert r.json()["identity"]["display_name"] == "Audited Subject"
page = st.access_log_all(limit=1000)
entries = page["entries"]
assert page["total"] == before + 1, ("the lookup was not logged", page["total"], before)
e = entries[0]
assert e["actor_id"] == me_id and e["subject_id"] == subject["id"], e
assert e["action"] == "view_identity" and e["reason"] == "AML review case 4471", e
assert e["at"], "log entry has no timestamp"
print(f"  logged who/whom/when/why: {e['action']} by operator on subject: ok")

# A lookup for a nonexistent identity is still logged — probing for which
# identities exist is itself something a reviewer should see.
ghost_id = str(uuid.uuid4())
n = st.access_log_all(limit=1)["total"]
r = c.post(f"{B}/api/operator/identity",
           json={"identity_id": ghost_id, "reason": "AML review case 4472"})
assert r.status_code == 404, r.status_code
assert st.access_log_all(limit=1)["total"] == n + 1, "a probe for a missing identity went unlogged"
print("  probing for a nonexistent identity is logged too: ok")

# Reading the log is itself logged.
n = st.access_log_all(limit=1)["total"]
r = c.post(f"{B}/api/operator/access-log")
assert r.status_code == 200, r.text[:160]
assert st.access_log_all(limit=1)["total"] == n + 1, "reading the access log went unlogged"
print("  reading the access log is itself logged: ok")

step("35. R3: the access log is append-only, enforced by the database")
# Not "the app never updates it" — the app connects as the table owner, so a
# GRANT alone would prove nothing. A trigger must refuse every caller.
target = st.access_log_all(limit=1)["entries"][0]["id"]
for sql, args in (
    ("UPDATE access_log SET reason='covered up' WHERE id=%s", (target,)),
    ("DELETE FROM access_log WHERE id=%s", (target,)),
):
    try:
        with st.conn() as sc:
            sc.execute(sql, args)
        raise AssertionError(f"access_log accepted: {sql.split()[0]}")
    except psycopg.errors.RaiseException as exc:
        assert "append-only" in str(exc), exc
still = [e for e in st.access_log_all(limit=1000)["entries"] if e["id"] == target]
assert len(still) == 1 and still[0]["reason"] != "covered up", "the log entry was altered"
print("  UPDATE and DELETE both refused by the database, row intact: ok")

step("36. R3: a person can see who looked at their record, and only that")
# The surveillance R4 builds on is one-directional by nature. This is the
# smallest thing that makes it observable by the person being surveilled.
subject_client_id = subject["id"]
mine = st.access_log_about(subject_client_id)["entries"]
assert mine and all(m["action"] == "view_identity" for m in mine), mine
assert any(m["reason"] == "AML review case 4471" for m in mine), mine
# ... and RLS must stop it becoming a window onto everyone else's entries.
other = st.upsert_identity(secrets.token_hex(16), "Unwatched Person", "")
assert st.access_log_about(other["id"])["entries"] == [], \
    "a person with no accesses saw someone else's log entries"
r = c.get(f"{B}/api/me/access-log")
assert r.status_code == 200 and isinstance(r.json()["entries"], list), r.text[:120]
print("  the subject sees accesses about them, and nobody else's: ok")

step("37. R3: the audit trail cannot be evicted, truncated, or made anonymous")
# (a) Eviction by volume. An unpaginated LIMIT meant an actor could bury an
# entry simply by generating more: the row survived in the table but fell off
# the only view anyone reads. Page past the noise and the old entry must still
# be reachable, and the total must reveal the truncation.
marker = "AML review case 4471"
noise_reason = "routine bulk review pass"
for _ in range(30):
    c.post(f"{B}/api/operator/identity",
           json={"identity_id": subject["id"], "reason": noise_reason})
first = st.access_log_all(limit=5)
assert first["total"] > 5, "total must report everything, not just the page"
assert first["next_before"], "a truncated page must offer a cursor"
seen, cursor, pages = [], first["next_before"], 0
seen += [e["reason"] for e in first["entries"]]
while cursor and pages < 40:
    pg = st.access_log_all(limit=5, before=cursor)
    seen += [e["reason"] for e in pg["entries"]]
    cursor, pages = pg["next_before"], pages + 1
assert marker in seen, "an older entry became unreachable behind newer noise"
print(f"  paged {pages+1} pages through {first['total']} entries, old entry still reachable: ok")

# The subject's own view must page too — it is their only window.
sub_page = st.access_log_about(subject["id"], limit=5)
assert sub_page["total"] > 5 and sub_page["next_before"], sub_page["total"]
sub_seen, cur, n = [], sub_page["next_before"], 0
sub_seen += [e["reason"] for e in sub_page["entries"]]
while cur and n < 40:
    pg = st.access_log_about(subject["id"], limit=5, before=cur)
    sub_seen += [e["reason"] for e in pg["entries"]]
    cur, n = pg["next_before"], n + 1
assert marker in sub_seen, "the subject could not page back to an older access"
print("  the subject can page back to an older access too: ok")

# (a2) Timestamps are not unique — a search writes one entry per result in a
# tight loop. A cursor on `at` alone skips every row sharing the last row's
# timestamp, which is the same eviction with a smaller window. Plant an exact
# collision and page through it one row at a time.
collide_at = st.iso(st.now())
collide_subject = st.upsert_identity(secrets.token_hex(16), "Collision Subject", "")
planted = set()
with st.conn() as sc:
    for k in range(5):
        eid = f"collide-{secrets.token_hex(6)}"
        planted.add(eid)
        sc.execute(
            """INSERT INTO access_log (id, at, actor_id, subject_id, action, reason)
               VALUES (%s,%s,%s,%s,'view_identity',%s)""",
            (eid, collide_at, me_id, collide_subject["id"], f"same-microsecond {k}"))
walked, cursor, guard = set(), None, 0
while guard < 60:
    pg = st.access_log_all(limit=1, before=cursor)
    if not pg["entries"]:
        break
    walked.update(e["id"] for e in pg["entries"])
    cursor, guard = pg["next_before"], guard + 1
    if planted <= walked:
        break
assert planted <= walked, \
    ("paging skipped entries sharing a timestamp", len(planted - walked))
print(f"  {len(planted)} entries at an identical timestamp all reachable: ok")

# (b) TRUNCATE does not fire row triggers — the single most effective way to
# erase the whole log. A statement trigger must catch it.
try:
    with st.conn() as sc:
        sc.execute("TRUNCATE access_log")
    raise AssertionError("TRUNCATE erased the access log")
except psycopg.errors.RaiseException as exc:
    assert "append-only" in str(exc), exc
print("  TRUNCATE refused: ok")

# (c) A plain trigger is skipped when session_replication_role='replica',
# which turns both guards off in one statement. ENABLE ALWAYS must defeat it.
try:
    with st.conn() as sc:
        sc.execute("SET session_replication_role = replica")
        sc.execute("DELETE FROM access_log WHERE id=%s", (target,))
    raise AssertionError("replica mode bypassed the append-only trigger")
except psycopg.errors.RaiseException as exc:
    assert "append-only" in str(exc), exc
assert any(e["id"] == target for e in st.access_log_all(limit=1000)["entries"]), \
    "the entry disappeared despite the refusal"
print("  session_replication_role=replica does not bypass it: ok")

# (d) Search made the discovery phase invisible: one entry naming the query,
# none naming who was returned, so no subject ever learned they surfaced.
found = st.upsert_identity(secrets.token_hex(16), "Searchable Person", "")
n_before = len(st.access_log_about(found["id"], limit=1000)["entries"])
r = c.post(f"{B}/api/operator/search",
           json={"query": "Searchable", "reason": "sanctions screening sweep"})
assert r.status_code == 200 and r.json()["results"], r.text[:160]
mine_now = st.access_log_about(found["id"], limit=1000)["entries"]
assert len(mine_now) == n_before + 1, \
    ("a search surfaced this person without telling them", len(mine_now), n_before)
assert mine_now[0]["action"] == "search_result", mine_now[0]
# ... and search must not hand out more than it needs to pick a record.
assert all("birthdate" not in x and "fin_hmac" not in x for x in r.json()["results"]), \
    "search results carry more than is needed to choose a record"
print("  each identity a search surfaces is logged to that person: ok")

# (e) The operator's full view must not re-expose the correlation key.
r = c.post(f"{B}/api/operator/identity",
           json={"identity_id": subject["id"], "reason": "AML review case 4473"})
assert r.status_code == 200 and "fin_hmac" not in r.text, \
    "the operator record re-exposes the FIN HMAC"
print("  the operator record withholds fin_hmac like the registry does: ok")

step("38. R3: operator powers need a Fayda session, and authority is itself logged")
# A passkey session was too weak to add another passkey yet strong enough to
# read every identity in the registry. Operator powers are the more sensitive
# of the two.
pk_op = httpx.Client(follow_redirects=False, timeout=30)
op_key = SoftAuthenticator()
opts = c.post(f"{B}/api/passkey/register/begin").json()
assert c.post(f"{B}/api/passkey/register/complete",
              json={"credential": op_key.register(opts["challenge"]),
                    "label": "operator device"}).status_code == 200
opts = pk_op.post(f"{B}/api/passkey/login/begin").json()
assert pk_op.post(f"{B}/api/passkey/login/complete",
                  json={"credential": op_key.assert_(opts["challenge"])}).status_code == 200
assert pk_op.get(f"{B}/api/me").json()["identity"]["id"] == me_id, "signed in as someone else"
r = pk_op.post(f"{B}/api/operator/identity",
               json={"identity_id": subject["id"], "reason": "AML review case 4474"})
assert r.status_code == 403, ("a passkey session exercised operator powers", r.status_code)
print("  the same operator on a passkey session is refused: ok")

# Granting and revoking the power is itself part of the trail.
newbie = st.upsert_identity(secrets.token_hex(16), "Future Operator", "")
n = st.access_log_all(limit=1)["total"]
st.grant_operator(newbie["id"], granted_by="t.py", note="temporary access")
st.revoke_operator(newbie["id"], revoked_by="t.py")
after = st.access_log_all(limit=10)["entries"]
actions = [e["action"] for e in after[:2]]
assert "grant_operator" in actions and "revoke_operator" in actions, actions
assert st.access_log_all(limit=1)["total"] == n + 2, "grant/revoke were not both logged"
assert not st.is_operator(newbie["id"]), "revoke did not take effect"
# Revocation is a tombstone: the record of who once held the power survives.
with st.conn() as sc:
    row = sc.execute("SELECT revoked_at FROM operators WHERE identity_id=%s",
                     (newbie["id"],)).fetchone()
assert row and row["revoked_at"], "revoking deleted the record of the grant"
print("  grant and revoke are logged; revocation leaves a tombstone: ok")

step("39. R3 hygiene: in-place migration, bulk disclosure logged, cursor errors")
# (a) CREATE TABLE IF NOT EXISTS adds nothing to a table that already exists,
# so revoked_at would never appear on a database created before revocation
# existed — and every operator route would then 500 on UndefinedColumn.
# Fail-closed, but silent until somebody needs compliance access.
with st.conn() as sc:
    sc.execute("ALTER TABLE operators DROP COLUMN IF EXISTS revoked_at")
    gone = sc.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name='operators' "
        "AND column_name='revoked_at'").fetchone()
assert not gone, "failed to simulate the old table shape"
st.init()
with st.conn() as sc:
    back = sc.execute(
        "SELECT 1 FROM information_schema.columns WHERE table_name='operators' "
        "AND column_name='revoked_at'").fetchone()
assert back, "init() did not migrate an existing operators table in place"
assert st.is_operator(me_id), "the operator lost their role across the migration"
print("  an older operators table gains revoked_at on boot: ok")

# (b) The registry discloses every bound identity's name AND both wallet
# addresses in one call — more than search does — so it must log per subject
# too, or the bulk route stays quieter than the narrow one.
listed = st.registry_ids()
assert listed, "need at least one wallet-holder for this to mean anything"
watched = listed[0]
n_before = st.access_log_about(watched, limit=1)["total"]
r = c.post(f"{B}/api/registry", json={"reason": "quarterly registry review"})
assert r.status_code == 200, (r.status_code, r.text[:160])
n_after = st.access_log_about(watched, limit=1)["total"]
assert n_after == n_before + 1, \
    ("a registry listing disclosed this person without telling them", n_before, n_after)
recent = st.access_log_about(watched, limit=5)["entries"][0]
assert recent["action"] == "listed_in_registry", recent
print("  a bulk registry listing is logged to every person it discloses: ok")

# (c) A malformed cursor must not silently rewind to page one — a reader would
# loop on the head of the log believing they were paging back through it.
for bad in ("garbage", "no-separator", "|", "abc|"):
    r = c.get(f"{B}/api/me/access-log", params={"before": bad})
    assert r.status_code == 400, ("a malformed cursor was accepted", bad, r.status_code)
print("  a malformed paging cursor is rejected, not silently reset: ok")

# (d) A CLI grant must name the human who ran it.
assert st.cli_actor().startswith("cli:") and "@" in st.cli_actor(), st.cli_actor()
who = st.upsert_identity(secrets.token_hex(16), "CLI Granted", "")
st.grant_operator(who["id"], granted_by=st.cli_actor(), note="from the CLI")
entry = [e for e in st.access_log_all(limit=20)["entries"]
         if e["action"] == "grant_operator" and e["subject_id"] == who["id"]][0]
assert entry["actor_id"].startswith("cli:") and len(entry["actor_id"]) > 5, entry
st.revoke_operator(who["id"], revoked_by=st.cli_actor())
print(f"  a CLI grant records who ran it ({entry['actor_id'][:28]}…): ok")

step("40. R4/F1: the in-app timeline is assembled from the bindings themselves")
# The timeline is derived from binding timestamps rather than kept in a
# parallel event table, so it cannot drift out of sync with what it describes.
# Build a full lifecycle and check every transition appears exactly once.
tl_id = st.upsert_identity(secrets.token_hex(16), "Timeline Subject", "1988-03-03")
w1, w2, w3 = rnd_addr(), rnd_addr(), rnd_addr()
st.create_binding(tl_id["id"], "evm", w1, secrets.token_hex(8), "s", "m", 72)  # immediate
st.create_binding(tl_id["id"], "evm", w2, secrets.token_hex(8), "s", "m", 72)  # pending
st.force_due(tl_id["id"], "evm")
st.promote_due(tl_id["id"])                                        # w2 activates, w1 archived
st.create_binding(tl_id["id"], "evm", w3, secrets.token_hex(8), "s", "m", 72)  # pending
st.cancel_pending(tl_id["id"], "evm")                              # w3 cancelled

tl = st.identity_timeline(tl_id["id"])
kinds = [e["kind"] for e in tl]
assert kinds.count("identity_verified") == 1, kinds
assert "wallet_bound" in kinds, kinds
assert "replacement_requested" in kinds and "replacement_activated" in kinds, kinds
assert "binding_archived" in kinds, ("the replaced wallet is not in the timeline", kinds)
assert "binding_cancelled" in kinds, ("the cancelled replacement is missing", kinds)
# Newest first, and every event timestamped.
ats = [e["at"] for e in tl]
assert all(ats) and ats == sorted(ats, reverse=True), ("timeline is not ordered", ats)
# Events name the wallet they concern, so a reviewer can follow one address.
assert {e["address"] for e in tl if e["address"]} == {w1, w2, w3}, \
    "timeline events do not identify their wallet"
assert st.identity_timeline(str(uuid.uuid4())) == [], "unknown identity produced events"
print(f"  {len(tl)} events across bind/replace/promote/cancel, ordered: ok")

step("41. R4: history is operator-only, logged, and absent from every user view")
# c2 is an ordinary signed-in user (its earlier session died with test 32's
# reset). It must be refused for lack of the ROLE, not for lack of a session —
# 401 would pass this assertion for the wrong reason.
assert fayda_login(c2, fins[2])["authenticated"], "could not re-establish c2"
assert not st.is_operator(c2.get(f"{B}/api/me").json()["identity"]["id"])
r = c2.post(f"{B}/api/operator/timeline",
            json={"identity_id": tl_id["id"], "reason": "AML case 5001"})
assert r.status_code == 403, ("timeline served a non-operator", r.status_code)
# The anonymous probe must use the inputs that DON'T reach authorization if the
# checks are ordered wrongly. An earlier version of this assertion passed a
# BOUND address — the one input that reached require_operator — so it passed
# while an unauthenticated caller could still distinguish "no such identity"
# from "not bound to this identity" and thereby confirm that a public wallet
# belongs to a specific Fayda identity. Probe all three shapes and require the
# SAME answer to each: any variation is the oracle.
probes = [
    {"identity_id": tl_id["id"], "chain": "evm", "address": w2},        # bound
    {"identity_id": tl_id["id"], "chain": "evm", "address": rnd_addr()},  # not bound
    {"identity_id": str(uuid.uuid4()), "chain": "evm", "address": w2},  # no identity
]
log_before = st.access_log_all(limit=1)["total"]
answers = set()
for p in probes:
    r = anon.post(f"{B}/api/operator/onchain", json={**p, "reason": "AML case 5001"})
    assert r.status_code == 401, ("on-chain answered an anonymous caller", p, r.status_code)
    answers.add((r.status_code, r.text))
assert len(answers) == 1, \
    ("an anonymous caller can distinguish bound from unbound — a linkage oracle",
     answers)
# Nothing was authorized, so nothing may have been written either — an
# unauthenticated caller must not be able to grow the append-only log.
assert st.access_log_all(limit=1)["total"] == log_before, \
    "unauthenticated probes wrote to the access log"
print("  anonymous probes are indistinguishable across bound/unbound/unknown: ok")

n = st.access_log_about(tl_id["id"], limit=1)["total"]
r = c.post(f"{B}/api/operator/timeline",
           json={"identity_id": tl_id["id"], "reason": "AML case 5001"})
assert r.status_code == 200, (r.status_code, r.text[:200])
body = r.json()
assert body["timeline"] and body["identity"]["display_name"] == "Timeline Subject"
assert st.access_log_about(tl_id["id"], limit=1)["total"] == n + 1, \
    "opening a case file went unlogged"
# The most sensitive join must never appear in a user-facing view.
mine = c.get(f"{B}/api/me").text
assert "timeline" not in mine and "transactions" not in mine, \
    "transaction history leaked into the user view"
print("  timeline is operator-only, logged, and not in /api/me: ok")

step("42. R4: the on-chain path is bound to the identity, cached, and degrades")
# (a) An address that is NOT bound to the named identity must be refused —
# otherwise this is a general chain proxy that happens to need an operator,
# and the log entry would name a subject unconnected to the address queried.
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm", "address": rnd_addr(),
                 "reason": "AML case 5002"})
assert r.status_code == 404, ("an unbound address was queried", r.status_code)
print("  an address not bound to this identity is refused: ok")

# (b) With no provider configured the answer must say so — never an empty list
# that reads as "this wallet has never transacted", and never sample data.
import chain as ch
from verify import looks_like_address as vf_looks
ch.clear_cache()
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm", "address": w2,
                 "reason": "AML case 5003"})
assert r.status_code == 200, (r.status_code, r.text[:200])
j = r.json()
assert j["status"] == "not_configured", ("unconfigured provider did not say so", j)
assert j["transactions"] == [], j
assert "no lookup was attempted" in j["detail"], j
print("  unconfigured provider reports it rather than faking an empty history: ok")

# (c) Provider failures degrade to a status, never a 500 and never an
# exception. Point the module at a URL that cannot answer and let the real
# _fetch handle it — mocking _fetch itself here would test the mock.
real_url = ch.EXPLORER_URL
ch.EXPLORER_URL = "http://127.0.0.1:9/explorer"      # port 9 discards
try:
    ch.clear_cache()
    out = ch.transactions("evm", w2)
    assert out["status"] == "provider_unreachable", out
    assert out["transactions"] == [], out
except Exception as exc:
    raise AssertionError(f"a provider failure escaped as an exception: {exc!r}")
finally:
    ch.EXPLORER_URL = real_url
print("  an unreachable provider degrades to a status, not an exception: ok")

# (d) Cached with a TTL, and never persisted as source of truth. The provider
# call is the seam replaced here — the point is the caching behaviour around
# it, not the HTTP parsing exercised above.
ch.clear_cache()
real_fetch = ch._fetch
served = {"n": 0}
def fake_ok(chain_, addr):
    served["n"] += 1
    return {"status": "ok", "detail": "",
            "transactions": [{"hash": "0xabc", "timestamp": "1700000000",
                              "direction": "in", "counterparty": "0xdead",
                              "value_wei": "1000"}]}
def always_down(chain_, addr):
    return {"status": "provider_unreachable", "detail": "down", "transactions": []}
try:
    ch._fetch = fake_ok
    first = ch.transactions("evm", w2)
    second = ch.transactions("evm", w2)
    assert served["n"] == 1, ("the cache did not serve the second call", served["n"])
    assert first["cached"] is False and second["cached"] is True, first["cached"]
    assert second["transactions"] == first["transactions"]
    # A blip after a success must not replace a good entry with an error —
    # caching the failure would hide a recovered provider for the whole TTL.
    ch._fetch = always_down
    third = ch.transactions("evm", w2)
    assert third["status"] == "ok" and third["cached"] is True, \
        ("a provider blip evicted a good cache entry", third)
finally:
    ch._fetch = real_fetch
    ch.clear_cache()
# On-chain data is public and refetchable; it must not become a record here.
with st.conn() as sc:
    tables = {r["tablename"] for r in sc.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall()}
    assert not any("tx" in t or "transaction" in t or "onchain" in t for t in tables), \
        ("on-chain data is being persisted as source of truth", tables)
print("  cached with a TTL, blips do not evict, nothing persisted: ok")

# (e) A CANCELLED binding is a repudiated claim — cancellation is exactly how a
# user kills a swap they did not authorise. Treating it as theirs would pull an
# attacker's address into the victim's case file and write it to a log that
# cannot be corrected. Archived bindings ARE theirs: they were live once.
cancelled_addr = w3          # cancelled during cooling, above
archived_addr = w1           # replaced by w2, archived
assert any(b["address"] == cancelled_addr and b["status"] == "cancelled"
           for b in st.history(tl_id["id"])), "test setup: w3 should be cancelled"
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm",
                 "address": cancelled_addr, "reason": "AML case 5004"})
assert r.status_code == 404, \
    ("a repudiated (cancelled) binding was treated as this identity's wallet",
     r.status_code)
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm",
                 "address": archived_addr, "reason": "AML case 5005"})
assert r.status_code == 200, ("a previously-active wallet should be reviewable",
                              r.status_code, r.text[:120])
print("  cancelled bindings refused, archived ones reviewable: ok")

# (f) A hostile or broken provider must degrade, never 500 — the parse used to
# sit outside the try, so a top-level list came back as an AttributeError
# AFTER the access-log row had been written.
import http.server, socketserver, threading as _th
class Hostile(http.server.BaseHTTPRequestHandler):
    payload = b'[]'
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.end_headers(); self.wfile.write(self.payload)
    def log_message(self, *a): pass

for name, payload in (("top-level list", b"[]"),
                      ("null", b"null"),
                      ("bare string", b'"hello"'),
                      ("not json", b"<html>nope</html>"),
                      ("result not a list", b'{"result": {"a": 1}}'),
                      ("non-dict entries", b'{"result": [1, 2, "three"]}')):
    Hostile.payload = payload
    srv2 = socketserver.TCPServer(("127.0.0.1", 0), Hostile)
    port2 = srv2.server_address[1]
    th = _th.Thread(target=srv2.serve_forever, daemon=True); th.start()
    try:
        ch.EXPLORER_URL = f"http://127.0.0.1:{port2}/api"
        ch.clear_cache()
        out = ch.transactions("evm", archived_addr)
        assert out["status"] in ("provider_error", "provider_unreachable"), (name, out)
        assert out["transactions"] == [], (name, out)
    finally:
        ch.EXPLORER_URL = real_url
        srv2.shutdown(); srv2.server_close()
print("  six hostile provider responses all degrade to a status: ok")

# (g) An oversized response must be cut off rather than materialised.
class Flood(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.end_headers()
        try:
            for _ in range(400):
                self.wfile.write(b'{"result":[' + b'{"x":"' + b'y'*50_000 + b'"},' )
        except Exception:
            pass
    def log_message(self, *a): pass
srv3 = socketserver.TCPServer(("127.0.0.1", 0), Flood)
port3 = srv3.server_address[1]
_th.Thread(target=srv3.serve_forever, daemon=True).start()
try:
    ch.EXPLORER_URL = f"http://127.0.0.1:{port3}/api"
    ch.clear_cache()
    t0 = time.time()
    out = ch.transactions("evm", archived_addr)
    took = time.time() - t0
    assert out["status"] != "ok", ("a 20MB flood was accepted as an answer", out)
    assert took < ch.TOTAL_BUDGET_SECONDS + 5, f"the size cap did not stop it ({took:.1f}s)"
finally:
    ch.EXPLORER_URL = real_url
    ch.clear_cache()
    srv3.shutdown(); srv3.server_close()
print(f"  an oversized response is cut off in {took:.1f}s, not buffered: ok")

# (g2) The slow-drip case, which per-operation timeouts do NOT catch: a
# provider that sends one byte just inside the read timeout, forever. These
# endpoints are sync, so each such request pins a worker thread until the whole
# service stops answering. Only an absolute wall-clock budget bounds it.
class Drip(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length","100000"); self.end_headers()
        try:
            for _ in range(100000):
                self.wfile.write(b"x"); self.wfile.flush(); time.sleep(0.05)
        except Exception:
            pass
    def log_message(self, *a): pass
srv4 = socketserver.TCPServer(("127.0.0.1", 0), Drip)
_th.Thread(target=srv4.serve_forever, daemon=True).start()
try:
    ch.EXPLORER_URL = f"http://127.0.0.1:{srv4.server_address[1]}/api"
    ch.clear_cache()
    t0 = time.time()
    out = ch.transactions("evm", archived_addr)
    drip_took = time.time() - t0
    assert out["status"] == "provider_unreachable", out
    assert drip_took < ch.TOTAL_BUDGET_SECONDS + 4, \
        (f"a slow-drip provider was not bounded ({drip_took:.1f}s) — it would "
         f"pin a worker thread")
finally:
    ch.EXPLORER_URL = real_url
    ch.clear_cache()
    srv4.shutdown(); srv4.server_close()
print(f"  a slow-drip provider is cut off at {drip_took:.1f}s, not left to pin a worker: ok")

# (h) The subject must learn WHICH wallet was traced, not merely that one was.
traced = st.access_log_about(tl_id["id"], limit=50)["entries"]
onchain_entries = [e for e in traced if e["action"] == "view_onchain"]
assert onchain_entries, "no on-chain access reached the subject's view"
assert any(archived_addr in (e.get("detail") or "") for e in onchain_entries), \
    ("the subject cannot tell which of their wallets was traced", onchain_entries[:2])
print("  the subject sees which wallet was traced: ok")

step("43. R4 audit integrity: an attempt is not a trace, and junk is not an address")
# Authorization has to be logged BEFORE the ownership check (that is what
# closed the anonymous oracle), but recording it as a completed trace let an
# operator write a permanent, subject-visible entry claiming they traced any
# address they named — indistinguishable afterwards from a real one. An
# attempt and a completion must be different actions.
before = st.access_log_about(tl_id["id"], limit=1000)["entries"]
n_attempt = sum(1 for e in before if e["action"] == "view_onchain_attempted")
n_done = sum(1 for e in before if e["action"] == "view_onchain")
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm",
                 "address": rnd_addr(), "reason": "AML case 5006"})
assert r.status_code == 404, r.status_code
after = st.access_log_about(tl_id["id"], limit=1000)["entries"]
assert sum(1 for e in after if e["action"] == "view_onchain_attempted") == n_attempt + 1, \
    "a refused lookup left no trace at all"
assert sum(1 for e in after if e["action"] == "view_onchain") == n_done, \
    ("a refused lookup was recorded as a completed trace", n_done)
# ... and a real one records both.
r = c.post(f"{B}/api/operator/onchain",
           json={"identity_id": tl_id["id"], "chain": "evm",
                 "address": archived_addr, "reason": "AML case 5007"})
assert r.status_code == 200, r.text[:160]
final = st.access_log_about(tl_id["id"], limit=1000)["entries"]
assert sum(1 for e in final if e["action"] == "view_onchain") == n_done + 1, \
    "a completed trace was not recorded as one"
print("  refused attempts and completed traces are distinguishable: ok")

# EVM validation was '0x' + any 40 characters, with no hex check, so arbitrary
# text — markup included — reached the permanent log's detail field.
for junk in ("0x" + "<script>alert(1)</script>zzzzzzzzzzzzzzz",
             "0x" + "g" * 40, "0x" + "!" * 40):
    assert not vf_looks("evm", junk), f"non-hex accepted as an EVM address: {junk[:24]}"
    r = c.post(f"{B}/api/operator/onchain",
               json={"identity_id": tl_id["id"], "chain": "evm",
                     "address": junk, "reason": "AML case 5008"})
    assert r.status_code == 400, ("junk reached the log", junk[:24], r.status_code)
assert vf_looks("evm", "0x" + "aF09" * 10), \
    "a legitimate checksummed address was rejected"
logged = " ".join((e.get("detail") or "") for e in
                  st.access_log_about(tl_id["id"], limit=1000)["entries"])
assert "<script>" not in logged, "markup was written to the permanent log"
print("  non-hex addresses refused before anything is written: ok")

step("44. R4: cache keys respect per-chain canonicalisation")
# A blanket .lower() collapsed two DIFFERENT Solana public keys onto one cache
# entry — base58 is case-sensitive — so the second caller was served the first
# address's transactions, marked cached. On a compliance screen that is one
# person's history shown under another's name.
sol_a = "So11111111111111111111111111111111111111112"
sol_b = "so11111111111111111111111111111111111111112"
assert sol_a != sol_b
ch.clear_cache()
seen_addrs = []
def per_addr(chain_, addr):
    seen_addrs.append(addr)
    return {"status": "ok", "detail": "",
            "transactions": [{"hash": f"0x{len(seen_addrs):064x}", "timestamp": "1",
                              "direction": "in", "counterparty": "0x0", "value_wei": "1"}]}
real_fetch2 = ch._fetch
ch._fetch = per_addr
try:
    ra = ch.transactions("solana", sol_a)
    rb = ch.transactions("solana", sol_b)
    assert rb["cached"] is False, "two distinct base58 keys shared one cache entry"
    assert ra["transactions"] != rb["transactions"], \
        "one address's history was served for another"
    # EVM must still share, since hex case is not part of the identifier.
    evm_lower = "0x" + "ab" * 20
    ch.transactions("evm", evm_lower)
    again = ch.transactions("evm", evm_lower.upper().replace("0X", "0x"))
    assert again["cached"] is True, "EVM case variants should share a cache entry"
finally:
    ch._fetch = real_fetch2
    ch.clear_cache()
print("  Solana keys stay distinct, EVM case variants share: ok")

# A malformed optional tuning value must not stop the app booting.
assert ch._int_env("CHAIN_CACHE_TTL_NOPE", 300) == 300
os.environ["T44_TTL"] = "not-a-number"
assert ch._int_env("T44_TTL", 300) == 300, "a malformed TTL was not defaulted"
os.environ["T44_TTL"] = "-5"
assert ch._int_env("T44_TTL", 300) == 300, "a negative TTL was accepted"
del os.environ["T44_TTL"]
print("  a malformed cache TTL falls back instead of crashing the boot: ok")

step("45. R5 readiness: the app runs against a real IdP with the mock DELETED")
# The roadmap said only mock_esignet.py changes for real Fayda. That was wrong
# in two ways, both of which would have surfaced only at integration time:
#   1. The client assertion was signed with a keypair generated PER PROCESS, so
#      the public JWK registered during partner onboarding could never match —
#      token exchange fails on the first request, and differs per instance.
#   2. app.py imported mock_esignet at module scope, so the "deleted in
#      production" posture CLAUDE.md describes could not actually boot.
# This proves both are fixed, without needing credentials: real URLs, a
# registered key, and the throwaway IdP physically removed.
import atexit as _atexit, shutil, tempfile
prod_dir = tempfile.mkdtemp(prefix="r5ready-")
# Registered at creation, not after the last assertion: this directory holds a
# copy of backend/.env, and a failing assertion below would otherwise strand a
# live database credential in /tmp.
_atexit.register(shutil.rmtree, prod_dir, True)
for f in os.listdir(HERE):
    if f.endswith(".py") and f != "mock_esignet.py":
        shutil.copy(os.path.join(HERE, f), prod_dir)
assert not os.path.exists(os.path.join(prod_dir, "mock_esignet.py"))
if os.path.exists(os.path.join(HERE, ".env")):
    shutil.copy(os.path.join(HERE, ".env"), prod_dir)

from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives import serialization as _ser
_k = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
registered_pem = _k.private_bytes(
    encoding=_ser.Encoding.PEM, format=_ser.PrivateFormat.PKCS8,
    encryption_algorithm=_ser.NoEncryption()).decode()

prod_env = {
    "APP_ENV": "production", "DEMO_MODE": "",
    "SESSION_SECRET": "s" * 32, "FIN_PEPPER": "p" * 32,
    "FAYDA_CLIENT_PRIVATE_KEY": registered_pem,
    # The client id is issued alongside the key. Leaving it at the demo default
    # would send a real IdP an assertion claiming to be "fayda-wallet-demo".
    "FAYDA_CLIENT_ID": "et-partner-0042",
    "FAYDA_AUTHORIZE_URL": "https://esignet.fayda.et/authorize",
    "FAYDA_TOKEN_URL": "https://esignet.fayda.et/v1/token",
    "FAYDA_USERINFO_URL": "https://esignet.fayda.et/v1/userinfo",
}
probe = subprocess.run(
    [sys.executable, "-c",
     "import app, sys, jwt;"
     "print('MOCK_IMPORTED', 'mock_esignet' in sys.modules);"
     "print('AUTHORIZE', app.AUTHORIZE_URL);"
     "c = app.client_assertion();"
     "h = jwt.get_unverified_header(c);"
     "print('ALG', h['alg']);"
     "import json,base64;"
     "p = json.loads(base64.urlsafe_b64decode(c.split('.')[1] + '=='));"
     "print('AUD', p['aud']); print('ISS', p['iss'])"],
    cwd=prod_dir, env={**os.environ, **prod_env},
    capture_output=True, text=True, timeout=120)
assert probe.returncode == 0, ("production could not boot without the mock",
                               probe.stdout[-400:], probe.stderr[-600:])
out = probe.stdout
assert "MOCK_IMPORTED False" in out, ("the mock was still imported", out)
assert "AUTHORIZE https://esignet.fayda.et/authorize" in out, out
assert "ALG RS256" in out, ("client assertion is not RS256", out)
assert "AUD https://esignet.fayda.et/v1/token" in out, \
    ("the assertion audience is not the real token endpoint", out)
# iss/sub carry the REGISTERED client id. An earlier cut printed this and
# asserted nothing, so it displayed the demo default going to a real IdP while
# concluding the app was ready.
assert "ISS et-partner-0042" in out, \
    ("the assertion does not carry the registered client id", out)
assert "fayda-wallet-demo" not in out, ("the demo client id leaked into a live "
                                        "assertion", out)
print("  boots with mock_esignet.py absent, real URLs, RS256, registered iss: ok")

# The registered key must actually be the one signing — a per-process key would
# make the registered public JWK useless.
probe2 = subprocess.run(
    [sys.executable, "-c",
     "import app;"
     "from cryptography.hazmat.primitives import serialization as s;"
     "k = s.load_pem_private_key(app.CLIENT_PRIVATE_KEY.encode(), password=None);"
     "import jwt;"
     "print('VERIFIED', bool(jwt.decode(app.client_assertion(),"
     "  k.public_key(), algorithms=['RS256'], audience=app.TOKEN_URL)))"],
    cwd=prod_dir, env={**os.environ, **prod_env},
    capture_output=True, text=True, timeout=120)
assert "VERIFIED True" in probe2.stdout, \
    ("the assertion is not signed by the configured registered key",
     probe2.stdout[-200:], probe2.stderr[-400:])
print("  the assertion verifies against the CONFIGURED key, not a fresh one: ok")

# Every misconfiguration below must fail AT BOOT. Each one previously booted
# green, passed the health check, and failed at the first user's login — which
# is the failure mode this whole change exists to remove, so each gets a case.
def boots(env_overrides, drop=()):
    e = {**os.environ, **prod_env}
    for k in drop:
        e.pop(k, None)
    e.update(env_overrides)
    return subprocess.run([sys.executable, "-c", "import app"], cwd=prod_dir,
                          env=e, capture_output=True, text=True, timeout=120)

bad_key_cases = [
    ("no key at all", {}, ("FAYDA_CLIENT_PRIVATE_KEY",), "FAYDA_CLIENT_PRIVATE_KEY"),
    ("truncated PEM", {"FAYDA_CLIENT_PRIVATE_KEY":
                       registered_pem[:len(registered_pem) // 2]}, (), "readable"),
    ("the PUBLIC half", {"FAYDA_CLIENT_PRIVATE_KEY": _k.public_key().public_bytes(
        encoding=_ser.Encoding.PEM,
        format=_ser.PublicFormat.SubjectPublicKeyInfo).decode()}, (), "readable"),
    ("not a key at all", {"FAYDA_CLIENT_PRIVATE_KEY": "hello"}, (), "readable"),
    ("demo client id with a real key", {"FAYDA_CLIENT_ID": "fayda-wallet-demo"},
     (), "FAYDA_CLIENT_ID"),
]
for label, override, drop, expect in bad_key_cases:
    p3 = boots(override, drop)
    assert p3.returncode != 0, (f"production booted with {label}", p3.stdout[-200:])
    assert expect in p3.stderr, (f"{label}: unhelpful failure", p3.stderr[-300:])
print(f"  {len(bad_key_cases)} client-credential misconfigurations all refused at boot: ok")

# A real partner key must never sit on a deploy where anyone can log in with a
# persona: DEMO_MODE publishes the mock IdP, and the key is the one credential
# that cannot be rotated without going back to Fayda.
p4 = boots({"DEMO_MODE": "1"})
assert p4.returncode != 0 and "DEMO_MODE" in p4.stderr, \
    ("a registered partner key was allowed onto a DEMO_MODE deploy",
     p4.stderr[-300:])
print("  a real partner key is refused on a DEMO_MODE deploy: ok")

print("\n\nALL CHECKS PASSED")
