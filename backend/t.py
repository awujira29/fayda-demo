import re, httpx, sys, base64, subprocess, os, time
B="http://127.0.0.1:8000"
c=httpx.Client(follow_redirects=False, timeout=10)

def step(n): print(f"\n--- {n}")

HERE=os.path.dirname(os.path.abspath(__file__))

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
c2=httpx.Client(follow_redirects=False, timeout=10)
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
anon=httpx.Client(follow_redirects=False, timeout=10)
r=anon.post(f"{B}/api/dev/reset")
print("  ", r.status_code, r.json().get("detail","")); assert r.status_code==401, r.status_code

step("13. H1/H2/M3: the whole dev surface 404s when APP_ENV != dev")
P=8099
srv=server(P, {"APP_ENV":"production","SESSION_SECRET":"s"*32,
               "FIN_PEPPER":"p"*32,"BASE_URL":f"http://127.0.0.1:{P}"})
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
    print("  dev routes + mock IdP all 404 in production: ok")
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
import secrets, sqlite3
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
for _ in range(3):
    r=c.get(f"{B}/api/registry"); assert r.status_code==200, ("registry wedged", r.status_code)
r=c.get(f"{B}/api/me"); assert r.status_code==200, ("api/me wedged", r.status_code)
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
    assert isinstance(e.__cause__, sqlite3.IntegrityError), e.__cause__
    print("  ux_pending_chain_address rejects the duplicate pending: ok")

step("17. M1: raced first-time binds of one address -> one wins, loser 409s, never 500")
# Two first-time binders race the check-then-insert window on the same address.
# Both must be first-time so both INSERTs target status='active' and the loser
# hits ux_active_chain_address — the raced-replacement variant is test 15's
# ground. c2 (step 10) never bound anything; log the third persona in fresh.
import threading
from eth_account import Account
from eth_account.messages import encode_defunct
c3=httpx.Client(follow_redirects=False, timeout=10)
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
        sc.execute("UPDATE wallet_bindings SET status='archived', archived_at=? WHERE address=?",
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

print("\n\nALL CHECKS PASSED")
