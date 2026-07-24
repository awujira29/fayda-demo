import re, httpx, sys, base64, subprocess, os, time
B="http://127.0.0.1:8000"
c=httpx.Client(follow_redirects=False, timeout=10)

def step(n): print(f"\n--- {n}")

def server(port, env_extra):
    env=dict(os.environ); env.update(env_extra)
    return subprocess.Popen(
        [sys.executable,"-m","uvicorn","app:app","--host","127.0.0.1",
         "--port",str(port),"--log-level","warning"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def wait_up(port, tries=100):
    for _ in range(tries):
        try: httpx.get(f"http://127.0.0.1:{port}/", timeout=1); return True
        except Exception: time.sleep(0.1)
    return False

step("1. OIDC login redirect")
r=c.get(f"{B}/login"); assert r.status_code==307, r.status_code
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
# The sensitive claims must be stripped at the callback boundary; a whitelisted
# claim must survive so the UI still has something to show.
assert "fayda_fin" not in full and "phone_number" not in full, "sensitive claim in /api/me"
assert '"sub"' not in full, "raw sub (== FIN) in /api/me"
assert me["claims"].get("name"), "whitelisted claim dropped — UI would be empty"
# SessionMiddleware signs but does not encrypt: decode the cookie the way any
# client can and confirm the FIN is not carried inside it.
cookie=c.cookies.get("session"); assert cookie, "no session cookie"
payload=cookie.split(".")[0]
decoded=base64.b64decode(payload+"="*(-len(payload)%4))
assert raw_fin.encode() not in decoded, "RAW FIN inside session cookie payload"
assert raw_fin not in cookie, "RAW FIN in raw session cookie"
print("  raw FIN absent from response body and cookie: ok")

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
p=subprocess.run([sys.executable,"-c","import app"], env=env,
                 capture_output=True, text=True, timeout=30)
out=p.stdout+p.stderr
assert p.returncode!=0, "app started in production with no secrets"
assert "refusing to start" in out, out[-300:]
print("  production start without secrets refused: ok")

print("\n\nALL CHECKS PASSED")
