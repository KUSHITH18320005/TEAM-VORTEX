"""Test MAD-PS login endpoint live."""
import json, sys, urllib.request

def test_login(label, url):
    payload = json.dumps({"email": "admin@madps.ai", "password": "admin123"}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = json.loads(r.read())
            tok = body.get("access_token", "")
            print(f"[+] {label}: SUCCESS! token={tok[:35]}...")
            return True
    except urllib.request.HTTPError as e:
        print(f"[-] {label}: FAIL {e.code} - {e.read().decode()[:80]}")
    except Exception as e:
        print(f"[-] {label}: ERROR - {e}")
    return False

test_login("Direct port 8000", "http://localhost:8000/api/v1/auth/login")
test_login("Via frontend 3000", "http://localhost:3000/api/v1/auth/login")
