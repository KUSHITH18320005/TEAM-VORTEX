import urllib.request

for p in [8000, 8001, 8007, 8008, 3000]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{p}/health", timeout=5.0) as r:
            print(f"Port {p}: {r.status} - {r.read().decode('utf-8')[:60]}")
    except Exception as exc:
        print(f"Port {p}: FAILED - {exc}")
