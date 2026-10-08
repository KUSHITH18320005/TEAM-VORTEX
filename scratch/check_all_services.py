import urllib.request
import urllib.error
import time

def check_services():
    time.sleep(2)
    services = {
        "Platform Frontend & Console": "http://127.0.0.1:3000/",
        "Zerodha React App": "http://127.0.0.1:3001/",
        "Zerodha Vulnerable Backend": "http://127.0.0.1:3002/order/ord_9999",
        "Telemetry Ingestion Gateway": "http://127.0.0.1:4000/health",
        "Explanation & Council Service": "http://127.0.0.1:8000/health",
        "Detection Mesh Gateway": "http://127.0.0.1:8001/health",
        "SVM Branch Service": "http://127.0.0.1:8007/health",
        "DNN Branch Service": "http://127.0.0.1:8008/health",
    }

    print("=" * 68)
    print("MAD-PS ECOSYSTEM & MONITORED APPLICATIONS STATUS CHECK")
    print("=" * 68)

    for name, url in services.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HealthCheck/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                print(f"  [+] {name:32s} -> ONLINE (HTTP {resp.status}) -> {url}")
        except urllib.error.HTTPError as e:
            print(f"  [+] {name:32s} -> ONLINE (HTTP {e.code}) -> {url}")
        except Exception as e:
            print(f"  [?] {name:32s} -> STARTING / NOT CONNECTED: {e}")

    print("=" * 68)

if __name__ == "__main__":
    check_services()
