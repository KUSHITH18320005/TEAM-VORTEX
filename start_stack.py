import os
import sys
import subprocess
import time
import urllib.request
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent

env = os.environ.copy()
env["PYTHONPATH"] = (
    str(ROOT_DIR)
    + os.pathsep
    + str(ROOT_DIR / "mad-ps-detection-api")
    + os.pathsep
    + str(ROOT_DIR / "mad-ps-explanation-service")
    + os.pathsep
    + str(ROOT_DIR / "mad-ps-platform-frontend")
)
env["PYTHONUNBUFFERED"] = "1"

SERVICES = [
    ("SVM Branch Service", 8007, ROOT_DIR / "mad-ps-detection-api", [sys.executable, "-m", "uvicorn", "services.svm_service:app", "--host", "0.0.0.0", "--port", "8007"]),
    ("DNN Branch Service", 8008, ROOT_DIR / "mad-ps-detection-api", [sys.executable, "-m", "uvicorn", "services.dnn_service:app", "--host", "0.0.0.0", "--port", "8008"]),
    ("Detection Mesh Gateway", 8001, ROOT_DIR / "mad-ps-detection-api", [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]),
    ("Explanation & SaaS API", 8000, ROOT_DIR / "mad-ps-explanation-service", [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]),
    ("Platform Frontend & Attack Console", 3000, ROOT_DIR / "mad-ps-platform-frontend", [sys.executable, "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3000"]),
]

procs = []
print("=" * 70)
print("[*] STARTING ZERODHA CLIENT APP & MAD-PS SAAS PLATFORM SERVICES...")
print("=" * 70)

for name, port, cwd, cmd in SERVICES:
    p = subprocess.Popen(cmd, cwd=str(cwd), env=env)
    procs.append((name, port, p))
    print(f"[*] Starting {name} (Port {port}, PID {p.pid})...")
    time.sleep(1.0)

print("\n[*] Waiting for ML models, SVM/DNN kernels, and API gateways to initialize...")
time.sleep(8.0)

for name, port, p in procs:
    poll = p.poll()
    if poll is not None:
        print(f"[-] {name} (Port {port}) EXITED with code {poll}")
    else:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as r:
                print(f"[+] {name} (Port {port}) is ONLINE and HEALTHY (Status: {r.status})")
        except Exception as exc:
            print(f"[?] {name} (Port {port}) running (PID {p.pid}) - status: {exc}")

print("\n" + "=" * 70)
print("[+] ALL ECOSYSTEM SERVICES ACTIVE & READY:")
print("  - Zerodha Kite Client App:     http://localhost:5000/")
print("  - MAD-PS Attack Console / Scan: http://localhost:3000/scan")
print("  - MAD-PS SOC Dashboard:        http://localhost:3000/dashboard")
print("  - MAD-PS 3-Agent Council:      http://localhost:3000/council")
print("  - MAD-PS SaaS API Docs:        http://localhost:8000/docs")
print("  - MAD-PS Detection Gateway:    http://localhost:8001/docs")
print("=" * 70 + "\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Shutting down all services...")
    for _, _, p in procs:
        p.terminate()

