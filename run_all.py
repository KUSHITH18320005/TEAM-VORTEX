"""
MAD-PS Master Ecosystem Launcher.
Launches the full unified stack:
- Port 8000: Explanation Service (Council, LLM Explanation, Multi-Tenant SaaS APIs)
- Port 8001: Detection Mesh Gateway API
- Port 8007: SVM Branch Service (Phase M1)
- Port 8008: DNN Branch Service (Phase M2)
- Port 3000: Unified Platform Frontend (Landing Page, Onboarding, Transparency & SOC Dashboard)
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT_DIR = Path(__file__).resolve().parent

SERVICES = [
    {
        "name": "Explanation & SaaS API",
        "port": 8000,
        "cwd": ROOT_DIR / "mad-ps-explanation-service",
        "cmd": [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"],
    },
    {
        "name": "Detection Mesh Gateway",
        "port": 8001,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"],
    },
    {
        "name": "SVM Branch Service",
        "port": 8007,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "services.svm_service:app", "--host", "0.0.0.0", "--port", "8007"],
    },
    {
        "name": "DNN Branch Service",
        "port": 8008,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "services.dnn_service:app", "--host", "0.0.0.0", "--port", "8008"],
    },
    {
        "name": "Platform Frontend & Landing Page",
        "port": 3000,
        "cwd": ROOT_DIR / "mad-ps-platform-frontend",
        "cmd": [sys.executable, "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3000"],
    },
]


def main():
    print("=" * 70)
    print("[*] LAUNCHING MAD-PS AUTONOMOUS ATTACK DETECTION ECOSYSTEM")
    print("=" * 70)

    log_dir = ROOT_DIR / "logs"
    log_dir.mkdir(exist_ok=True)

    processes = []
    log_files = []
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

    try:
        for svc in SERVICES:
            print(f"[*] Starting {svc['name']} on http://localhost:{svc['port']}...")
            proc = subprocess.Popen(
                svc["cmd"],
                cwd=str(svc["cwd"]),
                env=env,
            )
            processes.append((svc, proc))
            time.sleep(1.0)

        print("\n" + "=" * 70)
        print("[+] ALL MAD-PS SERVICES ONLINE & RUNNING!")
        print("  - Public Landing Page:       http://localhost:3000/")
        print("  - Model Transparency:        http://localhost:3000/transparency")
        print("  - Sentinel SOC Operations:   http://localhost:3000/dashboard")
        print("  - Multi-Tenant SaaS API:     http://localhost:8000/docs")
        print("  - Detection Mesh Gateway:    http://localhost:8001/docs")
        print("  - SVM Service:               http://localhost:8007/health")
        print("  - DNN Service:               http://localhost:8008/health")
        print("=" * 70 + "\n")

        while True:
            for svc, proc in processes:
                code = proc.poll()
                if code is not None:
                    print(f"[!] SERVICE {svc['name']} (Port {svc['port']}) EXITED with code {code}!", flush=True)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Shutting down all MAD-PS services...")
        for svc, proc in processes:
            proc.terminate()
        for svc, proc in processes:
            proc.wait()
        for lf in log_files:
            lf.close()
        print("✓ All services terminated cleanly.")


if __name__ == "__main__":
    main()
