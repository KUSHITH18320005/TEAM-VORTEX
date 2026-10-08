import os
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT_DIR / "scratch" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

SERVICES = [
    {
        "name": "explanation_8000",
        "port": 8000,
        "cwd": ROOT_DIR / "mad-ps-explanation-service",
        "cmd": [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"],
    },
    {
        "name": "gateway_8001",
        "port": 8001,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"],
    },
    {
        "name": "svm_8007",
        "port": 8007,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "services.svm_service:app", "--host", "0.0.0.0", "--port", "8007"],
    },
    {
        "name": "dnn_8008",
        "port": 8008,
        "cwd": ROOT_DIR / "mad-ps-detection-api",
        "cmd": [sys.executable, "-m", "uvicorn", "services.dnn_service:app", "--host", "0.0.0.0", "--port", "8008"],
    },
    {
        "name": "frontend_3000",
        "port": 3000,
        "cwd": ROOT_DIR / "mad-ps-platform-frontend",
        "cmd": [sys.executable, "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "3000"],
    },
]

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

processes = []
for svc in SERVICES:
    log_file = open(LOG_DIR / f"{svc['name']}.log", "w", encoding="utf-8")
    print(f"[*] Spawning {svc['name']} on port {svc['port']}...")
    proc = subprocess.Popen(
        svc["cmd"],
        cwd=str(svc["cwd"]),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT
    )
    processes.append((svc, proc, log_file))

print("[+] All 5 processes spawned. Monitoring...")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for svc, proc, log_file in processes:
        proc.terminate()
        log_file.close()
