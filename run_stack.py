"""
MAD-PS Master Threaded Server Runner
Directly instantiates and hosts all 5 FastAPI services in threaded runners with per-thread asyncio event loops.
"""

import asyncio
import sys
import threading
import time
from pathlib import Path
import uvicorn

ROOT_DIR = Path(__file__).resolve().parent

# Configure Python path
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(ROOT_DIR / "mad-ps-detection-api"))
sys.path.insert(0, str(ROOT_DIR / "mad-ps-explanation-service"))
sys.path.insert(0, str(ROOT_DIR / "mad-ps-platform-frontend"))


def run_service(app_instance, port: int, name: str):
    print(f"[*] Starting {name} on http://0.0.0.0:{port}...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    config = uvicorn.Config(
        app=app_instance,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    loop.run_until_complete(server.serve())


def main():
    print("=" * 70)
    print("[*] INITIALIZING MAD-PS ECOSYSTEM SERVICES...")
    print("=" * 70)

    # 1. Import explanation service app
    import app as explanation_mod
    explanation_app = explanation_mod.app

    # 2. Import detection gateway app & branches
    import services.svm_service as svm_mod
    import services.dnn_service as dnn_mod
    svm_app = svm_mod.app
    dnn_app = dnn_mod.app

    import importlib.util
    det_spec = importlib.util.spec_from_file_location("detection_main", str(ROOT_DIR / "mad-ps-detection-api" / "app.py"))
    det_mod = importlib.util.module_from_spec(det_spec)
    det_spec.loader.exec_module(det_mod)
    detection_app = det_mod.app

    # 3. Import frontend app
    front_spec = importlib.util.spec_from_file_location("frontend_main", str(ROOT_DIR / "mad-ps-platform-frontend" / "server.py"))
    front_mod = importlib.util.module_from_spec(front_spec)
    front_spec.loader.exec_module(front_mod)
    frontend_app = front_mod.app

    services = [
        (explanation_app, 8000, "Explanation & Multi-Agent SaaS API"),
        (detection_app, 8001, "Detection Mesh Gateway API"),
        (svm_app, 8007, "SVM Branch Service"),
        (dnn_app, 8008, "DNN Branch Service"),
        (frontend_app, 3000, "Unified Platform Frontend"),
    ]

    threads = []
    for app_inst, port, name in services:
        t = threading.Thread(target=run_service, args=(app_inst, port, name), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.3)

    print("\n[+] ALL 5 SERVICES RUNNING CONCURRENTLY!")
    print("  - Port 3000: http://localhost:3000/ (Landing & SOC Consoles)")
    print("  - Port 8000: http://localhost:8000/ (Explanation & Multi-Agent API)")
    print("  - Port 8001: http://localhost:8001/ (Detection Mesh Gateway)")
    print("  - Port 8007: http://localhost:8007/ (SVM Branch Service)")
    print("  - Port 8008: http://localhost:8008/ (DNN Branch Service)")
    print("=" * 70 + "\n")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
