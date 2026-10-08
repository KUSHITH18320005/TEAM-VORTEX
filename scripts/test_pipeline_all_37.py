import urllib.request
import urllib.parse
import json
import time
import sys

ATTACK_CATEGORIES = [
    # Tier 1: Frontend & Client-Side (#1–5)
    "xss-stored",
    "session-hijack",
    "csrf",
    "open-redirect",
    "auth-bypass",
    # Tier 2: Backend API & Auth (#6–16)
    "business-logic",
    "no-rate-limit",
    "jwt-abuse",
    "session-fixation",
    "bruteforce",
    "credential-stuffing",
    "password-spraying",
    "account-takeover",
    "idor",
    "ssrf",
    "xxe",
    # Tier 3: DBMS & Storage (#17–19)
    "nosql-injection",
    "api-abuse",
    "data-exfil",
    # Tier 4: Network, OS & Advanced Threats (#20–37)
    "port-scanning-recon",
    "network-service-enumeration",
    "dos",
    "ddos",
    "dns-spoofing",
    "mitm",
    "ransomware-behavioral",
    "trojan-behavioral",
    "spyware-behavioral",
    "botnet-c2",
    "compromised-iot",
    "polymorphic-malware",
    "apt-stealth-intrusion",
    "encrypted-c2",
    "ai-adaptive",
    "supply-chain-compromise",
    "double-extortion",
    "zero-day-eval",
]

def run_single_attack(category: str, index: int) -> bool:
    trace_id = f"trc_37all_{category}_{int(time.time()*1000)}"
    fire_url = f"http://127.0.0.1:3002/simulation/trigger/app/{category}"
    req = urllib.request.Request(
        fire_url,
        data=json.dumps({"trace_id": trace_id}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Trace-Id": trace_id,
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if resp.status != 200 or not data.get("success"):
                print(f"[{index:02d}/37] {category:30s} [ERR] Trigger failed status={resp.status}", flush=True)
                return False
    except Exception as e:
        print(f"[{index:02d}/37] {category:30s} [ERR] Trigger exception: {e}", flush=True)
        return False

    # Poll trace endpoint for pipeline completion
    hops = []
    has_ingest = False
    has_mesh = False
    recorded_codes = set()
    for _ in range(6):
        time.sleep(1.0)
        # Ping inspections endpoint to record dashboard query
        try:
            urllib.request.urlopen(f"http://127.0.0.1:8000/api/v1/inspections?trace_id={trace_id}", timeout=5).read()
        except Exception:
            pass

        trace_url = f"http://127.0.0.1:8000/api/v1/pipeline/trace/{trace_id}"
        try:
            with urllib.request.urlopen(trace_url, timeout=5) as resp:
                trace_data = json.loads(resp.read().decode("utf-8"))
                hops = trace_data.get("hops", [])
                recorded_codes = {h["hop_code"] for h in hops}
                has_ingest = "[INGEST-RECEIVE]" in recorded_codes or "[INGEST-AUTH]" in recorded_codes or "[Z-SDK]" in recorded_codes
                has_mesh = "[MESH-RECEIVE]" in recorded_codes or "[MESH-BRANCH-SCORE]" in recorded_codes or "[MESH-META]" in recorded_codes
                if has_ingest and has_mesh:
                    break
        except Exception:
            pass

    if has_ingest and has_mesh:
        print(f"[{index:02d}/37] {category:30s} [PASS] ({len(hops)} hops, mesh verified)", flush=True)
        return True
    else:
        print(f"[{index:02d}/37] {category:30s} [PARTIAL] ({len(hops)} hops: {list(recorded_codes)})", flush=True)
        return False

def main():
    print("=" * 70, flush=True)
    print("RUNNING END-TO-END 37-ATTACK PIPELINE TRACE VERIFICATION", flush=True)
    print("=" * 70, flush=True)

    passed = 0
    failed = 0

    for idx, cat in enumerate(ATTACK_CATEGORIES, 1):
        success = run_single_attack(cat, idx)
        if success:
            passed += 1
        else:
            failed += 1

    print("=" * 70, flush=True)
    print(f"RESULTS: {passed}/37 PASSED | {failed} FAILED", flush=True)
    print("=" * 70, flush=True)

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
