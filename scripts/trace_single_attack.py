import urllib.request
import urllib.parse
import json
import time
import sys

def main():
    category = sys.argv[1] if len(sys.argv) > 1 else "business-logic"
    trace_id = f"trc_live_{category}_{int(time.time()*1000)}"
    
    print(f"\n=======================================================", flush=True)
    print(f"FIRING ATTACK: {category} (trace_id: {trace_id})", flush=True)
    print(f"=======================================================\n", flush=True)
    
    # Fire attack to Zerodha simulation endpoint with x-trace-id header
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
            fire_result = json.loads(resp.read().decode("utf-8"))
            print(f"[Z-TRIGGER] Attack '{category}' response status: {resp.status}")
    except Exception as e:
        print(f"[Z-TRIGGER-ERR] Error firing attack: {e}")

    # Poll trace endpoint for pipeline completion
    hops = []
    trace_data = {}
    for _ in range(10):
        time.sleep(1.0)
        # Query inspections and dashboard feed with trace_id to trigger Hop 12
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
                if "[COUNCIL-COMPLETE]" in recorded_codes or (len(hops) >= 12 and "[COUNCIL-TRIGGER]" not in recorded_codes):
                    break
        except Exception:
            pass
    print(f"\n=======================================================")
    print(f"PIPELINE TRACE SEQUENCE ({len(hops)} hops recorded):")
    print(f"=======================================================")
    
    expected_hops = [
        (1, "[Z-SDK]"),
        (2, "[Z-SDK-SEND]"),
        (3, "[INGEST-RECEIVE]"),
        (4, "[INGEST-AUTH]"),
        (5, "[INGEST-QUEUE]"),
        (6, "[INGEST-WRITE]"),
        (7, "[MESH-RECEIVE]"),
        (8, "[MESH-BRANCH-SCORE]"),
        (9, "[MESH-META]"),
        (10, "[COUNCIL-TRIGGER]"),
        (11, "[COUNCIL-COMPLETE]"),
        (12, "[DASHBOARD-QUERY]"),
        (13, "[DASHBOARD-WS-PUSH]")
    ]

    recorded_codes = {h["hop_code"]: h for h in hops}
    
    for step_num, code in expected_hops:
        if code in recorded_codes:
            h = recorded_codes[code]
            print(f"  STEP {step_num:02d} {code:22s} [PASS] - {h.get('service')}: {json.dumps(h.get('details'))}")
        else:
            print(f"  STEP {step_num:02d} {code:22s} [MISSING / BREAK]")

    print(f"\nSummary: {len(hops)}/13 hops completed.")

if __name__ == "__main__":
    main()
