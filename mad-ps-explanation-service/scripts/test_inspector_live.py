import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app

async def main():
    print("Testing Passive Telemetry Inspector...")
    # Test 1: Clean API GET Telemetry
    res1 = await app.LiveTrafficInspector.inspect_raw_telemetry(
        path="/api/v1/posts/1",
        method="GET",
        headers={"Content-Type": "application/json"},
        payload="",
        status_code=200,
        latency_ms=14.2,
        council_engine=app.council_engine,
    )
    print("Result 1 (Clean):", res1["inspection_id"], "Category:", res1["category"], "Threat:", res1["is_threat"], "Latency:", res1["latency_ms"], "ms")

    # Test 2: Malicious SQLi Ingested Telemetry
    res2 = await app.LiveTrafficInspector.inspect_raw_telemetry(
        path="/api/v1/orders/search",
        method="POST",
        headers={"Content-Type": "application/json"},
        payload="' UNION SELECT username, password_hash FROM users --",
        status_code=500,
        latency_ms=120.5,
        council_engine=app.council_engine,
    )
    print("Result 2 (SQLi):", res2["inspection_id"], "Category:", res2["category"], "Confidence:", res2["confidence"], "Severity:", res2["severity"])
    if res2.get("council_report"):
        print("  -> Council Report synthesized! ID:", res2["council_report"].get("report_id"), "Risk:", res2["council_report"].get("risk_score"))

if __name__ == "__main__":
    asyncio.run(main())
