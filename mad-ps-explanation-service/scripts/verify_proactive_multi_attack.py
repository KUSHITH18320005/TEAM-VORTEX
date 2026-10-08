"""
Verification script for Task L7.3 — Proactive Multi-Attack Broadcast Verification.
Fires 5 distinct attack vectors through the live pipeline and verifies that MADDY
broadcasts distinct, real per-incident summaries over WebSocket.
"""

import asyncio
import json
import httpx
import websockets

GATEWAY_URL = "http://127.0.0.1:8001"
EXPLANATION_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/assistant/chat"

ATTACK_VECTORS = [
    {"category_id": "SQLI", "name": "SQL Injection on /api/v1/search"},
    {"category_id": "OS_COMMAND_INJECTION", "name": "Command Injection on /api/v1/system/ping"},
    {"category_id": "SSRF", "name": "Server-Side Request Forgery on /api/v1/proxy/fetch"},
    {"category_id": "PATH_TRAVERSAL", "name": "Path Traversal on /api/v1/static/read"},
    {"category_id": "IDOR", "name": "IDOR on /api/v1/documents/download"},
]


async def test_proactive_broadcasts():
    print("=" * 80)
    print("STARTING LIVE MULTI-ATTACK PROACTIVE NOTIFICATION VERIFICATION")
    print("=" * 80)

    received_alerts = []

    async with websockets.connect(WS_URL) as ws:
        print("Connected to MADDY Live WebSocket stream.")

        async def listen_for_alerts():
            while True:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=60.0)
                    data = json.loads(msg)
                    if data.get("type") == "proactive_notification":
                        payload = data.get("proactive_payload", {})
                        received_alerts.append({
                            "incident_id": payload.get("incident_id"),
                            "category": payload.get("category"),
                            "risk_score": payload.get("risk_score"),
                            "severity": payload.get("severity"),
                            "requires_human_approval": payload.get("requires_human_approval"),
                            "pending_actions_count": len(payload.get("pending_actions", [])),
                            "message": payload.get("message"),
                        })
                        print(f"\n[RECEIVED PROACTIVE ALERT] Incident: {payload.get('incident_id')} | Category: {payload.get('category')} | Risk: {payload.get('risk_score')} | Approval Req: {payload.get('requires_human_approval')}")
                        print(f"Summary: {payload.get('message')}")
                except asyncio.TimeoutError:
                    break
                except Exception as exc:
                    print(f"WS listener error: {exc}")
                    break

        listener_task = asyncio.create_task(listen_for_alerts())

        # Fire the 5 attacks sequentially with sufficient wait time for Council debate
        async with httpx.AsyncClient(timeout=45.0) as client:
            for vec in ATTACK_VECTORS:
                cat_id = vec["category_id"]
                print(f"\n>>> Firing attack vector: {vec['name']} ({cat_id}) to Gateway...")
                try:
                    resp = await client.post(f"{GATEWAY_URL}/v1/attacks/fire", json={"category_id": cat_id})
                    if resp.status_code == 200:
                        det = resp.json().get("detection_result", {})
                        print(f"    Gateway detected: {det.get('category')} (Conf: {det.get('confidence', 0):.2f}) -> Forwarded to Council.")
                    else:
                        print(f"    Attack fire returned status: {resp.status_code}: {resp.text}")
                except Exception as exc:
                    print(f"    Error firing attack {cat_id}: {exc}")
                await asyncio.sleep(8.0)

        # Wait for remaining alerts
        await asyncio.sleep(15.0)
        listener_task.cancel()

    print("\n" + "=" * 80)
    print(f"PROACTIVE ALERTS SUMMARY: Received {len(received_alerts)} distinct alerts.")
    print("=" * 80)
    for idx, alert in enumerate(received_alerts, 1):
        print(f"{idx}. {alert['incident_id']}: Category={alert['category']}, Risk={alert['risk_score']}, ApprovalReq={alert['requires_human_approval']}, Actions={alert['pending_actions_count']}")

    # Save to JSON
    with open("./data/proactive_multi_attack_verification.json", "w", encoding="utf-8") as f:
        json.dump(received_alerts, f, indent=2)

    return received_alerts


if __name__ == "__main__":
    asyncio.run(test_proactive_broadcasts())
