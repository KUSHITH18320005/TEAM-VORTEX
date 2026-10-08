"""
Phase Z Verification Test Suite:
Validates Maddy Conversational Assistant across all 6 Grounding Categories,
Strict Honest Negatives, and Real LLM Error Surface Behavior over REST API.
"""

import json
import time
import urllib.request
import urllib.error
import sys

def test_maddy_grounding_suite():
    print("=" * 70)
    print("PHASE Z: MADDY ASSISTANT & 6-CATEGORY GROUNDING REST VERIFICATION")
    print("=" * 70)

    # 1. Fetch latest incident from reports API
    sample_incident_id = "INC-20260906-73B989"
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/reports?limit=5", timeout=5) as resp:
            reports = json.loads(resp.read().decode("utf-8"))
            if reports:
                sample_incident_id = reports[0]["incident_id"]
    except Exception as e:
        print(f"[!] Warning fetching latest reports: {e}")

    print(f"[*] Testing with verified incident ID: {sample_incident_id}\n")

    test_queries = [
        # 1. Full 7-Panelist Council Transcripts
        ("Category 1: Council Transcripts", f"What was Dr. Elena Vance's reconstruction findings and the Chief Judge's verdict for incident {sample_incident_id}?"),
        
        # 2. 8-Model Branch Scores
        ("Category 2: 8-Model Branch Scores", f"What were the 8 model branch scores and 1D-CNN confidence for incident {sample_incident_id}?"),
        
        # 3. SQL Aggregate Statistics
        ("Category 3: Aggregate SQL Analytics", "How many total security incidents have occurred and what is the average risk score across all incidents?"),
        
        # 4. Live Mesh Health & Topology
        ("Category 4: Live Detection Mesh Health", "What is the current health status of the 8-model detection mesh gateway?"),
        
        # 5. Platform Architecture Specifications
        ("Category 5: Platform Architecture", "Explain the difference between Fast Lane and Deep Lane council execution, and what is the risk score formula?"),
        
        # 6. Raw Logs & Telemetry
        ("Category 6: Verbatim Raw Telemetry", f"Show the raw log details and telemetry payload for incident {sample_incident_id}"),
        
        # 7. Strict Honest Negative Test
        ("Category 7: Strict Honest Negative", "What are the forensics findings and risk score for non-existent incident INC-999999?"),
    ]

    for cat_name, query_text in test_queries:
        print(f"--- Running Test: {cat_name} ---")
        print(f"Query: \"{query_text}\"")

        req_data = json.dumps({
            "query": query_text,
            "message": query_text,
            "user_id": "soc_analyst_1",
            "org_id": "org_default"
        }).encode("utf-8")

        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/v1/assistant/chat",
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            assert resp.status == 200, f"Expected status 200 but got {resp.status}"
            data = json.loads(resp.read().decode("utf-8"))

        answer = data.get("answer") or data.get("reply") or ""
        sources = data.get("sources_cited") or []
        provider = data.get("provider_used") or "llm"
        model = data.get("model_used") or "unknown"
        is_grounded = data.get("is_grounded", False)

        print(f"Grounded: {is_grounded} | Sources: {sources}")
        print(f"Provider: {provider} | Model: {model}")
        print(f"Answer snippet: {answer[:220]}...\n")

        # Assertions
        if "Honest Negative" in cat_name:
            assert not is_grounded, "Non-existent incident should NOT be marked as grounded!"
            assert any(term in answer.lower() for term in ["not found", "not exist", "not present", "no records", "no matching", "no verified"]), "Honest negative must inform the analyst that the record does not exist!"
            print(f"[PASS] Honest Negative verified correctly.\n")
        else:
            assert is_grounded, f"Retriever should have grounded {cat_name}!"
            assert len(answer) > 20, "Answer should not be empty!"
            print(f"[PASS] {cat_name} grounded and answered successfully.\n")

    # 8. Test Error Visibility on Invalid LLM Key
    print("--- Running Test: Visible Error on Invalid / Mock-Free Failure ---")
    test_req = json.dumps({
        "provider": "gemini",
        "api_key": "INVALID_TEST_KEY_FOR_ERROR_VISIBILITY",
        "model_name": "gemini-2.0-flash"
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/llm/test",
        data=test_req,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        test_res = json.loads(resp.read().decode("utf-8"))
        print(f"Invalid Key Test Result: {test_res}")
        assert test_res.get("success") is False or test_res.get("status") == "FAILED" or "invalid" in str(test_res).lower() or "error" in str(test_res).lower(), "Invalid API key must return failure state, never silent fake mock success!"
        print("[PASS] LLM Error state surfaced visibly.\n")

    print("======================================================================")
    print("[PASS] ALL PHASE Z GROUNDING, HONEST NEGATIVES, AND ERROR SURFACE TESTS PASSED!")
    print("======================================================================")


if __name__ == "__main__":
    test_maddy_grounding_suite()
