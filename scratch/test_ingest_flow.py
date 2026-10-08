import urllib.request
import json

def main():
    url = 'http://127.0.0.1:8000/api/v1/ingest/log'
    data = {
        'method': 'GET',
        'path': '/allOrders?filter=%7B%22qty%22%3A%7B%22%24gt%22%3A0%7D%7D',
        'payload': '{"qty":{"$gt":0}}',
        'client_ip': '198.51.100.45',
        'status_code': 200,
        'latency_ms': 18.5
    }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer mk_live_primary_master_key_2026'
    }

    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
    with urllib.request.urlopen(req) as resp:
        res_json = json.loads(resp.read().decode('utf-8'))
        print('Ingestion Result:')
        print(json.dumps(res_json, indent=2))

    # Check /api/v1/reports
    req_rep = urllib.request.Request('http://127.0.0.1:8000/api/v1/reports?limit=1')
    with urllib.request.urlopen(req_rep) as resp:
        rep_json = json.loads(resp.read().decode('utf-8'))
        print('\nLatest Council Report in DB:')
        if rep_json:
            print(f"Incident ID: {rep_json[0].get('incident_id')}")
            print(f"Category: {rep_json[0].get('incident_category')}")
            print(f"Risk Score: {rep_json[0].get('risk_assessment', {}).get('composite_risk_score')}")
            print(f"Reconstruction Narrative: {rep_json[0].get('reconstruction_findings', {}).get('causal_narrative', '')[:100]}...")
            print(f"Response Plan: {rep_json[0].get('response_plan', {}).get('containment_strategy', '')[:100]}...")
            print(f"Judge Synthesis: {rep_json[0].get('judge_synthesis', {}).get('rationale', '')[:100]}...")

if __name__ == '__main__':
    main()
