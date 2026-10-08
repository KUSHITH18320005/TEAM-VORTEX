import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mad-ps-explanation-service"))
from app import app
from fastapi.testclient import TestClient

try:
    client = TestClient(app, raise_server_exceptions=True)
    res = client.post(
        '/api/v1/ingest/log',
        json={
            'method': 'GET',
            'path': '/allOrders?filter=1',
            'payload': '{"qty":{"$gt":0}}',
            'client_ip': '198.51.100.45'
        },
        headers={'Authorization': 'Bearer mk_live_primary_master_key_2026'}
    )
    print("STATUS:", res.status_code)
    print("RESPONSE:", res.json())
except Exception as e:
    traceback.print_exc()
