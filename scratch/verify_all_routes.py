import urllib.request
import json

endpoints = [
    ('GET', 'http://127.0.0.1:3000/'),
    ('GET', 'http://127.0.0.1:3000/scan'),
    ('GET', 'http://127.0.0.1:3000/council'),
    ('GET', 'http://127.0.0.1:3000/dashboard'),
    ('GET', 'http://127.0.0.1:3000/apps'),
    ('GET', 'http://127.0.0.1:3000/compliance'),
    ('GET', 'http://127.0.0.1:3000/risk'),
]

for method, url in endpoints:
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            print(f'{url} -> {resp.status}')
    except Exception as e:
        print(f'{url} -> FAILED: {e}')

# Test POST /api/v1/inspect/payload
p_data = json.dumps({'payload': "' OR 1=1 --", 'path': '/api/v1/search', 'method': 'POST'}).encode('utf-8')
p_req = urllib.request.Request('http://127.0.0.1:3000/api/v1/inspect/payload', data=p_data, headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(p_req) as resp:
        print('POST /api/v1/inspect/payload ->', resp.status, resp.read().decode('utf-8')[:120])
except Exception as e:
    print('POST /api/v1/inspect/payload -> FAILED:', e)

# Test POST /api/v1/assistant/chat
m_data = json.dumps({'query': 'Status of 8 models in mesh?', 'user_id': 'analyst'}).encode('utf-8')
m_req = urllib.request.Request('http://127.0.0.1:3000/api/v1/assistant/chat', data=m_data, headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(m_req) as resp:
        print('POST /api/v1/assistant/chat ->', resp.status, resp.read().decode('utf-8')[:120])
except Exception as e:
    print('POST /api/v1/assistant/chat -> FAILED:', e)

# Test POST /council/analyze
c_data = json.dumps({'incident_id': 'INC-001', 'alert_data': {'category': 'SQL_INJECTION', 'confidence': 0.98}}).encode('utf-8')
c_req = urllib.request.Request('http://127.0.0.1:3000/council/analyze', data=c_data, headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(c_req) as resp:
        print('POST /council/analyze ->', resp.status, resp.read().decode('utf-8')[:120])
except Exception as e:
    print('POST /council/analyze -> FAILED:', e)
