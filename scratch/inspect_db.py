import sqlite3
from pathlib import Path

db_path = Path("mad-ps-explanation-service/data/mad_ps_product.db")
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

print("--- TABLES ---")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
for t in cursor.fetchall():
    print(t[0])

print("\n--- ORGANIZATIONS ---")
try:
    cursor.execute("SELECT * FROM organizations")
    for row in cursor.fetchall():
        print(row)
except Exception as e:
    print(e)

print("\n--- API KEYS ---")
try:
    cursor.execute("SELECT * FROM api_keys")
    for row in cursor.fetchall():
        print(row)
except Exception as e:
    print(e)

print("\n--- INCIDENT REPORTS (COUNT & ORG) ---")
try:
    cursor.execute("SELECT org_id, count(*), max(generated_at) FROM incident_reports GROUP BY org_id")
    for row in cursor.fetchall():
        print(row)
except Exception as e:
    print(e)

print("\n--- TRAFFIC INSPECTIONS (COUNT & ORG) ---")
try:
    cursor.execute("SELECT org_id, count(*), max(timestamp) FROM traffic_inspections GROUP BY org_id")
    for row in cursor.fetchall():
        print(row)
except Exception as e:
    print(e)
