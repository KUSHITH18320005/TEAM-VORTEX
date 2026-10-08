#!/usr/bin/env python3
"""
MAD-PS Dataset Replay Importer (backend/dataset-replay/import.py)
----------------------------------------------------------------
Replays pre-labeled telemetry from established cybersecurity research datasets
(CICIDS2017, CIC-IoT2023, CIC-MalMem2022, NSL-KDD) into the shared MongoDB `logs` collection.

HARD CONSTRAINTS:
1. Static data ingestion only — never opens network sockets to attack or probe real hosts.
2. Strictly isolated as a standalone CLI script — never imported by live Express routes.
3. Every inserted document includes:
   - layer: "network" | "malware-behavioral" | "iot" | "research-scenario"
   - source: "dataset-replay"
   - dataset: original dataset name
   - category: standardized MAD-PS category
   - timestamp, ip, endpoint, method, payload, details
"""

import os
import sys
import json
import time
import math
import uuid
import random
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Optional libraries with graceful fallbacks
try:
    import pandas as pd
except ImportError:
    pd = None

try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None


CURRENT_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = CURRENT_DIR / "data"
CONFIG_FILE = CURRENT_DIR / "categories.json"

# Synthetic IP Pools for realistic telemetry
EXTERNAL_ATTACKER_IPS = [
    "198.51.100.45", "203.0.113.19", "185.220.101.5", "194.26.29.112",
    "45.154.255.89", "91.240.118.234", "103.251.167.20", "185.191.171.12"
]
INTERNAL_HOST_IPS = [
    "10.0.4.15", "10.0.4.22", "192.168.1.105", "172.16.0.50", "10.0.12.88"
]
IOT_DEVICE_IDS = [
    "ESP32_SENSOR_NODE_01", "ESP32_SENSOR_NODE_02", "ESP32_GATEWAY_ALPHA", "ESP32_EDGE_CONTROLLER"
]


def load_categories():
    """Load attack categories configuration."""
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("attacks", [])


def get_mongo_collection(uri=None):
    """Establish connection to MongoDB logs collection or return None."""
    if not MongoClient:
        return None

    if not uri:
        # Check backend/.env
        env_path = CURRENT_DIR.parent / ".env"
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("MONGO_URL="):
                        uri = line.strip().split("=", 1)[1].strip()
                        break

    uri = uri or "mongodb://127.0.0.1:27017/zerodha_lab"
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2500)
        # Verify connection
        client.admin.command("ping")
        db = client.get_database()
        return db["logs"]
    except Exception as e:
        print(f"[NOTE] MongoDB direct connection unavailable ({e.__class__.__name__}). Operating in resilient ingestion/simulation mode.")
        return None


def push_to_ingestion_service(docs, ingestion_url=None, is_batch=True):
    """
    Push telemetry records to the MAD-PS Ingestion Service gateway (port 4000)
    AND the 8-model detection mesh / explanation gateway (port 8000).
    """
    import urllib.request
    import urllib.error

    if not docs:
        return False

    url_base = ingestion_url or os.environ.get("INGESTION_SERVICE_URL", "http://127.0.0.1:4000")
    token = os.environ.get("INGEST_SERVICE_TOKEN", "madps_sec_svc_tok_9918237b4f2c01_alpha88")
    mad_ps_api_key = os.environ.get("MAD_PS_API_KEY", "mk_live_demo1234567890abcdef1234567890abcdef")
    mad_ps_mesh_url = os.environ.get("MAD_PS_INGEST_URL", "http://127.0.0.1:8000/api/v1/ingest/log")

    # 1. Forward to Port 8000 Detection Mesh & Council Gateway
    try:
        sample_doc = docs[0] if is_batch else docs[0]
        mesh_payload = {
            "trace_id": sample_doc.get("trace_id") or f"trc_replay_{secrets.token_hex(6)}",
            "timestamp": sample_doc.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "method": sample_doc.get("method") or "POST",
            "path": sample_doc.get("route") or sample_doc.get("endpoint") or f"/{sample_doc.get('category', 'security-event')}",
            "endpoint": sample_doc.get("route") or sample_doc.get("endpoint") or f"/{sample_doc.get('category', 'security-event')}",
            "headers": {"Content-Type": "application/json"},
            "payload": sample_doc.get("details") or sample_doc,
            "status_code": sample_doc.get("responseStatus") or 200,
            "latency_ms": sample_doc.get("latencyMs") or 14.5,
            "client_ip": sample_doc.get("ip") or "198.51.100.45",
            "category": sample_doc.get("category", "threat"),
            "expected_category": sample_doc.get("category", "threat"),
        }
        mesh_data = json.dumps(mesh_payload).encode("utf-8")
        mesh_req = urllib.request.Request(
            mad_ps_mesh_url,
            data=mesh_data,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": mad_ps_api_key,
                "Authorization": f"Bearer {mad_ps_api_key}",
            },
            method="POST"
        )
        with urllib.request.urlopen(mesh_req, timeout=3.0) as _:
            pass
    except Exception:
        pass

    # 2. Forward to Port 4000 Ingestion Gateway
    endpoint = f"{url_base.rstrip('/')}/ingest/batch" if is_batch else f"{url_base.rstrip('/')}/ingest/log"
    payload = docs if is_batch else docs[0]

    try:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            if 200 <= resp.status < 300:
                return True
    except Exception:
        return False
    return True


def sanitize_value(val):
    """Sanitize float / numpy values for JSON/BSON compatibility."""
    if val is None:
        return None
    if isinstance(val, (float, int)):
        if math.isnan(val) or math.isinf(val):
            return 0.0
        return round(val, 4) if isinstance(val, float) else val
    return str(val).strip()


def find_csv_rows_for_attack(attack_cfg, data_dir, limit=10):
    """Attempt to load real CSV records using pandas if files exist in data_dir."""
    if pd is None or not data_dir.exists():
        return None

    dataset_name = attack_cfg["dataset"]
    labels = [l.lower() for l in attack_cfg.get("labels", [])]

    # Look for matching CSV files in data_dir
    candidate_files = []
    for ext in ["*.csv", "*.csv.gz", f"{dataset_name}*/*.csv"]:
        candidate_files.extend(list(data_dir.glob(ext)))

    for csv_file in candidate_files:
        try:
            # Read first chunk or entire file
            df = pd.read_csv(csv_file, nrows=5000)
            
            # Find label column
            label_col = None
            for col in df.columns:
                if col.strip().lower() in ["label", "class", "attack_type", "attack"]:
                    label_col = col
                    break
            
            if not label_col:
                continue

            # Filter rows
            matched_df = df[df[label_col].astype(str).str.lower().isin(labels)]
            if not matched_df.empty:
                rows = []
                for _, row in matched_df.head(limit).iterrows():
                    row_dict = {
                        sanitize_value(k): sanitize_value(v)
                        for k, v in row.to_dict().items()
                        if k != label_col
                    }
                    rows.append(row_dict)
                return rows
        except Exception:
            continue

    return None


def generate_synthetic_features(attack_cfg, index):
    """Generate high-fidelity feature vectors when raw multi-GB CSVs are not present."""
    cat = attack_cfg["category"]
    layer = attack_cfg["layer"]

    details = {
        "dataset_name": attack_cfg["dataset"],
        "simulated_flow_id": f"flow_{cat}_{int(time.time())}_{index:04d}",
        "protocol": random.choice(["TCP", "UDP", "ICMP", "ARP", "TLS"]),
    }

    if layer == "network":
        details.update({
            "flow_duration_us": random.randint(500, 2500000),
            "total_fwd_packets": random.randint(1, 1500),
            "total_bwd_packets": random.randint(0, 1200),
            "flow_bytes_per_sec": round(random.uniform(100.0, 5000000.0), 2),
            "flow_packets_per_sec": round(random.uniform(5.0, 25000.0), 2),
            "syn_flag_count": 1 if cat in ["port-scanning-recon", "dos", "ddos"] else 0,
            "ack_flag_count": 1 if cat in ["ddos", "mitm"] else 0,
            "destination_port": random.choice([80, 443, 8080, 22, 21, 3306, 53, 445]),
        })
        if cat == "port-scanning-recon":
            details["scan_type"] = "SYN_STEALTH_PORT_SCAN"
            details["probed_port_range"] = "20-1024"
        elif cat == "network-service-enumeration":
            details["probe_type"] = "NMAP_SERVICE_VERSION_SWEEP"
            details["queried_banner"] = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d"
        elif cat == "dos":
            details["dos_variant"] = random.choice(["Slowloris", "Hulk", "GoldenEye", "Slowhttptest"])
            details["concurrent_half_open_connections"] = random.randint(500, 4000)
        elif cat == "ddos":
            details["ddos_source_count"] = random.randint(150, 2500)
            details["aggregate_flow_rate_mbps"] = round(random.uniform(250.0, 10000.0), 2)
        elif cat == "dns-spoofing":
            details["dns_query_domain"] = "api.zerodhaclone.local"
            details["poisoned_resolved_ip"] = random.choice(EXTERNAL_ATTACKER_IPS)
            details["cache_poison_ttl"] = 86400
        elif cat == "mitm":
            details["arp_opcode"] = 2  # Reply spoofing
            details["target_mac_spoofed"] = "00:1A:2B:3C:4D:5E"
            details["intercepted_gateway_ip"] = "10.0.4.1"
        elif cat == "apt-stealth-intrusion":
            details["intrusion_phase"] = "Low-and-Slow Network Infiltration"
            details["subflow_fwd_packets"] = random.randint(2, 10)
            details["stealth_jitter_sec"] = round(random.uniform(45.0, 300.0), 2)

    elif layer == "malware-behavioral":
        details.update({
            "pslist_nproc": random.randint(35, 120),
            "pslist_avg_threads": round(random.uniform(8.5, 45.0), 2),
            "handles_nhandles": random.randint(2500, 35000),
            "handles_nfile": random.randint(200, 1800),
            "malfind_ninjections": random.randint(1, 12),
            "ldrmodules_not_in_load": random.randint(0, 8),
            "memory_entropy": round(random.uniform(6.8, 7.99), 3),
        })
        if cat == "ransomware-behavioral":
            details["rapid_file_encryptions_per_sec"] = random.randint(150, 2500)
            details["targeted_extension_types"] = [".docx", ".pdf", ".xlsx", ".db", ".key"]
            details["ransom_note_dropped"] = "README_RESTORE_FILES.txt"
        elif cat == "trojan-behavioral":
            details["hidden_backdoor_port"] = 4444
            details["injected_system_process"] = "svchost.exe"
            details["registry_persistence_key"] = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        elif cat == "spyware-behavioral":
            details["keystroke_buffer_size_kb"] = random.randint(12, 128)
            details["screen_capture_interval_sec"] = 5
            details["exfiltration_remote_host"] = random.choice(EXTERNAL_ATTACKER_IPS)
        elif cat == "botnet-c2":
            details["c2_beacon_interval_sec"] = 60
            details["c2_heartbeat_payload_bytes"] = 128
            details["bot_command_channel"] = "IRC/HTTPS"
        elif cat == "polymorphic-malware":
            details["code_mutation_engine"] = "Metamorphic-Instruction-Substitutor"
            details["signature_evasion_entropy"] = round(random.uniform(7.85, 7.99), 3)
            details["unique_injections_count"] = random.randint(4, 16)
        elif cat == "encrypted-c2":
            details["tls_sni"] = "c2-cdn-edge-node.net"
            details["tls_ja3_fingerprint"] = "e7d705a3286e19ea42f587b344ee6865"
            details["beacon_interval_jitter_sec"] = round(random.uniform(0.1, 1.5), 2)
            details["note"] = "Re-tagged from botnet-c2: represents the same C2 behavior over an encrypted TLS channel"

    elif layer == "iot":
        details.update({
            "device_id": random.choice(IOT_DEVICE_IDS),
            "node_type": "ESP32-WROOM-32D",
            "firmware_version": "v1.4.2-edge",
            "sensor_telemetry_rate_hz": 10,
            "anomaly_score": round(random.uniform(0.75, 0.99), 3),
            "abnormal_external_socket": f"{random.choice(EXTERNAL_ATTACKER_IPS)}:4444",
            "compromise_vector": "Mirai-family Telnet brute-force & credential reuse",
        })

    elif layer == "research-scenario":
        if cat == "ai-adaptive":
            details.update({
                "original_feature_vector": [1420, 28.5, 12000, 1],
                "perturbed_feature_vector": [1395, 27.8, 11850, 0],
                "perturbation_epsilon": 0.05,
                "evasion_technique": "Fast Gradient Sign Method (FGSM) Feature Perturbation",
                "evasion_target": "RandomForest_Classifier",
                "original_row_id": f"row_cicids_{index:04d}",
            })
        elif cat == "supply-chain-compromise":
            details.update({
                "campaign_id": f"CMP_SUPPLY_CHAIN_{uuid.uuid4().hex[:8]}",
                "stage": f"Stage {index % 3 + 1}: Dependency Execution & Payload Drop",
                "component_name": "@trade-lib/market-analytics-v2.1.0",
                "infected_dependency": "event-stream-helper",
                "c2_server": "update-package-mirror.org",
            })
        elif cat == "double-extortion":
            details.update({
                "campaign_id": f"CMP_DOUBLE_EXTORTION_{uuid.uuid4().hex[:8]}",
                "stage": "Exfiltration -> Encryption Burst",
                "exfiltrated_records_count": random.randint(25000, 100000),
                "ransom_demand_btc": 2.5,
                "leak_site_url": "http://darkwebleakmarket77.onion",
            })
        elif cat == "zero-day-eval":
            details.update({
                "holdout_target_category": "zero-day-eval",
                "zero_day_eval": True,
                "novelty_score": round(random.uniform(0.88, 0.98), 3),
                "isolation_forest_anomaly_score": -0.42,
                "unseen_protocol_features": ["CUSTOM_P2P_RPC", "NON_STANDARD_ENCODING"],
            })

    return details


def create_log_document(attack_cfg, details, index, custom_timestamp=None, custom_category=None, custom_layer=None):
    """Assemble a standard telemetry document matching LOGGING.md."""
    cat = custom_category or attack_cfg["category"]
    layer = custom_layer or attack_cfg["layer"]
    dataset = attack_cfg.get("dataset", "Dataset-Replay")

    is_internal = cat in [
        "ransomware-behavioral", "trojan-behavioral", "spyware-behavioral",
        "polymorphic-malware", "encrypted-c2"
    ]
    src_ip = random.choice(INTERNAL_HOST_IPS) if is_internal else random.choice(EXTERNAL_ATTACKER_IPS)

    endpoint_map = {
        "network": "/network/flow",
        "malware-behavioral": "/endpoint/host-telemetry",
        "iot": "/iot/sensor-gateway",
        "research-scenario": "/research/scenario-event",
    }

    ts = custom_timestamp or datetime.now(timezone.utc).isoformat()

    doc = {
        "timestamp": ts,
        "ip": src_ip,
        "endpoint": endpoint_map.get(layer, "/telemetry/event"),
        "method": "DATA",
        "category": cat,
        "layer": layer,
        "source": "dataset-replay",
        "dataset": dataset,
        "payload": {
            "body": details,
            "query": {},
            "params": {},
        },
        "details": details,
    }
    return doc


def generate_composite_scenarios(attacks_by_cat, limit=5, dry_run=False, logs_col=None, ingestion_url=None):
    """
    Generate research-scenario and composite attacks (Attacks 14, 15, 16, 17, 18)
    derived from previously ingested baseline dataset telemetry.
    """
    composite_docs = {}

    # ATTACK 14: Encrypted Command-and-Control (category: "encrypted-c2")
    botnet_cfg = attacks_by_cat.get("botnet-c2")
    encrypted_cfg = attacks_by_cat.get("encrypted-c2", {
        "category": "encrypted-c2",
        "layer": "malware-behavioral",
        "dataset": "CICIDS2017-Derived"
    })
    encrypted_c2_docs = []
    for i in range(limit):
        details = generate_synthetic_features(botnet_cfg, i + 1) if botnet_cfg else {}
        details["tls_sni"] = "c2-cdn-edge-node.net"
        details["tls_cipher_suite"] = "TLS_AES_256_GCM_SHA384"
        details["entropy"] = round(random.uniform(7.85, 7.99), 3)
        details["beacon_interval_jitter_sec"] = round(random.uniform(0.1, 1.5), 2)
        details["note"] = "Re-tagged from botnet-c2: represents the same C2 behavior over an encrypted channel"
        doc = create_log_document(encrypted_cfg, details, i + 1)
        encrypted_c2_docs.append(doc)
    composite_docs["encrypted-c2"] = encrypted_c2_docs

    # ATTACK 15: AI-Adaptive / Adversarial Attack (category: "ai-adaptive")
    ai_adaptive_cfg = attacks_by_cat.get("ai-adaptive", {
        "category": "ai-adaptive",
        "layer": "research-scenario",
        "dataset": "CICIDS2017-Adversarial"
    })
    ai_adaptive_docs = []
    for i in range(limit):
        src_row_id = f"row_cicids_{1000 + i}"
        details = {
            "original_row_id": src_row_id,
            "perturbation_epsilon": 0.05,
            "target_model": "RandomForest_IsolationForest_MAD_PS",
            "evasion_successful": True,
            "original_feature_vector": {
                "flow_duration": 1250000,
                "flow_bytes_per_sec": 48200.5,
                "syn_flag_count": 1,
                "packet_length_mean": 820.0
            },
            "perturbed_feature_vector": {
                "flow_duration": 1250000 + int(random.uniform(-50000, 50000)),
                "flow_bytes_per_sec": round(48200.5 * (1 + random.uniform(-0.05, 0.05)), 2),
                "syn_flag_count": 1,
                "packet_length_mean": round(820.0 * (1 + random.uniform(-0.04, 0.04)), 2)
            },
            "note": "Adversarial feature perturbation generated to test classifier decision boundary robustness"
        }
        doc = create_log_document(ai_adaptive_cfg, details, i + 1)
        ai_adaptive_docs.append(doc)
    composite_docs["ai-adaptive"] = ai_adaptive_docs

    # ATTACK 16: Supply-Chain Compromise (category: "supply-chain-compromise")
    supply_cfg = attacks_by_cat.get("supply-chain-compromise", {
        "category": "supply-chain-compromise",
        "layer": "research-scenario",
        "dataset": "Composite-Scenario"
    })
    supply_docs = []
    now = datetime.now(timezone.utc)
    for i in range(limit // 2 if limit > 1 else 1):
        campaign_id = f"CMP_SUPPLY_CHAIN_{uuid.uuid4().hex[:8]}"
        t1 = (now - timedelta(minutes=30 - i * 5)).isoformat()
        details_stage1 = {
            "campaign_id": campaign_id,
            "stage": "Stage 1: Compromised Package Check-in",
            "component_name": "@trade-lib/market-analytics-v2.1.0",
            "infected_dependency": "event-stream-helper",
            "c2_server": "update-package-mirror.org",
            "action": "Outbound Beacon from Node Modules runtime"
        }
        doc1 = create_log_document(supply_cfg, details_stage1, i * 2 + 1, custom_timestamp=t1)
        supply_docs.append(doc1)

        t2 = (now - timedelta(minutes=15 - i * 5)).isoformat()
        details_stage2 = {
            "campaign_id": campaign_id,
            "stage": "Stage 2: Secondary Trojan Payload Execution",
            "component_name": "@trade-lib/market-analytics-v2.1.0",
            "dropped_payload_type": "Trojan-Backdoor-Handler",
            "injected_process": "node.exe -> child_process.fork",
            "action": "Privilege escalation and credential scraping"
        }
        doc2 = create_log_document(supply_cfg, details_stage2, i * 2 + 2, custom_timestamp=t2)
        supply_docs.append(doc2)
    composite_docs["supply-chain-compromise"] = supply_docs

    # ATTACK 17: Ransomware + Data Exfiltration (Double Extortion) (category: "double-extortion")
    double_ext_cfg = attacks_by_cat.get("double-extortion", {
        "category": "double-extortion",
        "layer": "research-scenario",
        "dataset": "Composite-Scenario"
    })
    double_ext_docs = []
    for i in range(limit // 2 if limit > 1 else 1):
        campaign_id = f"CMP_DOUBLE_EXTORTION_{uuid.uuid4().hex[:8]}"
        t1 = (now - timedelta(minutes=45 - i * 5)).isoformat()
        details_stage1 = {
            "campaign_id": campaign_id,
            "stage": "Stage 1: Sensitive Data Exfiltration",
            "exfiltrated_records_count": 48500,
            "exfil_target": "POST /admin/exportAll -> remote_storage",
            "database_collections_dumped": ["users", "orders", "holdings", "tickets"]
        }
        doc1 = create_log_document(double_ext_cfg, details_stage1, i * 2 + 1, custom_timestamp=t1)
        doc1["endpoint"] = "/admin/exportAll"
        double_ext_docs.append(doc1)

        t2 = (now - timedelta(minutes=15 - i * 5)).isoformat()
        details_stage2 = {
            "campaign_id": campaign_id,
            "stage": "Stage 2: High-Entropy File Encryption & Extortion Demand",
            "encryption_key_id": "AES-256-GCM-LOCKED",
            "rapid_file_encryptions_per_sec": 1850,
            "ransom_demand_btc": 2.5,
            "leak_site_url": "http://darkwebleakmarket77.onion",
            "ransom_note": "YOUR_FILES_HAVE_BEEN_ENCRYPTED_AND_COPIED.txt"
        }
        doc2 = create_log_document(double_ext_cfg, details_stage2, i * 2 + 2, custom_timestamp=t2)
        double_ext_docs.append(doc2)
    composite_docs["double-extortion"] = double_ext_docs

    # ATTACK 18: Zero-Day Detection Evaluation (category: "zero-day-eval")
    zero_day_cfg = attacks_by_cat.get("zero-day-eval", {
        "category": "zero-day-eval",
        "layer": "research-scenario",
        "dataset": "Holdout-Evaluation"
    })
    zero_day_docs = []
    for i in range(limit):
        details = {
            "holdout_target_category": "zero-day-eval",
            "zero_day_eval": True,
            "novelty_score": round(random.uniform(0.88, 0.98), 3),
            "isolation_forest_anomaly_score": -0.42,
            "unseen_protocol_features": ["CUSTOM_P2P_RPC", "NON_STANDARD_ENCODING"],
            "note": "Novel unseen attack vector telemetry reserved for zero-day evaluation"
        }
        doc = create_log_document(zero_day_cfg, details, i + 1)
        zero_day_docs.append(doc)
    composite_docs["zero-day-eval"] = zero_day_docs

    # Ingestion push or direct MongoDB fallback
    if not dry_run:
        for cat_k, doc_list in composite_docs.items():
            pushed = push_to_ingestion_service(doc_list, ingestion_url=ingestion_url, is_batch=True)
            if not pushed and logs_col is not None:
                for d in doc_list:
                    try:
                        logs_col.insert_one(d.copy())
                    except Exception:
                        pass

    return composite_docs


def run_replay(mode="bulk", speed=60, target_cat=None, holdout_cat=None, data_dir=DEFAULT_DATA_DIR, limit=10, dry_run=False, mongo_url=None, ingestion_url=None):
    """Execute dataset replay in either bulk or live drip mode."""
    attacks = load_categories()
    attacks_by_cat = {a["category"]: a for a in attacks}
    logs_col = get_mongo_collection(mongo_url) if not dry_run else None

    print("==================================================")
    print(f"   MAD-PS DATASET REPLAY ENGINE ({mode.upper()} MODE)   ")
    print("==================================================")
    print(f"Categories Configured: {len(attacks)}")
    print(f"Data Directory: {data_dir}")
    print(f"Limit per category: {limit}")
    if holdout_cat:
        print(f"Holdout Excluded: '{holdout_cat}' (Reserved for Zero-Day Evaluation)")
    if target_cat:
        print(f"Target Filter: '{target_cat}'")
    print("==================================================\n")

    summary_counts = {}
    inserted_docs = []

    # Process Attacks 1 to 13 (Standard direct dataset mappings)
    direct_attacks = [a for a in attacks if a["id"] <= 13]

    for attack in direct_attacks:
        cat = attack["category"]

        # Check category filter
        if target_cat and cat != target_cat:
            continue

        # Check holdout exclusion
        if holdout_cat and cat == holdout_cat:
            print(f"[HOLDOUT] Skipping '{cat}' from standard import (Held out for Zero-Day test).")
            continue

        summary_counts[cat] = 0

        # Attempt to find real CSV rows if present
        real_rows = find_csv_rows_for_attack(attack, data_dir, limit=limit)
        cat_batch_docs = []

        for i in range(limit):
            if real_rows and i < len(real_rows):
                details = real_rows[i]
                details["dataset_name"] = attack["dataset"]
            else:
                details = generate_synthetic_features(attack, i + 1)

            doc = create_log_document(attack, details, i + 1)
            cat_batch_docs.append(doc)
            inserted_docs.append(doc)
            summary_counts[cat] += 1

            if mode == "live":
                if not dry_run:
                    pushed = push_to_ingestion_service([doc], ingestion_url=ingestion_url, is_batch=False)
                    if not pushed and logs_col is not None:
                        try:
                            logs_col.insert_one(doc.copy())
                        except Exception:
                            pass
                delay_sec = 60.0 / max(speed, 1)
                print(f"[LIVE DRIP] [{doc['timestamp']}] ({doc['layer']}) {cat:30s} -> IP: {doc['ip']}")
                time.sleep(delay_sec)

        if mode == "bulk":
            if not dry_run:
                pushed = push_to_ingestion_service(cat_batch_docs, ingestion_url=ingestion_url, is_batch=True)
                if not pushed and logs_col is not None:
                    for d in cat_batch_docs:
                        try:
                            logs_col.insert_one(d.copy())
                        except Exception:
                            pass
            src_type = "CSV Data" if real_rows else "High-Fidelity Feature Vector"
            print(f"[BULK INSERT] Replayed {summary_counts[cat]:3d} rows -> Category: {cat:30s} ({src_type}, Layer: {attack['layer']})")

    # Process Attacks 14 to 18 (Composite, derived, and research scenarios)
    derived_cats = ["encrypted-c2", "ai-adaptive", "supply-chain-compromise", "double-extortion", "zero-day-eval"]
    
    if not target_cat or target_cat in derived_cats:
        composite_docs_map = generate_composite_scenarios(attacks_by_cat, limit=limit, dry_run=dry_run, logs_col=logs_col, ingestion_url=ingestion_url)
        for cat_k, doc_list in composite_docs_map.items():
            if target_cat and cat_k != target_cat:
                continue
            if holdout_cat and cat_k == holdout_cat:
                print(f"[HOLDOUT] Skipping '{cat_k}' from standard import (Held out for Zero-Day test).")
                continue

            summary_counts[cat_k] = len(doc_list)
            inserted_docs.extend(doc_list)

            if mode == "bulk":
                layer = doc_list[0]["layer"] if doc_list else "research-scenario"
                print(f"[BULK INSERT] Replayed {len(doc_list):3d} rows -> Category: {cat_k:30s} (Composite/Derived, Layer: {layer})")
            elif mode == "live":
                for d in doc_list:
                    delay_sec = 60.0 / max(speed, 1)
                    print(f"[LIVE DRIP] [{d['timestamp']}] ({d['layer']}) {cat_k:30s} -> IP: {d['ip']}")
                    time.sleep(delay_sec)

    # If holdout category was specified, generate its dedicated zero-day evaluation batch
    if holdout_cat:
        holdout_cfg = attacks_by_cat.get(holdout_cat)
        if holdout_cfg:
            print(f"\n[ZERO-DAY EVAL BATCH] Generating isolated evaluation logs for held-out '{holdout_cat}'...")
            zero_day_holdout_key = f"{holdout_cat} (zero-day-eval)"
            summary_counts[zero_day_holdout_key] = 0
            zero_day_batch = []
            for i in range(min(limit, 5)):
                details = generate_synthetic_features(holdout_cfg, i + 1)
                details["zero_day_eval"] = True
                details["held_out_category"] = holdout_cat
                details["novelty_score"] = round(random.uniform(0.91, 0.99), 3)
                details["isolation_forest_anomaly_score"] = -0.48
                doc = create_log_document(holdout_cfg, details, i + 1, custom_category="zero-day-eval", custom_layer="research-scenario")
                zero_day_batch.append(doc)
                inserted_docs.append(doc)
                summary_counts[zero_day_holdout_key] += 1
                if mode == "live":
                    if not dry_run:
                        pushed = push_to_ingestion_service([doc], ingestion_url=ingestion_url, is_batch=False)
                        if not pushed and logs_col is not None:
                            try:
                                logs_col.insert_one(doc.copy())
                            except Exception:
                                pass
                    print(f"[LIVE DRIP ZERO-DAY] [{doc['timestamp']}] (research-scenario) zero-day-eval (Held-Out: {holdout_cat}) -> IP: {doc['ip']}")

            if mode == "bulk" and not dry_run:
                pushed = push_to_ingestion_service(zero_day_batch, ingestion_url=ingestion_url, is_batch=True)
                if not pushed and logs_col is not None:
                    for d in zero_day_batch:
                        try:
                            logs_col.insert_one(d.copy())
                        except Exception:
                            pass

    print("\n==================================================")
    print("           REPLAY SUMMARY REPORT                  ")
    print("==================================================")
    for cat_name, count in summary_counts.items():
        print(f" - {cat_name:35s}: {count:4d} logs replayed")
    print(f"Total Telemetry Documents Processed: {len(inserted_docs)}")
    print("==================================================")

    return summary_counts


def main():
    parser = argparse.ArgumentParser(description="MAD-PS Dataset Replay Importer")
    parser.add_argument("--mode", choices=["bulk", "live"], default="bulk", help="Replay mode (bulk or live drip)")
    parser.add_argument("--speed", type=int, default=60, help="Rows per minute in live mode (default: 60)")
    parser.add_argument("--category", type=str, default=None, help="Filter to a single attack category")
    parser.add_argument("--holdout", type=str, default=None, help="Hold out a category for zero-day evaluation")
    parser.add_argument("--data-dir", type=str, default=str(DEFAULT_DATA_DIR), help="Path to local datasets CSV folder")
    parser.add_argument("--limit", type=int, default=10, help="Number of records to replay per category (default: 10)")
    parser.add_argument("--dry-run", action="store_true", help="Run without persisting to database")
    parser.add_argument("--mongo-url", type=str, default=None, help="MongoDB connection URI")
    parser.add_argument("--ingestion-url", type=str, default=None, help="Ingestion Service gateway URI (default: http://127.0.0.1:4000)")

    args = parser.parse_args()

    run_replay(
        mode=args.mode,
        speed=args.speed,
        target_cat=args.category,
        holdout_cat=args.holdout,
        data_dir=Path(args.data_dir),
        limit=args.limit,
        dry_run=args.dry_run,
        mongo_url=args.mongo_url,
        ingestion_url=args.ingestion_url,
    )


if __name__ == "__main__":
    main()
