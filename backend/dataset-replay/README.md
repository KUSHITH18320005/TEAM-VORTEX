# MAD-PS Dataset Replay Module (`backend/dataset-replay/`)

This directory contains the dataset replay engine for the **18 non-application-vulnerability MAD-PS attack categories** (network/infrastructure-layer, malware-behavioral, IoT edge devices, and research/adversarial scenarios).

The script replays static, pre-labeled records into the shared MongoDB `logs` collection using the standardized telemetry schema established in [LOGGING.md](file:///c:/Users/Hp/Desktop/OKOK/LOGGING.md).

---

## 1. Safety & Operational Constraints

1. **Zero Live Attack Traffic**: This module reads exclusively from static files or benchmark distributions. It **never** opens network sockets to scan, flood, spoof, or attack any real host, server, or device.
2. **Strict Isolation**: This module is a standalone CLI utility. It is **never** imported into Express routes or triggered by client-side frontend requests.
3. **Traceability**: Every generated log document explicitly contains:
   - `"source": "dataset-replay"`
   - `"layer": "network" | "malware-behavioral" | "iot" | "research-scenario"`
   - `"dataset": "<dataset_name>"`

---

## 2. Research Datasets & Manual Download Instructions

The pre-labeled telemetry is derived from publicly available, peer-reviewed cybersecurity research datasets provided by the **Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick (UNB)**.

> [!IMPORTANT]
> **Manual Download Required**: Due to licensing, registration requirements, and file sizes (10GB–50GB+), datasets must be downloaded manually from the official UNB CIC portal into the local `backend/dataset-replay/data/` folder. **Do not attempt to auto-download or scrape.**

### Dataset Reference Table

| Dataset | Focus Areas | Official Portal | Academic Citation |
|---------|-------------|-----------------|-------------------|
| **CICIDS2017** | PortScan, DoS (Hulk/GoldenEye/Slowloris), DDoS, Infiltration, Botnet C2 | [UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Sharafaldin et al. (2018), *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization* |
| **CIC-IoT2023** | DNS Spoofing, MITM ARP Spoofing, Mirai Botnet, IoT Edge Floods | [UNB CIC-IoT2023](https://www.unb.ca/cic/datasets/iot-dataset-2023.html) | Neto et al. (2023), *CICIoT2023: A Real-time Dataset and Benchmark for Large-Scale Attacks in IoT Networks* |
| **CIC-MalMem2022** | Ransomware, Spyware, Trojan, Obfuscated/Polymorphic Memory Vectors | [UNB CIC-MalMem2022](https://www.unb.ca/cic/datasets/malmem-2022.html) | Carrier et al. (2022), *Detecting Obfuscated Memory Malware using Machine Learning* |
| **NSL-KDD** | Probe, Network Service Enumeration, Baseline Comparison | [UNB NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) | Tavallaee et al. (2009), *A Detailed Analysis of the KDD CUP 99 Data Set* |

---

## 3. Directory Layout

```text
backend/dataset-replay/
├── README.md               # Documentation & UNB CIC dataset citations
├── categories.json         # Attack metadata, layer, dataset mapping, and feature definitions
├── import.py               # Replay engine (bulk mode, live drip mode, holdout mode)
└── data/                   # Target directory for manual UNB CIC CSV placement
```

---

## 4. Usage & Execution Modes

### A. Bulk Ingestion Mode (`--mode bulk`)
Replays pre-labeled batches for all 18 categories directly into the MongoDB `logs` collection.

```bash
# Via npm script (from backend/)
npm run replay:bulk

# Via direct Python CLI
python dataset-replay/import.py --mode bulk --limit 20
```

### B. Live Drip-Feed Mode (`--mode live`)
Sequentially emits logs with configurable delay (e.g. 60 rows/min) so the SOC dashboard displays live inbound attack events during interactive demonstrations.

```bash
# Via npm script (from backend/)
npm run replay:live

# Drip-feed a specific attack (e.g., DNS spoofing at 120 events/min)
python dataset-replay/import.py --mode live --speed 120 --category dns-spoofing
```

### C. Zero-Day Holdout Evaluation (`--holdout <category>`)
Excludes an attack category from the training dataset batch so it can be evaluated as an unseen novel attack vector by the MAD-PS anomaly detector.

```bash
python dataset-replay/import.py --mode bulk --holdout dos
```

---

## 5. Summary of the 18 Replay Attack Categories

| # | Attack Category | Layer | Source Dataset | Key Indicators / Features |
|---|-----------------|-------|----------------|---------------------------|
| 1 | `port-scanning-recon` | `network` | CICIDS2017 / NSL-KDD | SYN flag bursts, multi-destination port probes |
| 2 | `network-service-enumeration`| `network` | NSL-KDD | Specific protocol and service query spikes |
| 3 | `dos` | `network` | CICIDS2017 | Slowloris, Hulk, GoldenEye connection exhaustion |
| 4 | `ddos` | `network` | CICIDS2017 | Distributed volumetric floods across source IPs |
| 5 | `dns-spoofing` | `network` | CIC-IoT2023 | Poisoned cache replies, redirected resolution IPs |
| 6 | `mitm` | `network` | CIC-IoT2023 | ARP spoofing opcode 2 replies, altered hardware MACs |
| 7 | `ransomware-behavioral` | `malware-behavioral` | CIC-MalMem2022 | Rapid file write operations, high memory entropy |
| 8 | `trojan-behavioral` | `malware-behavioral` | CIC-MalMem2022 | Hidden process injection, unexpected registry handles |
| 9 | `spyware-behavioral` | `malware-behavioral` | CIC-MalMem2022 | Keystroke buffering, periodic outbound screen dumps |
| 10 | `botnet-c2` | `malware-behavioral` | CICIDS2017 / CIC-IoT2023 | Periodic low-frequency beaconing to external servers |
| 11 | `compromised-iot` | `iot` | CIC-IoT2023 | Abnormal outbound traffic from ESP32 edge nodes |
| 12 | `polymorphic-malware` | `malware-behavioral` | CIC-MalMem2022 | Obfuscated code signatures, variable memory layout |
| 13 | `apt-stealth-intrusion` | `network` | CICIDS2017 | Low-and-slow infiltration blending with baseline |
| 14 | `encrypted-c2` | `malware-behavioral` | CICIDS2017-Derived | C2 beaconing over encrypted TLS / HTTPS channels |
| 15 | `ai-adaptive` | `research-scenario` | CICIDS2017-Adversarial | Bounded feature perturbations ($\epsilon=0.05$) to evade ML |
| 16 | `supply-chain-compromise` | `research-scenario` | Composite-Scenario | Multi-stage package update injection + payload drop |
| 17 | `double-extortion` | `research-scenario` | Composite-Scenario | Pre-encryption data exfiltration + ransom demand |
| 18 | `zero-day-eval` | `research-scenario` | Holdout-Evaluation | Novel attack telemetry held out from model training |
