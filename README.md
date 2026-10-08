# MAD-PS Target Application & Security Demo Environment (`OKOK`)

A vulnerable Zerodha-clone MERN application designed for cybersecurity training, SOC demonstrations, and training anomaly detection models on realistic security telemetry.

---

## 1. Quick Start & Execution

```bash
# 1. Start Backend (Port 3002)
cd backend
npm install
npm start

# 2. Start Frontend (Port 3000)
cd frontend
npm install
npm start
```

---

## 2. Attack Simulation Console

The MAD-PS platform includes a production-quality **Attack Simulation Console** accessible at `/attack-console` or `/dashboard/attack-console`.

> [!NOTE]
> **Authorized Security Simulation Environment**: All simulations operate strictly against the application's controlled security-testing environment (`127.0.0.1` / `localhost`). The system exercises real end-to-end defensive pipelines without arbitrary external tooling.

### End-to-End Demonstration Pipeline:

$$\text{Attack Console} \longrightarrow \text{Target Application} \longrightarrow \text{MongoDB Logs} \longrightarrow \text{ML Detection} \longrightarrow \text{LLM Explanation} \longrightarrow \text{Incidents} \longrightarrow \text{SOC Dashboard} \longrightarrow \text{Live Telemetry Feed}$$

### Step-by-Step Operator Workflow:

1. **Start MAD-PS Normally**: Launch the backend on port 3002 and frontend on port 3000.
2. **Authenticate as an Administrator**: Log in using seeded administrator credentials (`admin` / `admin123`).
3. **Open Attack Simulation Console**: Navigate to `http://localhost:3000/attack-console` or click **"⚡ Attack Console"** in the navigation menu.
4. **Fire Individual Simulations**:
   - **Phase 1 (Web & App)**: Click **"⚡ Fire Attack"** on *NoSQL Operator Injection*, *Stored XSS*, *Open Redirect*, *Business Logic*, etc.
   - **Phase 2 (Auth & Identity)**: Click **"⚡ Fire Attack"** on *JWT None-Algorithm*, *Session Fixation*, *Brute-Force*, *IDOR*, etc.
   - **Network, Malware & Research Simulation**: Click **"⚡ Fire Attack"** or **"🛠️ Tool"** on *Port Scanning*, *DoS Benchmark*, *DNS Cache Poisoning*, *Ransomware Burst*, etc.
5. **Observe the Event in the Live Feed**: Watch real-time telemetry land instantly via the Server-Sent Events (SSE) stream on the right panel.
6. **Observe the Event in `logs`**: Verify that structured telemetry documents are stored in the MongoDB `logs` collection with strict schema conformance.
7. **Observe ML Detection**: View the model prediction, anomaly classification, and risk score (`Detected ✓ Risk: 8/10 • Model: Random Forest`).
8. **Observe the Resulting Incident**: Review the incident metadata and LLM-generated root cause explanation detailing why the event was flagged.
9. **Observe the Incident in the SOC Dashboard**: Navigate to `/dashboard` to monitor active alerts and security posture metrics.
10. **Use Fire All 38 for Complete Simulation**:
    - Click **"🔥 Fire All 38"** at the top of the Attack Simulation Console.
    - Confirm the execution modal.
    - Watch the automated sequential progress indicator cycle through all 38 categories (`Running X / 38`, `Completed`, `Failed`, `Detected`) with live telemetry streaming smoothly without page reloads.

---

## 3. Replay CLI Commands (Alternative CLI Workflow)

```bash
# Ingest pre-labeled research dataset telemetry in bulk
npm run replay:bulk

# Live drip feed (e.g., DNS Spoofing at 60 events/minute)
npm run replay:live -- --speed 60 --category dns-spoofing

# Zero-Day Holdout evaluation
python dataset-replay/import.py --mode bulk --holdout dos
```
