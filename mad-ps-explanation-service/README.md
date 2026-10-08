# MAD-PS LLM Explanation Layer — "Browser Council v2" Multi-Agent Debate

The **MAD-PS Explanation Service** is a high-assurance security explanation and incident response layer that ingests real `IncidentRecord` outputs from the **MAD-PS Detection Mesh**, convenes a **7-model Browser Council** across **5 sequential debate rounds**, and produces authoritative, telemetry-grounded explanation reports with deterministic consensus metrics and judicial fact-check audits.

---

## 🏛️ System Architecture (Browser Council v2)

```
                       ┌─────────────────────────────────────────────────────────┐
                       │          mad-ps-detection-api (Incident Record)         │
                       │     (Category, Severity, Branch Scores, Raw Logs)       │
                       └────────────────────────────┬────────────────────────────┘
                                                    │
                                                    ▼
                       ┌─────────────────────────────────────────────────────────┐
                       │   Task Y8: Threshold Gating (Latency/Cost Optimizer)    │
                       │   • Fast-Lane: Confidence < 0.70 OR Risk < 7.0 (1 Model)│
                       │   • Deep-Lane: Confidence >= 0.70 & Risk >= 7.0 (7 Model│
                       └────────────┬───────────────────────────────┬────────────┘
                                    │                               │
                      [Fast-Lane]   │                               │  [Deep-Lane]
                                    ▼                               ▼
                 ┌───────────────────────────┐    ┌──────────────────────────────────────────────┐
                 │ Single-Model Magistrate   │    │ Task Y2: Shared Telemetry Grounding Assembly │
                 │ Quick Incident Synthesis  │    └───────────────────────┬──────────────────────┘
                 └─────────────┬─────────────┘                            │
                               │                                          ▼
                               │                 ┌──────────────────────────────────────────────┐
                               │                 │ Task Y3: Round 1 — Reconstruction (P1 - P3)  │
                               │                 │ Claude 3.5 Sonnet, GPT-4o, Gemini 2.0 Flash  │
                               │                 │ Parallel answers: "What happened & why"      │
                               │                 └───────────────────────┬──────────────────────┘
                               │                                          │
                               │                                          ▼
                               │                 ┌──────────────────────────────────────────────┐
                               │                 │ Task Y4: Round 2 — Response (P4 - P6)        │
                               │                 │ Llama 3.3 70B, Mixtral 8x7B, DeepSeek Chat   │
                               │                 │ Tactical Containment & System Resilience     │
                               │                 └───────────────────────┬──────────────────────┘
                               │                                          │
                               │                                          ▼
                               │                 ┌──────────────────────────────────────────────┐
                               │                 │ Task Y5: Round 3 — Peer Cross-Examinations   │
                               │                 │ 6 Panelists cross-examine peer hypotheses    │
                               │                 └───────────────────────┬──────────────────────┘
                               │                                          │
                               │                                          ▼
                               │                 ┌──────────────────────────────────────────────┐
                               │                 │ Task Y6: Round 4 — Chief Magistrate Synthesis│
                               │                 │ The Arbiter: Telemetry Fact-Check Audit,     │
                               │                 │ Split Resolution, Consensus Metric (0-100%)  │
                               │                 └───────────────────────┬──────────────────────┘
                               │                                          │
                               │                                          ▼
                               │                 ┌──────────────────────────────────────────────┐
                               │                 │ Round 5 — Panelist Stance Voting             │
                               │                 │ 6 Panelists cast AGREE / REVISE / DISSENT    │
                               │                 └───────────────────────┬──────────────────────┘
                               │                                          │
                               └────────────────────┬─────────────────────┘
                                                    │
                                                    ▼
                               ┌──────────────────────────────────────────┐
                               │ Final Grounded Explanation Report        │
                               │ (Execution Lane, Fact Checks, Consensus) │
                               └──────────────────────────────────────────┘
```

---

## 🤖 The Council: 7 Model Roles

1. **Panelist 1 (Lead Forensic Reconstructor)** — `claude-3-5-sonnet` (Anthropic)
2. **Panelist 2 (Deterministic Log Analyst)** — `gpt-4o` (OpenAI)
3. **Panelist 3 (Heuristic Code Invariant Auditor)** — `gemini-2.0-flash` (Google)
4. **Panelist 4 (Rapid Containment Specialist)** — `llama-3.3-70b` (Meta / Groq)
5. **Panelist 5 (Resilience Architect)** — `mixtral-8x7b` (Mistral)
6. **Panelist 6 (Zero-Trust Policy Advisor)** — `deepseek-chat` (DeepSeek)
7. **Chief Magistrate ("The Arbiter")** — `gemini-1.5-pro` (Judicial Fact-Check & Split Resolution)

4. **Multi-Agent Debate Revision Protocol**
   - Sends the Judge's synthesis back to Agent 1 and Agent 2: *"The Judge found X — do you agree or want to revise your position?"*
   - Captures real agent stances (`AGREE`, `REVISE`, `DISSENT`) and calculates empirical **"Confidence via Consensus"** scores.

---

## 🧪 AI Distillation Strategy

### Tier 1 (Active & Built): In-Context Exemplar Distillation
- **Debate Transcripts Store**: Every Council debate session is logged to `data/distillation/debate_transcripts.jsonl`.
- **Human-in-the-Loop Feedback**: SOC analysts can submit thumbs-up / thumbs-down ratings on generated reports.
- **Quality Filter & Indexing**: Transcripts with human approval (1.0) or automated Full Consensus (0.95) are indexed into category-specific few-shot exemplars.
- **Dynamic In-Context Injection**: Future runs on matching vulnerability categories automatically retrieve and inject the top 2-3 historical gold-standard demonstrations into Agent 1 and Agent 2 prompts, continuously improving precision without training overhead.

### Tier 2 (Future Work): True Weight-Level Distillation
> **Scope Definition**: True weight-level distillation fine-tunes the weights of a small open-weight model on high-volume synthetic outputs generated by a stronger teacher model.

- **Objective**: As the `debate_transcripts` collection scales to thousands of verified incidents, fine-tune an open-weight 7B–8B model (e.g., *Llama-3.1-8B-Instruct* or *Qwen-2.5-7B*) via **LoRA / QLoRA** specifically on the **Judge Agent's** synthesized outputs.
- **Edge-Cloud Tiered Dispatch**:
  - **Local Tier (7B Fine-Tuned)**: Serves routine, high-frequency incidents locally with zero cloud API cost and sub-second latency.
  - **Council Tier (Cloud Multi-Agent)**: Dynamically escalates novel attack signatures, critical-severity incidents, or disputed alerts to the full 3-Agent Council.
- **Dataset Export**: The built-in `ExemplarStore.export_fine_tuning_dataset()` method automatically exports formatted SFT (Supervised Fine-Tuning) JSONL datasets ready for HuggingFace / Axolotl / Unsloth training pipelines.

---

## 🚀 Getting Started

### Installation & Prerequisites
```bash
# Clone and navigate to service
cd mad-ps-explanation-service

# Install dependencies
pip install fastapi uvicorn httpx pydantic pytest
```

### Environment Configuration
```bash
# Configure LLM Provider Keys (at least one required; simulator fallback available)
export ANTHROPIC_API_KEY="your-claude-key"
export OPENAI_API_KEY="your-openai-key"
export GEMINI_API_KEY="your-gemini-key"
```

### Running Tests
```bash
python -m pytest tests/ -v
```
