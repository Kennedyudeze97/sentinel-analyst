# Sentinel SOC Automation Platform

Sentinel is a deterministic SOC-style security detection and automation platform that ingests identity/security telemetry, builds behavioral context, detects suspicious activity, explains findings, correlates related incidents, and generates response-ready artifacts.

It is designed to mirror how modern security teams triage identity threats, reduce alert fatigue, and support investigation and response workflows.

## Core capabilities

### Detection pipeline
- JSONL security event ingestion
- Per-user behavioral baseline construction
- Rule-based detection and anomaly identification
- Risk scoring and verdict generation
- MITRE ATT&CK mapping
- Structured incident generation

### Security engineering controls
- Deterministic canonical hashing
- Tamper-evident incident verification
- Strict-mode fail-closed ingest behavior
- JSON-safe serialization boundary
- Regression-tested pipeline behavior

### Automation and response
- Analyst-ready incident artifacts
- Slack / Jira / ServiceNow payload generation
- Deterministic risk-tiered response playbooks
- Response artifact generation tied to incident hashes
- SIEM-style forwarder payload generation

### Platform capabilities
- FastAPI service wrapper
- `/health` API endpoint
- `/analyze` API endpoint
- `/metrics` observability endpoint
- Docker support
- Cloud identity ingestion via Azure AD sign-in log adapter

---

## What Sentinel produces

Sentinel generates both analyst-facing and automation-ready outputs.

### Analyst-facing
- Human-readable SOC-style incident summaries
- Risk score, confidence, and verdict
- Timeline of suspicious activity
- Structured explanation of why detections fired
- MITRE ATT&CK mapping
- Recommended or simulated response actions

### Automation-ready
- Structured incident JSON (`incidents/*.json`)
- Slack alert payloads (`tickets/*.slack.json`)
- Jira ticket payloads (`tickets/*.jira.json`)
- ServiceNow ticket payloads (`tickets/*.servicenow.json`)
- SIEM forward payloads
- Response artifacts (`responses/*.json`)

---

## Why this matters

Security teams do not struggle with lack of alerts,they struggle with lack of context, excessive noise, and inconsistent response.

Sentinel focuses on:
- Correlating related signals into a single incident
- Explaining why detections fired
- Enriching alerts with contextual signals
- Mapping behavior to MITRE ATT&CK
- Reducing alert noise through correlation
- Producing deterministic, verifiable artifacts
- Driving response decisions from risk

This mirrors how SOC detection and security automation pipelines operate in production environments.

---

## Architecture

```mermaid
flowchart LR
  A[Event Logs / Identity Telemetry] --> B[Ingest & Normalize]
  B --> C[Behavioral Baseline]
  B --> D[Enrichment]
  C --> E[Detection Rules]
  D --> E
  E --> F[Explainability]
  F --> G[Correlation / Deduplication]
  G --> H[Risk Scoring]
  H --> I[Incident Generator]
  I --> J[Response Playbooks]
  I --> K[Integrity Hashing]
  K --> L[Outputs]

  L --> L1[CLI SOC Summary]
  L --> L2[Incident JSON]
  L --> L3[Slack / Jira / ServiceNow Payloads]
  L --> L4[SIEM Forward Payloads]
  L --> L5[Response Artifacts]
  L --> L6[FastAPI /metrics]
