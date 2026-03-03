# Sentinel SOC Automation Platform

Sentinel is a local SOC-style detection engine that ingests identity/security events, builds a per-user behavioral baseline, detects suspicious activity, scores risk, and generates analyst-ready incidents and workflow payloads.

It is designed to mirror how real security teams triage identity threats, correlate signals, and produce investigation-ready output.

## What it produces

Sentinel generates both analyst-facing and automation-ready outputs.

### Analyst-facing
- Human-readable SOC-style incident summaries (terminal)
- Risk score, confidence, and verdict
- Timeline of suspicious activity
- MITRE ATT&CK mapping
- Recommended response actions

### Automation-ready
- Structured incident JSON (`incidents/*.json`)
- Slack alert payloads (`tickets/*.slack.json`)
- Jira ticket payloads (`tickets/*.jira.json`)
- ServiceNow ticket payloads (`tickets/*.servicenow.json`)

## Why this matters (SOC reality)

Security teams don’t struggle with lack of alerts — they struggle with lack of context.

Sentinel focuses on:
- Correlating related signals into a single incident
- Explaining why detections fired
- Attaching evidence and rationale
- Mapping behavior to MITRE ATT&CK
- Generating ready-to-use workflow artifacts

This mirrors how SOC detection engineering pipelines operate in production environments.

---

## Architecture

```mermaid
flowchart LR
  A[Event Logs JSONL] --> B[Ingest & Parse]
  B --> C[Baseline Builder]
  B --> D[Detection Rules]
  C --> D
  D --> E[Risk Scoring]
  E --> F[Incident Generator]
  F --> G[Outputs]

  G --> G1[CLI SOC Summary]
  G --> G2[Incident JSON]
  G --> G3[Slack / Jira / ServiceNow Payloads]
md
