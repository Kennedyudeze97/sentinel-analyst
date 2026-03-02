from __future__ import annotations

from datetime import datetime
import uuid
import os

from sentinel.schemas import SecurityEvent, Finding, Incident
from sentinel.detectors import detect, score
from sentinel.baseline import build_baseline, save_baseline, get_user_baseline


MITRE_MAP = {
    "R001": {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"},
    "R002": {"tactic": "Privilege Escalation", "technique_id": "T1098", "technique": "Account Manipulation"},
    "R003": {"tactic": "Collection", "technique_id": "T1213", "technique": "Data from Information Repositories"},
    "R004": {"tactic": "Initial Access", "technique_id": "T1078", "technique": "Valid Accounts"},
    "R005": {"tactic": "Initial Access", "technique_id": "T1078", "technique": "Valid Accounts"},
    "R006": {"tactic": "Defense Evasion", "technique_id": "T1036", "technique": "Masquerading"},
}


def enrich_mitre(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if not f.mitre:
            f.mitre = MITRE_MAP.get(f.rule_id, {})
    return findings


def build_timeline(events: list[SecurityEvent]) -> str:
    lines = []
    for e in sorted(events, key=lambda x: x.ts):
        loc = ", ".join([x for x in [e.city, e.country] if x])
        dev = f" device={e.device_id}" if e.device_id else ""
        out = f" outcome={e.outcome}" if e.outcome else ""
        res = f" resource={e.resource}" if e.resource else ""
        ip = e.source_ip or "unknown_ip"
        lines.append(f"{e.ts.isoformat()}  {e.event_type}  ip={ip}{dev}  {loc}{out}{res}".rstrip())
    return "\n".join(lines)


def compute_confidence(findings: list[Finding]) -> float:
    if not findings:
        return 0.0

    sev_weight = {"low": 0.10, "medium": 0.20, "high": 0.32, "critical": 0.45}
    base = 0.25

    max_sev = max(findings, key=lambda f: sev_weight[f.severity]).severity
    conf = base + sev_weight[max_sev]

    distinct_rules = len(set(f.rule_id for f in findings))
    if distinct_rules > 1:
        conf += min(0.18, 0.06 * (distinct_rules - 1))

    rules = set(f.rule_id for f in findings)
    if "R002" in rules:
        conf += 0.10
    if "R004" in rules and "R005" in rules:
        conf += 0.06

    conf = max(0.05, min(0.99, conf))
    return round(conf, 2)


def compute_verdict(risk_level: str, confidence: float) -> str:
    if risk_level == "critical" and confidence >= 0.85:
        return "confirmed_compromise"
    if risk_level in ("critical", "high") and confidence >= 0.65:
        return "likely_compromise"
    if risk_level in ("medium", "high"):
        return "suspicious"
    return "benign"


def build_narrative(user: str, risk_score: int, risk_level: str, findings: list[Finding], confidence: float, verdict: str) -> str:
    bullets = "\n".join([
        f"- {f.title} ({f.severity.upper()}): {f.rationale}"
        + (f" [MITRE {f.mitre.get('technique_id','')} {f.mitre.get('technique','')}]" if f.mitre else "")
        for f in findings
    ]) or "- No strong signals detected."

    return (
        f"Assessment for user '{user}': risk={risk_level.upper()} ({risk_score}/100), "
        f"confidence={confidence:.2f}, verdict={verdict}.\n\n"
        f"Key signals:\n{bullets}\n\n"
        "Interpretation:\n"
        "Signals are correlated patterns often seen in account compromise, misuse, or policy violations. "
        "Validate whether this matches expected business behavior before taking irreversible actions."
    )


def recommended_actions(risk_level: str) -> list[str]:
    base_actions = [
        "Confirm user activity with manager or the user (out-of-band).",
        "Check recent password resets, MFA changes, and device enrollments.",
        "Review correlated activity for affected systems in the same timeframe.",
    ]
    if risk_level in ("high", "critical"):
        return [
            "Temporarily revoke active sessions and require re-authentication (step-up MFA).",
            "Reset password and enforce MFA re-enrollment if compromise suspected.",
            "Review privilege assignments; revert unauthorized role changes.",
            "Preserve logs and timestamps for investigation (do not delete evidence).",
            "Open an incident and notify security operations.",
            *base_actions,
        ]
    return base_actions


def _events_already_have_baseline(events: list[SecurityEvent]) -> bool:
    for e in events:
        if isinstance(e.meta, dict) and "baseline" in e.meta and isinstance(e.meta["baseline"], dict):
            return True
    return False


def _attach_baseline_singlefile_mode(events: list[SecurityEvent]) -> None:
    os.makedirs("baseline", exist_ok=True)
    baseline_data = build_baseline(events)
    save_baseline("baseline/baseline.json", baseline_data)

    users = sorted(set(e.user for e in events))
    for user in users:
        user_base = get_user_baseline(baseline_data, user)
        for e in events:
            if e.user == user and isinstance(e.meta, dict):
                e.meta["baseline"] = user_base


def analyze(events: list[SecurityEvent]) -> list[Incident]:
    if not _events_already_have_baseline(events):
        _attach_baseline_singlefile_mode(events)

    users = sorted(set(e.user for e in events))
    incidents: list[Incident] = []

    for user in users:
        u_events = [e for e in events if e.user == user]

        findings = enrich_mitre(detect(u_events))
        rs, rl = score(findings)
        if rs == 0:
            continue

        confidence = compute_confidence(findings)
        verdict = compute_verdict(rl, confidence)

        timeline = build_timeline(u_events)
        narrative = build_narrative(user, rs, rl, findings, confidence, verdict)
        if timeline:
            narrative = narrative + "\n\nTimeline:\n" + timeline

        mitre_ids = sorted({(f.mitre or {}).get("technique_id") for f in findings if (f.mitre or {}).get("technique_id")})

        incidents.append(Incident(
            incident_id=str(uuid.uuid4())[:8],
            created_at=datetime.utcnow(),
            user=user,
            risk_score=rs,
            risk_level=rl,
            confidence=confidence,
            verdict=verdict,
            summary=f"{rl.upper()} risk activity detected for {user}",
            narrative=narrative,
            timeline=timeline,
            mitre_techniques=mitre_ids,
            findings=findings,
            recommended_actions=recommended_actions(rl),
            raw_events=sorted(u_events, key=lambda x: x.ts),
        ))

    return incidents
