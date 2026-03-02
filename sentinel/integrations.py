from __future__ import annotations

from typing import Any, Dict, List, Set


def _impact_urgency_from_risk(risk_level: str) -> tuple[int, int, int]:
    if risk_level == "critical":
        return 1, 1, 15
    if risk_level == "high":
        return 1, 2, 60
    if risk_level == "medium":
        return 2, 3, 240
    return 3, 4, 1440


def _jira_priority_from_risk(risk_level: str) -> str:
    return {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}.get(risk_level, "P3")


def _category_from_rule_ids(rule_ids: Set[str]) -> tuple[str, str]:
    if "R001" in rule_ids:
        return "Identity Security", "Credential Attacks"
    if "R002" in rule_ids:
        return "Identity Security", "Privilege Escalation"
    if "R004" in rule_ids or "R005" in rule_ids or "R006" in rule_ids:
        return "Identity Security", "Anomalous Access"
    return "Security Monitoring", "Suspicious Activity"


def _extract_artifacts(incident) -> Dict[str, Any]:
    ips: Set[str] = set()
    devices: Set[str] = set()
    countries: Set[str] = set()
    cities: Set[str] = set()
    resources: Set[str] = set()

    for e in incident.raw_events:
        if e.source_ip:
            ips.add(e.source_ip)
        if e.device_id:
            devices.add(e.device_id)
        if e.country:
            countries.add(e.country)
        if e.city:
            cities.add(e.city)
        if e.resource:
            resources.add(e.resource)

    return {
        "ips": sorted(list(ips)),
        "devices": sorted(list(devices)),
        "countries": sorted(list(countries)),
        "cities": sorted(list(cities)),
        "resources": sorted(list(resources)),
    }


def _labels(incident, rule_ids: List[str]) -> List[str]:
    labels: List[str] = []
    labels.extend([f"mitre:{t}" for t in (incident.mitre_techniques or [])])
    labels.extend([f"rule:{r}" for r in rule_ids])
    labels.append("domain:identity")
    labels.append(f"risk:{incident.risk_level}")
    labels.append(f"verdict:{incident.verdict}")
    return labels


def build_servicenow_ticket(incident) -> Dict[str, Any]:
    rule_ids = sorted({f.rule_id for f in incident.findings})
    impact, urgency, sla_target_minutes = _impact_urgency_from_risk(incident.risk_level)
    category, subcategory = _category_from_rule_ids(set(rule_ids))
    artifacts = _extract_artifacts(incident)
    dedupe_key = f"user={incident.user}|rules={','.join(rule_ids)}|risk={incident.risk_level}"
    top_steps = incident.recommended_actions[:3]

    return {
        "short_description": incident.summary,
        "description": incident.narrative,
        "category": category,
        "subcategory": subcategory,
        "assignment_group": "SOC",
        "caller_id": "sentinel-analyst",
        "priority": incident.risk_level.upper(),
        "impact": impact,
        "urgency": urgency,
        "sla_target_minutes": sla_target_minutes,
        "u_incident_id": incident.incident_id,
        "u_user": incident.user,
        "u_verdict": incident.verdict,
        "u_confidence": incident.confidence,
        "u_mitre_techniques": incident.mitre_techniques,
        "u_rule_ids": rule_ids,
        "u_artifacts": artifacts,
        "u_dedupe_key": dedupe_key,
        "work_notes": "Recommended next steps:\n- " + "\n- ".join(top_steps) if top_steps else "",
        "u_timeline": incident.timeline,
        "created_at": incident.created_at.isoformat(),
        "source": "sentinel-analyst",
    }


def build_jira_ticket(incident) -> Dict[str, Any]:
    rule_ids = sorted({f.rule_id for f in incident.findings})
    category, subcategory = _category_from_rule_ids(set(rule_ids))
    artifacts = _extract_artifacts(incident)
    dedupe_key = f"user={incident.user}|rules={','.join(rule_ids)}|risk={incident.risk_level}"

    return {
        "projectKey": "SEC",
        "issueType": "Incident",
        "summary": f"{_jira_priority_from_risk(incident.risk_level)}: {incident.summary}",
        "description": incident.narrative + ("\n\nTimeline:\n" + incident.timeline if incident.timeline else ""),
        "labels": _labels(incident, rule_ids),
        "priority": _jira_priority_from_risk(incident.risk_level),
        "customFields": {
            "incident_id": incident.incident_id,
            "user": incident.user,
            "risk_level": incident.risk_level,
            "risk_score": incident.risk_score,
            "verdict": incident.verdict,
            "confidence": incident.confidence,
            "mitre_techniques": incident.mitre_techniques,
            "rule_ids": rule_ids,
            "category": category,
            "subcategory": subcategory,
            "artifacts": artifacts,
            "dedupe_key": dedupe_key,
            "recommended_actions": incident.recommended_actions,
        },
        "created_at": incident.created_at.isoformat(),
        "source": "sentinel-analyst",
    }


def _compact_timeline_lines(timeline: str, max_lines: int = 2) -> str:
    """
    Compress timeline lines so they don't wrap badly in Slack.
    Keeps timestamp + event_type + ip + location.
    """
    if not timeline:
        return ""
    out: List[str] = []
    for line in timeline.splitlines()[:max_lines]:
        # Example format:
        # 2026-...  login_success  ip=... device=...  Berlin, DE outcome=success
        parts = line.split()
        if len(parts) < 4:
            out.append(line)
            continue

        ts = parts[0]
        evt = parts[1]
        ip = next((p for p in parts if p.startswith("ip=")), "ip=?")
        # try to keep last "City, CC" if present
        loc = ""
        if "," in line:
            loc = line.split("  ")[-1]  # last segment after double-space
        compact = f"{ts}  {evt}  {ip}"
        if loc:
            compact += f"  {loc}"
        out.append(compact[:180])  # safety cap
    return "\n".join(out)


def build_slack_payload(incident) -> Dict[str, Any]:
    rule_ids = sorted({f.rule_id for f in incident.findings})
    artifacts = _extract_artifacts(incident)
    mitre_list = incident.mitre_techniques or []
    mitre = ", ".join(mitre_list) if mitre_list else "N/A"
    dedupe_key = f"user={incident.user}|rules={','.join(rule_ids)}|risk={incident.risk_level}"

    incident_path = f"incidents/{incident.incident_id}.json"
    servicenow_path = f"tickets/{incident.incident_id}.servicenow.json"
    jira_path = f"tickets/{incident.incident_id}.jira.json"

    top_actions = incident.recommended_actions[:3]
    actions_text = "\n".join([f"• {a}" for a in top_actions]) if top_actions else "_None_"
    timeline_text = _compact_timeline_lines(incident.timeline, max_lines=2) or "_No timeline_"

    artifacts_lines = []
    if artifacts.get("ips"):
        artifacts_lines.append("*IPs:* " + ", ".join([f"`{ip}`" for ip in artifacts["ips"]]))
    if artifacts.get("devices"):
        artifacts_lines.append("*Devices:* " + ", ".join([f"`{d}`" for d in artifacts["devices"]]))
    if artifacts.get("countries"):
        artifacts_lines.append("*Countries:* " + ", ".join([f"`{c}`" for c in artifacts["countries"]]))
    artifacts_text = "\n".join(artifacts_lines) if artifacts_lines else "_No artifacts extracted_"

    blocks: List[Dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": incident.summary}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Risk:*\n{incident.risk_level.upper()} ({incident.risk_score}/100)"},
            {"type": "mrkdwn", "text": f"*Confidence:*\n{incident.confidence:.2f}"},
            {"type": "mrkdwn", "text": f"*Verdict:*\n{incident.verdict}"},
            {"type": "mrkdwn", "text": f"*User:*\n`{incident.user}`"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*MITRE:*\n{mitre}"},
            {"type": "mrkdwn", "text": f"*Rules:*\n{', '.join(rule_ids)}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Artifacts:*\n{artifacts_text}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Next steps (top 3):*\n{actions_text}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Timeline (first events):*\n```{timeline_text}```"}},

        # Action buttons (placeholders for future automation)
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Contain"}, "value": f"contain:{incident.incident_id}"},
            {"type": "button", "text": {"type": "plain_text", "text": "Escalate"}, "value": f"escalate:{incident.incident_id}"},
            {"type": "button", "text": {"type": "plain_text", "text": "False Positive"}, "value": f"fp:{incident.incident_id}"},
        ]},

        {"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"*Incident file:* `{incident_path}`"},
            {"type": "mrkdwn", "text": f"*ServiceNow payload:* `{servicenow_path}`"},
            {"type": "mrkdwn", "text": f"*Jira payload:* `{jira_path}`"},
            {"type": "mrkdwn", "text": f"*Dedupe:* `{dedupe_key}`"},
        ]},
    ]

    return {
        "text": incident.summary,
        "blocks": blocks,
        "unfurl_links": False,
        "unfurl_media": False,
        "metadata": {
            "event_type": "sentinel_analyst_incident",
            "dedupe_key": dedupe_key,
            "incident_id": incident.incident_id,
            "user": incident.user,
            "risk_level": incident.risk_level,
            "rule_ids": rule_ids,
            "mitre_techniques": mitre_list,
        }
    }
