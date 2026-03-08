from __future__ import annotations

from typing import Any, Dict, List


def build_incident_narrative(incident: Dict[str, Any]) -> str:
    user = incident.get("user", "unknown user")
    risk_score = incident.get("risk_score", 0)
    risk_level = incident.get("risk_level", "unknown")
    verdict = incident.get("verdict", "unknown")

    explanation = incident.get("explanation") or {}
    rules = explanation.get("rules_triggered") or []
    evidence = explanation.get("evidence") or []

    actions = incident.get("actions") or []
    if not actions:
        response = incident.get("response") or {}
        actions = response.get("actions") or []

    parts: List[str] = []

    parts.append(
        f"User {user} triggered a {risk_level}-risk incident with a risk score of {risk_score} and verdict {verdict}."
    )

    if rules:
        parts.append(
            "The incident was driven by " + ", ".join(str(r) for r in rules) + "."
        )

    if evidence:
        parts.append(
            "Observed activity included " + ", ".join(str(e) for e in evidence) + "."
        )

    if actions:
        parts.append(
            "Recommended response actions are " + ", ".join(str(a) for a in actions) + "."
        )

    return " ".join(parts)


def attach_narrative(incident: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(incident)
    enriched["narrative"] = build_incident_narrative(incident)
    return enriched
