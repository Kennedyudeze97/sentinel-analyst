from __future__ import annotations

from typing import Any, Dict, List


def build_incident_explanation(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a structured explanation block for an incident.

    This is intentionally heuristic and minimal:
    it extracts rationale from fields already present in the incident.
    """
    findings = incident.get("findings") or []
    evidence: List[str] = []
    rules: List[str] = []

    for f in findings:
        if isinstance(f, dict):
            rule = f.get("rule") or f.get("detector") or f.get("name")
            if rule:
                rules.append(str(rule))

            if f.get("reason"):
                evidence.append(str(f["reason"]))
            elif f.get("summary"):
                evidence.append(str(f["summary"]))

    risk_score = incident.get("risk_score", 0)
    if risk_score >= 80:
        confidence_reasoning = "multiple high-risk indicators present"
    elif risk_score >= 60:
        confidence_reasoning = "moderate-risk indicators correlated"
    else:
        confidence_reasoning = "limited but suspicious signal set"

    return {
        "rules_triggered": sorted(set(rules)),
        "evidence": evidence,
        "confidence_reasoning": confidence_reasoning,
        "risk_basis": {
            "risk_score": risk_score,
            "risk_level": incident.get("risk_level"),
            "verdict": incident.get("verdict"),
        },
    }


def attach_explanation(incident: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(incident)
    enriched["explanation"] = build_incident_explanation(incident)
    return enriched
