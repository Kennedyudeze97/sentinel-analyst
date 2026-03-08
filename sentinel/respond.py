from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from sentinel.integrity import canonical_json, sha256_bytes
from sentinel.serialize import to_json_safe


RESPONDER_VERSION = "1.0"


def select_actions(risk_score: int) -> Dict[str, Any]:
    if risk_score >= 80:
        return {
            "actions": ["disable_user", "escalate_ticket"],
            "required_approvals": ["security_lead"],
            "reasoning": "high-risk incident requires containment and escalation",
        }
    if risk_score >= 60:
        return {
            "actions": ["escalate_ticket"],
            "required_approvals": [],
            "reasoning": "medium-risk incident requires analyst review",
        }
    return {
        "actions": ["monitor"],
        "required_approvals": [],
        "reasoning": "low-risk incident retained for observation",
    }


def build_response(incident: Dict[str, Any]) -> Dict[str, Any]:
    safe_incident = to_json_safe(incident)

    incident_hash = safe_incident.get("incident_hash")
    if not incident_hash:
        raise ValueError("incident_hash is required to build a response")

    risk_score = int(safe_incident.get("risk_score", 0))
    decision = select_actions(risk_score)

    response_id = sha256_bytes(
        canonical_json(
            {
                "incident_hash": incident_hash,
                "responder_version": RESPONDER_VERSION,
            }
        )
    )

    response = {
        "response_id": response_id,
        "incident_hash": incident_hash,
        "risk_score": risk_score,
        "actions": decision["actions"],
        "required_approvals": decision["required_approvals"],
        "reasoning": decision["reasoning"],
        "responder_version": RESPONDER_VERSION,
    }

    response["response_hash"] = sha256_bytes(canonical_json(response))
    return response


def write_response_artifact(incident: Dict[str, Any], out_dir: str = "responses") -> str:
    response = build_response(incident)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    path = out / f"response_{response['response_id'][:12]}.json"
    path.write_text(json.dumps(response, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)
