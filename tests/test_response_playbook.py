from __future__ import annotations

import json
from pathlib import Path

from sentinel.respond import build_response, write_response_artifact


def test_response_playbook_is_deterministic_and_risk_tiered(tmp_path: Path):
    incident = {
        "incident_hash": "abc123incidenthash",
        "risk_score": 85,
        "user": "alice@example.com",
    }

    r1 = build_response(incident)
    r2 = build_response(incident)

    assert r1["response_id"] == r2["response_id"]
    assert r1["response_hash"] == r2["response_hash"]
    assert r1["actions"] == ["disable_user", "escalate_ticket"]
    assert r1["required_approvals"] == ["security_lead"]

    path = write_response_artifact(incident, out_dir=str(tmp_path))
    data = json.loads(Path(path).read_text())

    assert data["incident_hash"] == "abc123incidenthash"
    assert data["response_id"] == r1["response_id"]
    assert data["actions"] == ["disable_user", "escalate_ticket"]
