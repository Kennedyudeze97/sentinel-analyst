from __future__ import annotations

from sentinel.narrative import attach_narrative


def test_attach_narrative_adds_human_readable_summary():
    incident = {
        "user": "alice@example.com",
        "risk_score": 85,
        "risk_level": "high",
        "verdict": "malicious",
        "explanation": {
            "rules_triggered": ["unusual_login_location", "failed_login_spike"],
            "evidence": ["login from RU", "repeated failed authentication attempts"],
        },
        "actions": ["disable_user", "escalate_ticket"],
    }

    enriched = attach_narrative(incident)

    assert "narrative" in enriched
    assert "alice@example.com" in enriched["narrative"]
    assert "high-risk incident" in enriched["narrative"]
    assert "unusual_login_location" in enriched["narrative"]
    assert "disable_user" in enriched["narrative"]
