from __future__ import annotations

from sentinel.explain import attach_explanation


def test_attach_explanation_adds_structured_reasoning():
    incident = {
        "risk_score": 82,
        "risk_level": "high",
        "verdict": "malicious",
        "findings": [
            {
                "rule": "unusual_login_location",
                "reason": "login from new country",
            },
            {
                "rule": "failed_login_spike",
                "reason": "repeated failed authentication attempts",
            },
        ],
    }

    enriched = attach_explanation(incident)

    assert "explanation" in enriched
    assert enriched["explanation"]["rules_triggered"] == [
        "failed_login_spike",
        "unusual_login_location",
    ]
    assert "multiple high-risk indicators present" == enriched["explanation"]["confidence_reasoning"]
    assert enriched["explanation"]["risk_basis"]["risk_score"] == 82
