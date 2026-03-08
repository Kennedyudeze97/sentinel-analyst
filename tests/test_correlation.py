from __future__ import annotations

from sentinel.correlation import correlate_incidents


def test_correlation_merges_same_user_rule_and_hour():
    incidents = [
        {
            "user": "alice@example.com",
            "risk_score": 70,
            "findings": [{"rule": "unusual_login_location"}],
            "explanation": {
                "rules_triggered": ["unusual_login_location"],
                "evidence": ["login from RU"],
            },
            "timeline": [{"ts": "2026-03-01T10:05:00Z"}],
        },
        {
            "user": "alice@example.com",
            "risk_score": 85,
            "findings": [{"rule": "unusual_login_location"}],
            "explanation": {
                "rules_triggered": ["unusual_login_location"],
                "evidence": ["login from RU again"],
            },
            "timeline": [{"ts": "2026-03-01T10:40:00Z"}],
        },
        {
            "user": "bob@example.com",
            "risk_score": 40,
            "findings": [{"rule": "failed_login_spike"}],
            "explanation": {
                "rules_triggered": ["failed_login_spike"],
                "evidence": ["many failures"],
            },
            "timeline": [{"ts": "2026-03-01T10:10:00Z"}],
        },
    ]

    out = correlate_incidents(incidents)

    assert len(out) == 2

    alice = [i for i in out if i["user"] == "alice@example.com"][0]
    assert alice["correlated_count"] == 2
    assert alice["risk_score"] == 85
    assert alice["correlation_window"]["first_seen"] == "2026-03-01T10:05:00Z"
    assert alice["correlation_window"]["last_seen"] == "2026-03-01T10:40:00Z"
    assert alice["explanation"]["rules_triggered"] == ["unusual_login_location"]
