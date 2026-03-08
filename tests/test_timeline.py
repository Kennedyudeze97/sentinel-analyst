from __future__ import annotations

from sentinel.timeline import attach_timeline


def test_attach_timeline_orders_events_deterministically():
    incident = {
        "user": "alice@example.com",
        "risk_score": 80,
    }

    events = [
        {
            "ts": "2026-03-01T10:10:00Z",
            "event_type": "login_failure",
            "user": "alice@example.com",
            "src_ip": "185.12.44.2",
            "success": False,
        },
        {
            "ts": "2026-03-01T10:00:00Z",
            "event_type": "login_success",
            "user": "alice@example.com",
            "src_ip": "10.0.0.1",
            "success": True,
        },
        {
            "ts": "2026-03-01T10:05:00Z",
            "event_type": "login_failure",
            "user": "alice@example.com",
            "src_ip": "185.12.44.2",
            "success": False,
        },
    ]

    enriched = attach_timeline(incident, events)

    assert "timeline" in enriched
    assert len(enriched["timeline"]) == 3
    assert enriched["timeline"][0]["ts"] == "2026-03-01T10:00:00Z"
    assert enriched["timeline"][1]["ts"] == "2026-03-01T10:05:00Z"
    assert enriched["timeline"][2]["ts"] == "2026-03-01T10:10:00Z"
