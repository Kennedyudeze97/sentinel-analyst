from __future__ import annotations

from sentinel.enrichment import enrich_event


def test_enrichment_adds_geoip_and_history_context():
    history = [
        {"event_type": "login", "user": "alice@example.com", "src_ip": "10.0.0.1", "success": False},
        {"event_type": "login", "user": "alice@example.com", "src_ip": "10.0.0.1", "success": False},
        {"event_type": "login", "user": "bob@example.com", "src_ip": "203.0.113.5", "success": False},
    ]

    event = {
        "event_type": "login",
        "user": "alice@example.com",
        "src_ip": "185.12.44.2",
        "success": True,
        "meta": {"source": "azuread"},
    }

    enriched = enrich_event(event, history)

    assert enriched["meta"]["geoip_country"] == "RU"
    assert enriched["meta"]["failed_login_history"] == 2
    assert enriched["meta"]["historical_risk"] == "medium"
    assert enriched["meta"]["source"] == "azuread"
