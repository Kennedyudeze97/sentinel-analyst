from __future__ import annotations

from sentinel.adapters.azuread import normalize_azuread_signin


def test_azuread_adapter_maps_fields_correctly():
    event = {
        "createdDateTime": "2026-03-01T10:00:00Z",
        "userPrincipalName": "alice@example.com",
        "ipAddress": "10.0.0.1",
        "location": {"countryOrRegion": "US"},
        "status": {"errorCode": 0},
        "authenticationDetails": [{"authenticationMethod": "Password"}],
    }

    normalized = normalize_azuread_signin(event)

    assert normalized["event_type"] == "login"
    assert normalized["user"] == "alice@example.com"
    assert normalized["src_ip"] == "10.0.0.1"
    assert normalized["success"] is True
    assert normalized["meta"]["source"] == "azuread"
    assert normalized["meta"]["location"] == "US"
