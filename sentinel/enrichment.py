from __future__ import annotations

from typing import Any, Dict, List


# Deterministic mock GeoIP map
GEOIP_MAP = {
    "10.0.0.1": "US",
    "10.0.0.99": "US",
    "185.12.44.2": "RU",
    "203.0.113.5": "GB",
}


def mock_geoip(ip: str | None) -> str | None:
    if not ip:
        return None
    return GEOIP_MAP.get(ip, "UNKNOWN")


def count_failed_logins(events: List[Dict[str, Any]], user: str) -> int:
    count = 0
    for e in events:
        if e.get("user") == user and e.get("event_type") == "login" and e.get("success") is False:
            count += 1
    return count


def historical_risk_context(events: List[Dict[str, Any]], user: str) -> str:
    failed = count_failed_logins(events, user)
    if failed >= 5:
        return "high"
    if failed >= 2:
        return "medium"
    return "low"


def enrich_event(event: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    user = event.get("user")
    ip = event.get("src_ip")

    enriched = dict(event)
    meta = dict(enriched.get("meta") or {})

    meta["geoip_country"] = mock_geoip(ip)
    meta["failed_login_history"] = count_failed_logins(history, user) if user else 0
    meta["historical_risk"] = historical_risk_context(history, user) if user else "low"

    enriched["meta"] = meta
    return enriched
