from __future__ import annotations

from typing import Any, Dict
from dateutil.parser import isoparse


def normalize_azuread_signin(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Azure AD sign-in log into Sentinel event schema.

    Azure AD fields mapped:
    - userPrincipalName -> user
    - ipAddress -> src_ip
    - createdDateTime -> ts
    - location.countryOrRegion -> meta.location
    - status.errorCode -> success
    """
    ts = event.get("createdDateTime")
    if isinstance(ts, str):
        ts = isoparse(ts)

    location = None
    loc = event.get("location")
    if isinstance(loc, dict):
        location = loc.get("countryOrRegion")

    status = event.get("status") or {}
    success = status.get("errorCode", 0) == 0

    return {
        "ts": ts,
        "event_type": "login",
        "user": event.get("userPrincipalName"),
        "src_ip": event.get("ipAddress"),
        "success": success,
        "meta": {
            "source": "azuread",
            "location": location,
            "authenticationDetails": event.get("authenticationDetails"),
        },
    }
