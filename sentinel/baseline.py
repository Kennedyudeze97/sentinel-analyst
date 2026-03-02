from __future__ import annotations

import json
from collections import Counter
from typing import Dict, Any

from sentinel.schemas import SecurityEvent

Baseline = Dict[str, Any]


def build_baseline(events: list[SecurityEvent]) -> Baseline:
    """
    Per-user baseline (MVP):
    - countries seen on login_success
    - devices seen on login_success
    - typical login hours (top 6 hours by frequency)
    """
    users = sorted(set(e.user for e in events))
    baseline: Baseline = {"users": {}}

    for user in users:
        u_events = [e for e in events if e.user == user]
        login_success = [e for e in u_events if e.event_type == "login_success"]

        country_counts = Counter([e.country for e in login_success if e.country])
        devices = sorted({e.device_id for e in login_success if e.device_id})

        hour_counts = Counter([e.ts.hour for e in login_success])
        typical_hours = [h for h, _ in hour_counts.most_common(6)]

        baseline["users"][user] = {
            "countries": [c for c, _ in country_counts.most_common()],
            "devices": devices,
            "typical_login_hours": typical_hours,
        }

    return baseline


def save_baseline(path: str, baseline: Baseline) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)


def load_baseline(path: str) -> Baseline:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_user_baseline(baseline: Baseline, user: str) -> dict:
    return baseline.get("users", {}).get(
        user, {"countries": [], "devices": [], "typical_login_hours": []}
    )
