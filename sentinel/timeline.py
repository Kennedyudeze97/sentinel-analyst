from __future__ import annotations

from typing import Any, Dict, List


def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a deterministic incident timeline from event dictionaries.

    Output fields are intentionally compact and analyst-friendly.
    """
    timeline: List[Dict[str, Any]] = []

    for e in events:
        timeline.append(
            {
                "ts": e.get("ts"),
                "event_type": e.get("event_type"),
                "user": e.get("user"),
                "src_ip": e.get("src_ip"),
                "success": e.get("success"),
            }
        )

    timeline.sort(
        key=lambda x: (
            str(x.get("ts") or ""),
            str(x.get("event_type") or ""),
            str(x.get("src_ip") or ""),
        )
    )
    return timeline


def attach_timeline(incident: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    enriched = dict(incident)
    enriched["timeline"] = build_timeline(events)
    return enriched
