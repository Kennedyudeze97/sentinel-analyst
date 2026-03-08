from __future__ import annotations

from typing import Dict


# In-memory metrics store (simple, deterministic, process-local)
_METRICS: Dict[str, int] = {
    "events_processed": 0,
    "detections_generated": 0,
    "high_severity_incidents": 0,
    "ingest_failures": 0,
    "azuread_events": 0,
}


def reset_metrics() -> None:
    for k in _METRICS:
        _METRICS[k] = 0


def incr(name: str, amount: int = 1) -> None:
    if name not in _METRICS:
        _METRICS[name] = 0
    _METRICS[name] += amount


def snapshot() -> Dict[str, int]:
    return dict(_METRICS)
