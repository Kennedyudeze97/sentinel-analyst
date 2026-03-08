from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict


DEFAULT_POLICY_PATH = Path("config/policy.json")


@lru_cache(maxsize=1)
def load_policy(path: str = str(DEFAULT_POLICY_PATH)) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def get_risk_thresholds() -> Dict[str, int]:
    policy = load_policy()
    return policy.get("risk_thresholds", {"high": 80, "medium": 60})


def get_response_playbooks() -> Dict[str, Dict[str, Any]]:
    policy = load_policy()
    return policy.get("response_playbooks", {})


def get_correlation_window_hours() -> int:
    policy = load_policy()
    correlation = policy.get("correlation", {})
    return int(correlation.get("window_hours", 1))


def reset_policy_cache() -> None:
    load_policy.cache_clear()
