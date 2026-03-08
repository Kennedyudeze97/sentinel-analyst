from __future__ import annotations

from sentinel.config import (
    get_correlation_window_hours,
    get_response_playbooks,
    get_risk_thresholds,
    reset_policy_cache,
)


def test_policy_file_loads_expected_thresholds_and_playbooks():
    reset_policy_cache()

    thresholds = get_risk_thresholds()
    playbooks = get_response_playbooks()
    window = get_correlation_window_hours()

    assert thresholds["high"] == 80
    assert thresholds["medium"] == 60
    assert window == 1

    assert playbooks["high"]["actions"] == ["disable_user", "escalate_ticket"]
    assert playbooks["medium"]["actions"] == ["escalate_ticket"]
    assert playbooks["low"]["actions"] == ["monitor"]
