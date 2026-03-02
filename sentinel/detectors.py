from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from sentinel.schemas import SecurityEvent, Finding


def _get_user_baseline_from_events(evs: list[SecurityEvent]) -> dict | None:
    for e in evs:
        if isinstance(e.meta, dict) and "baseline" in e.meta:
            b = e.meta.get("baseline")
            if isinstance(b, dict):
                return b
    return None


def detect(events: list[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_user = defaultdict(list)
    for e in events:
        by_user[e.user].append(e)

    # R001: Brute-force style failures
    for user, evs in by_user.items():
        evs_sorted = sorted(evs, key=lambda x: x.ts)
        failed = [e for e in evs_sorted if e.event_type == "login_failed"]
        if len(failed) >= 5:
            window = failed[-1].ts - failed[0].ts
            if window <= timedelta(minutes=15):
                findings.append(Finding(
                    rule_id="R001",
                    severity="high",
                    title="Brute-force style login failures",
                    evidence={"user": user, "count": len(failed), "window_minutes": int(window.total_seconds()/60)},
                    rationale="Many failed logins in a short time can indicate credential stuffing or password guessing.",
                ))

    # R002: Privilege change shortly after anomalous/foreign login
    for user, evs in by_user.items():
        logins = [e for e in evs if e.event_type == "login_success"]
        privs = [e for e in evs if e.event_type == "privilege_change"]
        if logins and privs:
            newest_login = max(logins, key=lambda x: x.ts)
            newest_priv = max(privs, key=lambda x: x.ts)
            dt = newest_priv.ts - newest_login.ts
            if dt <= timedelta(minutes=10):
                base = _get_user_baseline_from_events(evs)
                known_countries = set((base or {}).get("countries", []) or [])

                if base and newest_login.country and known_countries and newest_login.country not in known_countries:
                    findings.append(Finding(
                        rule_id="R002",
                        severity="critical",
                        title="Privilege change after anomalous login (baseline)",
                        evidence={
                            "user": user,
                            "login_country": newest_login.country,
                            "known_countries": sorted(list(known_countries)),
                            "minutes_after_login": int(dt.total_seconds()/60),
                        },
                        rationale="Privilege escalation soon after an anomalous login is a strong takeover signal.",
                    ))
                elif newest_login.country and newest_login.country != "US":
                    findings.append(Finding(
                        rule_id="R002",
                        severity="critical",
                        title="Privilege change after foreign login",
                        evidence={
                            "user": user,
                            "login_country": newest_login.country,
                            "minutes_after_login": int(dt.total_seconds()/60),
                        },
                        rationale="Privilege escalation soon after an unusual login location is a strong takeover signal.",
                    ))

    # R003: Sensitive resource spike (optional)
    for user, evs in by_user.items():
        data = [
            e for e in evs
            if e.event_type == "data_access" and (e.resource or "").lower().find("sensitive") >= 0
        ]
        if len(data) >= 10:
            findings.append(Finding(
                rule_id="R003",
                severity="medium",
                title="High-volume access to sensitive resources",
                evidence={"user": user, "sensitive_access_count": len(data)},
                rationale="Unusual access to sensitive resources can indicate exfiltration or misuse.",
            ))

    # Baseline-aware rules
    for user, evs in by_user.items():
        base = _get_user_baseline_from_events(evs)
        if not base:
            continue

        known_countries = set(base.get("countries", []) or [])
        known_devices = set(base.get("devices", []) or [])
        typical_hours = set(base.get("typical_login_hours", []) or [])

        # R004: New country
        if known_countries:
            for e in evs:
                if e.event_type == "login_success" and e.country and e.country not in known_countries:
                    findings.append(Finding(
                        rule_id="R004",
                        severity="high",
                        title="Login from new country (baseline deviation)",
                        evidence={"user": user, "country": e.country, "known_countries": sorted(list(known_countries))},
                        rationale="User logged in from a country not previously seen for this account.",
                    ))
                    break

        # R005: New device
        if known_devices:
            for e in evs:
                if e.event_type == "login_success" and e.device_id and e.device_id not in known_devices:
                    findings.append(Finding(
                        rule_id="R005",
                        severity="medium",
                        title="Login from new device (baseline deviation)",
                        evidence={"user": user, "device_id": e.device_id, "known_devices": sorted(list(known_devices))},
                        rationale="User logged in from a device not previously seen for this account.",
                    ))
                    break

        # R006: Outside typical hours
        if typical_hours:
            for e in evs:
                if e.event_type == "login_success" and e.ts.hour not in typical_hours:
                    findings.append(Finding(
                        rule_id="R006",
                        severity="low",
                        title="Login outside typical hours (baseline deviation)",
                        evidence={"user": user, "login_hour": e.ts.hour, "typical_hours": sorted(list(typical_hours))},
                        rationale="Login time is outside the user's typical login hour pattern.",
                    ))
                    break

    return findings


def score(findings: list[Finding]) -> tuple[int, str]:
    weights = {"low": 10, "medium": 25, "high": 45, "critical": 70}
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    s = 0
    top = "low"
    for f in findings:
        s += weights[f.severity]
        if rank[f.severity] > rank[top]:
            top = f.severity

    s = min(100, s)

    # If any CRITICAL exists, elevate classification
    if top == "critical":
        level = "critical" if s >= 85 else "high"
    else:
        if s >= 85:
            level = "critical"
        elif s >= 60:
            level = "high"
        elif s >= 30:
            level = "medium"
        else:
            level = "low"

    return s, level
