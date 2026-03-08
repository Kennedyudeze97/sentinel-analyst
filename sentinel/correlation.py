from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple


def _hour_bucket(ts: str | None) -> str:
    if not ts:
        return "unknown"
    return str(ts)[:13]  # e.g. 2026-03-01T10


def _rules_key(incident: Dict[str, Any]) -> Tuple[str, ...]:
    explanation = incident.get("explanation") or {}
    rules = explanation.get("rules_triggered") or []

    if not rules:
        findings = incident.get("findings") or []
        extracted = []
        for f in findings:
            if isinstance(f, dict):
                r = f.get("rule") or f.get("detector") or f.get("name")
                if r:
                    extracted.append(str(r))
        rules = extracted

    return tuple(sorted(set(str(r) for r in rules)))


def _incident_ts(incident: Dict[str, Any]) -> str | None:
    if incident.get("ts"):
        return str(incident["ts"])

    timeline = incident.get("timeline") or incident.get("events") or []
    for item in timeline:
        if isinstance(item, dict) and item.get("ts"):
            return str(item["ts"])

    return None


def _merge_group(group: List[Dict[str, Any]]) -> Dict[str, Any]:
    base = dict(group[0])

    merged_findings: List[Any] = []
    merged_evidence: List[Any] = []
    merged_rules = set()
    ts_values: List[str] = []

    max_risk = 0

    for inc in group:
        max_risk = max(max_risk, int(inc.get("risk_score", 0)))

        findings = inc.get("findings") or []
        merged_findings.extend(findings)

        explanation = inc.get("explanation") or {}
        for r in explanation.get("rules_triggered") or []:
            merged_rules.add(str(r))
        for e in explanation.get("evidence") or []:
            merged_evidence.append(e)

        ts = _incident_ts(inc)
        if ts:
            ts_values.append(ts)

    explanation = dict(base.get("explanation") or {})
    explanation["rules_triggered"] = sorted(merged_rules)
    explanation["evidence"] = merged_evidence

    base["findings"] = merged_findings
    base["explanation"] = explanation
    base["correlated_count"] = len(group)
    base["risk_score"] = max_risk
    base["correlation_window"] = {
        "first_seen": min(ts_values) if ts_values else None,
        "last_seen": max(ts_values) if ts_values else None,
    }

    return base


def correlate_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deterministically group incidents by:
      - user
      - triggered rules
      - hour bucket
    """
    grouped: Dict[Tuple[str, Tuple[str, ...], str], List[Dict[str, Any]]] = defaultdict(list)

    for inc in incidents:
        user = str(inc.get("user") or "unknown")
        rules = _rules_key(inc)
        bucket = _hour_bucket(_incident_ts(inc))
        grouped[(user, rules, bucket)].append(inc)

    merged: List[Dict[str, Any]] = []
    for key in sorted(grouped.keys(), key=lambda k: (k[0], k[1], k[2])):
        merged.append(_merge_group(grouped[key]))

    return merged
