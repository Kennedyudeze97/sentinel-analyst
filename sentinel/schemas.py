from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Literal, List

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    ts: datetime
    event_type: str
    user: str
    source_ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    device_id: Optional[str] = None
    resource: Optional[str] = None
    outcome: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    evidence: Dict[str, Any]
    rationale: str
    mitre: Dict[str, Any] = Field(default_factory=dict)  # tactic/technique mapping


Verdict = Literal["benign", "suspicious", "likely_compromise", "confirmed_compromise"]


class Incident(BaseModel):
    incident_id: str
    created_at: datetime
    user: str

    risk_score: int  # 0-100
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float  # 0.0-1.0
    verdict: Verdict

    summary: str
    narrative: str
    timeline: str = ""

    mitre_techniques: List[str] = Field(default_factory=list)

    findings: list[Finding]
    recommended_actions: list[str]
    raw_events: list[SecurityEvent]
