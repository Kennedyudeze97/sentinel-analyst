from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

from dateutil.parser import isoparse

from sentinel.schemas import SecurityEvent


DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
DEFAULT_MAX_LINE_BYTES = 64_000


@dataclass
class IngestSummary:
    source: str
    strict: bool
    max_file_size: int
    max_line_bytes: int
    lines_read: int = 0
    valid_events: int = 0
    skipped_events: int = 0
    skip_reasons: Dict[str, int] = field(default_factory=dict)

    def bump(self, reason: str) -> None:
        self.skipped_events += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1


@dataclass
class IngestResult:
    events: List[SecurityEvent]
    summary: IngestSummary


def ingest_jsonl(
    path: str,
    strict: bool = True,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
) -> IngestResult:
    if os.path.getsize(path) > max_file_size:
        raise ValueError(f"File too large: {path} (max {max_file_size} bytes)")

    summary = IngestSummary(
        source=path,
        strict=strict,
        max_file_size=max_file_size,
        max_line_bytes=max_line_bytes,
    )

    events: List[SecurityEvent] = []

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            summary.lines_read += 1

            # Line-size guardrail (DoS safety)
            if len(line.encode("utf-8")) > max_line_bytes:
                if strict:
                    raise ValueError(f"Oversized line at {path}:{lineno} (max {max_line_bytes} bytes)")
                summary.bump("oversized_line")
                continue

            line = line.strip()
            if not line:
                # ignore empty lines (not counted as skipped event)
                continue

            try:
                obj = json.loads(line)
            except Exception as e:
                if strict:
                    raise ValueError(f"Invalid JSON at line {lineno}: {e}")
                summary.bump("invalid_json")
                continue

            # normalize timestamp
            if "ts" in obj and isinstance(obj["ts"], str):
                try:
                    obj["ts"] = isoparse(obj["ts"])
                except Exception as e:
                    if strict:
                        raise ValueError(f"Invalid timestamp at line {lineno}: {e}")
                    summary.bump("invalid_ts")
                    continue

            try:
                ev = SecurityEvent(**obj)
                events.append(ev)
                summary.valid_events += 1
            except Exception as e:
                if strict:
                    raise ValueError(f"Schema validation failed at line {lineno}: {e}")
                summary.bump("validation_error")
                continue

    return IngestResult(events=events, summary=summary)


# Backward compatible API (returns only events)
def read_jsonl(path: str, strict: bool = True) -> list[SecurityEvent]:
    return ingest_jsonl(path, strict=strict).events
