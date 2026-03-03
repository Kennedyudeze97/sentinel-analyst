from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from dateutil.parser import isoparse

from sentinel.analyst import analyze
from sentinel.integrity import add_integrity_metadata, canonical_json, sha256_bytes
from sentinel.schemas import SecurityEvent
from sentinel.serialize import to_json_safe

APP_VERSION = os.environ.get("SENTINEL_VERSION", "1.0.0")

app = FastAPI(title="Sentinel API", version=APP_VERSION)


class AnalyzeRequest(BaseModel):
    # Provide ONE:
    events: Optional[List[Dict[str, Any]]] = None   # JSON array
    jsonl: Optional[str] = None                     # JSONL string

    strict: bool = True


def _parse_events(req: AnalyzeRequest) -> List[SecurityEvent]:
    if req.events is not None:
        raw = req.events
    elif req.jsonl is not None:
        raw = []
        for lineno, line in enumerate(req.jsonl.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw.append(json.loads(line))
            except Exception as e:
                if req.strict:
                    raise ValueError(f"Invalid JSONL at line {lineno}: {e}")
                continue
    else:
        raise ValueError("Provide either 'events' (JSON array) or 'jsonl' (JSONL string).")

    events: List[SecurityEvent] = []
    for idx, obj in enumerate(raw, start=1):
        # normalize ts like ingest does
        if "ts" in obj and isinstance(obj["ts"], str):
            try:
                obj["ts"] = isoparse(obj["ts"])
            except Exception as e:
                if req.strict:
                    raise ValueError(f"Invalid ts at event {idx}: {e}")
                obj.pop("ts", None)

        try:
            events.append(SecurityEvent(**obj))
        except Exception as e:
            if req.strict:
                raise ValueError(f"Schema validation failed at event {idx}: {e}")
            continue

    return events


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "version": APP_VERSION}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeRequest) -> Dict[str, Any]:
    try:
        events = _parse_events(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Deterministic input hash from normalized event dicts (no secrets logged)
    event_dicts = [e.model_dump(mode="python") for e in events]
    input_hash = sha256_bytes(canonical_json(to_json_safe(event_dicts)))

    incidents = analyze(events)

    payloads: List[Dict[str, Any]] = []
    for inc in incidents:
        # model -> dict
        if hasattr(inc, "model_dump"):
            d = inc.model_dump(mode="python")
        elif hasattr(inc, "__dict__"):
            d = inc.__dict__
        else:
            d = inc

        d = to_json_safe(d)

        d = add_integrity_metadata(
            d,
            input_sources=["api"],
            input_hash=input_hash,
            engine_version=APP_VERSION,
        )
        payloads.append(d)

    # Minimal response contract
    return {
        "incident_count": len(payloads),
        "incidents": payloads,
    }


def main() -> None:
    import uvicorn
    uvicorn.run(
        "sentinel.api:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        log_level="warning",  # avoid verbose logs
    )


if __name__ == "__main__":
    main()
