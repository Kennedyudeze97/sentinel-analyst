import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from datetime import datetime


# Fields that MUST NOT influence incident_hash because they change each run.
_NON_HASH_FIELDS = {
    "incident_hash",
    "created_at",
    "generated_at",
    "incident_id",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()



def _normalize(obj: Any) -> Any:
    """
    Recursively normalize objects into JSON-serializable,
    deterministic structures.
    """
    # datetime
    if isinstance(obj, datetime):
        return obj.isoformat()

    # Pydantic model support
    try:
        from pydantic import BaseModel
        if isinstance(obj, BaseModel):
            return _normalize(obj.model_dump(mode="python"))
    except Exception:
        pass

    # custom object with __dict__
    if hasattr(obj, "__dict__"):
        return _normalize(vars(obj))

    # dict
    if isinstance(obj, dict):
        clean = {}
        for k in sorted(obj.keys()):
            if k in _NON_HASH_FIELDS:
                continue
            clean[k] = _normalize(obj[k])
        return clean

    # list / tuple / set
    if isinstance(obj, (list, tuple, set)):
        normalized = [_normalize(x) for x in obj]
        try:
            return sorted(
                normalized,
                key=lambda x: json.dumps(
                    x, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ),
            )
        except TypeError:
            return normalized

    return obj


def canonical_json(obj: Any) -> bytes:
    normalized = _normalize(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_file(path: str) -> str:
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _compute_input_hash(input_sources: Iterable[str]) -> str:
    items = []
    for src in sorted(input_sources):
        items.append({"path": src, "sha256": hash_file(src)})
    return sha256_bytes(canonical_json(items))


def _compute_incident_hash(incident: Dict[str, Any]) -> str:
    temp = deepcopy(incident)
    return sha256_bytes(canonical_json(temp))


def add_integrity_metadata(
    incident: Dict[str, Any],
    *,
    input_sources: Optional[List[str]] = None,
    input_hash: Optional[str] = None,
    engine_version: Optional[str] = None,
    **_kwargs: Any,
) -> Dict[str, Any]:

    if input_sources is not None:
        incident["input_sources"] = list(input_sources)

    if engine_version is not None:
        incident["engine_version"] = engine_version

    if input_hash is not None:
        incident["input_hash"] = input_hash
    else:
        sources = incident.get("input_sources") or []
        if sources:
            incident["input_hash"] = _compute_input_hash(sources)

    incident["incident_hash"] = _compute_incident_hash(incident)
    return incident
