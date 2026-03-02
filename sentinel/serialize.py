from __future__ import annotations

from datetime import date, datetime
from typing import Any

try:
    # Pydantic v2
    from pydantic import BaseModel  # type: ignore
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore


def to_json_safe(obj: Any) -> Any:
    """
    Convert nested objects into JSON-safe Python types:
    - Pydantic models -> dict
    - datetime/date -> ISO string
    - dict/list/tuple/set -> recursively normalized
    - everything else -> unchanged (must already be JSON-safe)
    """
    if obj is None:
        return None

    # datetime / date
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    # Pydantic model
    if isinstance(obj, BaseModel):
        # model_dump makes nested BaseModels into dicts too
        return to_json_safe(obj.model_dump(mode="python"))

    # dict
    if isinstance(obj, dict):
        return {str(k): to_json_safe(v) for k, v in obj.items()}

    # list/tuple/set
    if isinstance(obj, (list, tuple, set)):
        return [to_json_safe(v) for v in obj]

    # fallback (must be JSON-safe already: str/int/float/bool)
    return obj
