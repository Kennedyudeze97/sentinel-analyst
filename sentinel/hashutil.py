import json
import hashlib
from copy import deepcopy

# Fields that are allowed to vary run-to-run (runtime metadata)
# and therefore must NOT contribute to integrity hashing.
NON_HASH_FIELDS = {
    "incident_hash",
    "created_at",
    "generated_at",
    "incident_id",
}

def _normalize(obj):
    """
    Recursively normalize objects to a deterministic form:
      - Dict keys are sorted
      - Known non-hash fields are removed
      - Lists are normalized and then sorted by canonical JSON (best-effort)
    """
    if isinstance(obj, dict):
        clean = {}
        for k in sorted(obj.keys()):
            if k in NON_HASH_FIELDS:
                continue
            clean[k] = _normalize(obj[k])
        return clean

    if isinstance(obj, list):
        normed = [_normalize(x) for x in obj]
        # Sort lists deterministically when possible
        try:
            return sorted(
                normed,
                key=lambda x: json.dumps(
                    x, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ),
            )
        except TypeError:
            # If elements are not directly comparable/serializable, keep order as-is
            return normed

    return obj


def canonical_hash(payload: dict) -> str:
    """
    Canonical SHA-256 hash of the semantic content of payload.
    This intentionally excludes runtime metadata like timestamps and IDs.
    """
    clean = _normalize(deepcopy(payload))
    s = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
