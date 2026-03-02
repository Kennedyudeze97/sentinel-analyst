import json
import sys
from pathlib import Path

from sentinel.integrity import _compute_incident_hash


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m sentinel.verify <incident_json_path>")
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        return 2

    data = json.loads(path.read_text())

    stored_hash = data.get("incident_hash")
    if not stored_hash:
        print("No incident_hash found.")
        return 2

    # Recompute using EXACT same logic as generator
    recomputed = _compute_incident_hash(data)

    if stored_hash != recomputed:
        print("INTEGRITY CHECK FAILED")
        print(f"Stored:      {stored_hash}")
        print(f"Recalculated:{recomputed}")
        return 1

    print("INTEGRITY CHECK PASSED")
    print(f"incident_hash:{stored_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
