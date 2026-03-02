import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from dataclasses import is_dataclass, asdict

from sentinel.ingest import read_jsonl
from sentinel.analyst import analyze
from sentinel.integrity import hash_file, add_integrity_metadata, canonical_json, sha256_bytes
from sentinel.redaction import redact
from sentinel.serialize import to_json_safe


def normalize(obj):
    # Recursively convert objects to JSON-safe structures
    if is_dataclass(obj):
        return normalize(asdict(obj))

    if isinstance(obj, dict):
        return {k: normalize(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [normalize(v) for v in obj]

    if hasattr(obj, "__dict__"):
        return normalize(vars(obj))

    return obj


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", required=True)
    parser.add_argument("--today", required=True)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--redact", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        history_events = read_jsonl(args.history, strict=args.strict)
        today_events = read_jsonl(args.today, strict=args.strict)
    except Exception as e:
        print(f"[INGEST ERROR] {e}", file=sys.stderr)
        sys.exit(3)

    input_sources = [args.history, args.today]

    file_hashes = [
        hash_file(args.history),
        hash_file(args.today),
    ]

    combined_input_hash = sha256_bytes(
        canonical_json(sorted(file_hashes))
    )

    events = history_events + today_events
    incidents = analyze(events)

    if not incidents:
        print("No incidents detected.")
        sys.exit(0)

    ts = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    output_dir = Path("incidents")
    output_dir.mkdir(exist_ok=True)

    for idx, incident in enumerate(incidents):
        raw_dict = normalize(incident)

        raw_user = raw_dict.get("user")
        secrets = [raw_user] if raw_user else []

        redacted_incident = redact(
            raw_dict,
            args.redact,
            secrets=secrets,
        )

        final_incident = add_integrity_metadata(
            redacted_incident,
            input_sources=input_sources,
            input_hash=combined_input_hash,
        )

        output_path = output_dir / f"incident_{ts}_{idx}.json"

        with open(output_path, "w") as f:
            json.dump(to_json_safe(final_incident), f, indent=2, sort_keys=True)

        print(f"Wrote incident to {output_path}")


if __name__ == "__main__":
    main()
