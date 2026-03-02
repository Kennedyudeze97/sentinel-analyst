import subprocess
import sys
from pathlib import Path


def run_cli(workdir: Path, history: str, today: str, strict: bool = False):
    cmd = [
        sys.executable,
        "-m",
        "sentinel.cli",
        "--history",
        history,
        "--today",
        today,
    ]
    if strict:
        cmd.append("--strict")

    return subprocess.run(
        cmd,
        cwd=workdir,
        capture_output=True,
        text=True,
    )


def test_strict_mode_fails_closed_on_bad_json(tmp_path):
    # Copy minimal project into isolated temp workspace
    root = Path(__file__).resolve().parents[1]
    workspace = tmp_path / "ws"
    workspace.mkdir()

    import shutil
    shutil.copytree(root / "sentinel", workspace / "sentinel")
    shutil.copytree(root / "data", workspace / "data")

    # Create a bad JSONL file (malformed JSON)
    bad = workspace / "data" / "bad.jsonl"
    bad.write_text('{"ts": "2026-03-01T00:00:00Z", "user": "alice"\n')  # missing closing }

    # Run CLI with --strict against malformed input
    r = run_cli(workspace, "data/bad.jsonl", "data/today.jsonl", strict=True)

    # Must fail closed with exit code 3
    assert r.returncode == 3, f"expected exit=3, got {r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}"

    # Must not produce incidents
    incidents_dir = workspace / "incidents"
    assert not incidents_dir.exists() or not any(incidents_dir.glob("*.json"))
