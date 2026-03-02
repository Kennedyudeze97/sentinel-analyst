import json
import subprocess
import sys
from pathlib import Path


def run_cli(workdir: Path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.cli",
            "--history",
            "data/history.jsonl",
            "--today",
            "data/today.jsonl",
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
    )


def load_incidents(workdir: Path):
    incidents_dir = workdir / "incidents"
    files = sorted(incidents_dir.glob("*.json"))
    assert files, "No incident files generated"
    return [json.loads(f.read_text()) for f in files]


def test_incident_hash_is_deterministic(tmp_path):
    # Copy project into isolated temp workspace
    root = Path(__file__).resolve().parents[1]
    workspace = tmp_path / "ws"
    workspace.mkdir()

    # Minimal copy (sentinel + data only)
    import shutil
    shutil.copytree(root / "sentinel", workspace / "sentinel")
    shutil.copytree(root / "data", workspace / "data")

    # Run #1
    r1 = run_cli(workspace)
    assert r1.returncode == 0, r1.stderr
    i1 = load_incidents(workspace)

    # Clean incidents folder
    shutil.rmtree(workspace / "incidents")

    # Run #2
    r2 = run_cli(workspace)
    assert r2.returncode == 0, r2.stderr
    i2 = load_incidents(workspace)

    # Compare incident_hash by user
    by_user_1 = {i["user"]: i["incident_hash"] for i in i1}
    by_user_2 = {i["user"]: i["incident_hash"] for i in i2}

    assert by_user_1 == by_user_2
