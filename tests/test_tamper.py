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


def run_verify(workdir: Path, incident_path: Path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel.verify",
            str(incident_path),
        ],
        cwd=workdir,
        capture_output=True,
        text=True,
    )


def test_verify_fails_on_tampered_incident(tmp_path):
    # Copy project into isolated temp workspace
    root = Path(__file__).resolve().parents[1]
    workspace = tmp_path / "ws"
    workspace.mkdir()

    import shutil
    shutil.copytree(root / "sentinel", workspace / "sentinel")
    shutil.copytree(root / "data", workspace / "data")

    # Generate incidents
    r = run_cli(workspace)
    assert r.returncode == 0, r.stderr

    incidents_dir = workspace / "incidents"
    files = sorted(incidents_dir.glob("*.json"))
    assert files, "No incident files generated"
    incident_file = files[0]

    # Verify should PASS before tampering
    v1 = run_verify(workspace, incident_file)
    assert v1.returncode == 0, v1.stderr

    # Tamper with incident: change risk_score
    data = json.loads(incident_file.read_text())
    # Make sure we actually change something
    data["risk_score"] = int(data.get("risk_score", 0)) + 1
    incident_file.write_text(json.dumps(data, indent=2, sort_keys=True))

    # Verify should FAIL after tampering
    v2 = run_verify(workspace, incident_file)
    assert v2.returncode != 0, "verify unexpectedly succeeded on tampered incident"
