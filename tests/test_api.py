from __future__ import annotations

from fastapi.testclient import TestClient
from sentinel.api import app

client = TestClient(app)


def test_api_returns_200_and_is_deterministic():
    payload = {
        "strict": True,
        "events": [
            {
                "ts": "2026-03-01T10:00:00Z",
                "event_type": "login",
                "user": "alice",
                "src_ip": "10.0.0.1",
                "success": True,
            },
            {
                "ts": "2026-03-01T10:05:00Z",
                "event_type": "login",
                "user": "alice",
                "src_ip": "10.0.0.99",
                "success": False,
            },
        ],
    }

    r1 = client.post("/analyze", json=payload)
    assert r1.status_code == 200, r1.text
    out1 = r1.json()

    r2 = client.post("/analyze", json=payload)
    assert r2.status_code == 200, r2.text
    out2 = r2.json()

    hashes1 = [i["incident_hash"] for i in out1["incidents"]]
    hashes2 = [i["incident_hash"] for i in out2["incidents"]]
    assert hashes1 == hashes2
