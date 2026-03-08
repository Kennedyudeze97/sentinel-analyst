from __future__ import annotations

from fastapi.testclient import TestClient

from sentinel.api import app
from sentinel.metrics import reset_metrics


client = TestClient(app)


def test_metrics_endpoint_exposes_expected_keys():
    reset_metrics()

    # trigger one analyze request
    payload = {
        "strict": True,
        "events": [
            {
                "ts": "2026-03-01T10:00:00Z",
                "event_type": "login",
                "user": "alice",
                "src_ip": "10.0.0.1",
                "success": True,
            }
        ],
    }

    r = client.post("/analyze", json=payload)
    assert r.status_code == 200, r.text

    m = client.get("/metrics")
    assert m.status_code == 200, m.text
    data = m.json()

    assert "events_processed" in data
    assert "detections_generated" in data
    assert "high_severity_incidents" in data
    assert "ingest_failures" in data
    assert "azuread_events" in data

    assert data["events_processed"] >= 1
