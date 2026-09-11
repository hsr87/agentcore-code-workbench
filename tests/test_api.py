from fastapi.testclient import TestClient

from cwe.api import create_app


def test_api_roundtrip(manager):
    client = TestClient(create_app(manager))
    assert client.get("/ping").json() == {"status": "Healthy"}
    sid = client.post("/v1/sessions", json={"tags": {"t": "1"}}).json()["session_id"]
    run = client.post(f"/v1/sessions/{sid}/runs", json={"title": "api"}).json()
    r = client.post(f"/v1/sessions/{sid}/exec", json={"type": "command", "input": "echo hi"}).json()
    assert r["exit_code"] == 0 and "hi" in r["stdout"]
    client.post(f"/v1/sessions/{sid}/files", json={"files": {"a.txt": "abc"}})
    assert client.get(f"/v1/sessions/{sid}/files/a.txt").text == "abc"
    assert client.post(f"/v1/sessions/{sid}/runs/{run['run_id']}/finish").json()["status"] == "succeeded"
    rep = client.post(f"/v1/sessions/{sid}/evaluate", json={
        "criteria": {"checks": [{"type": "stdout_contains", "value": "hi"}]}, "use_llm": False}).json()
    assert rep["passed"]
    assert len(client.get(f"/v1/sessions/{sid}/events").json()) > 3
    assert client.delete(f"/v1/sessions/{sid}").json()["closed"] == sid
