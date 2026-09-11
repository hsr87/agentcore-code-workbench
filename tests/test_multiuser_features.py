"""Multi-user hardening features: post-hoc grading (recording restore), tokens/cost, API key, snapshot guard, reaper tags."""
import pytest
from fastapi.testclient import TestClient

from cwe.agent import estimate_cost_usd
from cwe.api import create_app
from cwe.models import EvalCheck, EvalCriteria
from cwe.session import SessionManager


def test_post_hoc_evaluation_from_recorded_session(manager):
    sess = manager.create()
    run = sess.begin_run("record", metadata={"task": "echo"})
    sess.write_files({"app.py": "print(1)"})
    sess.run_command("echo hello")
    sess.end_run()
    sid, run_id = sess.info.session_id, run.run_id
    manager.close(sid)

    # a fresh manager (simulating a process restart) opens the session from the recording alone and grades it
    fresh = SessionManager(settings=manager.settings, sandbox_factory=lambda p: (_ for _ in ()).throw(AssertionError("no sandbox")))
    rec = fresh.open_recorded(sid)
    assert rec.sandbox.session_id is None
    rep = rec.evaluate(EvalCriteria(checks=[EvalCheck(type="stdout_contains", value="hello"), EvalCheck(type="file_exists", value="app.py")]), run_id=run_id, use_llm=False)
    assert rep.passed and len(rep.items) == 2


def test_run_has_trace_id_and_usage_fields(manager):
    sess = manager.create()
    run = sess.begin_run("t")
    assert len(run.trace_id) == 32 and run.usage == {} and run.cost_usd_estimate is None
    sess.end_run()
    assert any(e["payload"].get("action") == "end_run" and "usage" in e["payload"] for e in sess.recorder.events(run.run_id))


def test_cost_estimate():
    assert estimate_cost_usd("us.anthropic.claude-opus-5", {"inputTokens": 1_000_000, "outputTokens": 100_000}) == 7.5
    assert estimate_cost_usd("unknown-model", {"inputTokens": 10}) is None


def test_api_key_middleware(manager, monkeypatch):
    monkeypatch.setenv("CWE_API_KEY", "s3cret")
    client = TestClient(create_app(manager))
    assert client.get("/ping").status_code == 200
    assert client.get("/v1/sessions").status_code == 401
    assert client.get("/v1/sessions", headers={"x-api-key": "s3cret"}).status_code == 200


def test_recorded_evaluate_endpoint(manager):
    client = TestClient(create_app(manager))
    sid = client.post("/v1/sessions", json={}).json()["session_id"]
    client.post(f"/v1/sessions/{sid}/runs", json={"title": "r"})
    client.post(f"/v1/sessions/{sid}/exec", json={"type": "command", "input": "echo hi"})
    client.delete(f"/v1/sessions/{sid}")
    rep = client.post(f"/v1/recorded/{sid}/evaluate", json={"criteria": {"checks": [{"type": "stdout_contains", "value": "hi"}]}, "use_llm": False}).json()
    assert rep["passed"]


def test_snapshot_size_guard(monkeypatch):
    from cwe import snapshots
    from cwe.sandbox import FakeSandbox

    sb = FakeSandbox()
    sb.execute_command = lambda cmd: type("R", (), {"ok": True, "output": ""})()
    sb.read_files = lambda paths: {snapshots._ARCHIVE: b"x" * (snapshots.MAX_INLINE_BYTES + 1)}
    with pytest.raises(RuntimeError, match="100 MB"):
        snapshots.take_snapshot(sb, None, "s", "workspace")


def test_expires_at_tag_format():
    from cwe.android import _expires_at

    assert _expires_at(3600).endswith("+00:00")
