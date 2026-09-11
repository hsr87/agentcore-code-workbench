"""Extended workflow features: host builds, skills, profile proposal, PR evidence, multiple devices."""
import httpx

from cwe.android import FakeAndroidDevice
from cwe.android_setup import propose_profile, scan_gradle
from cwe.github import attach_evidence, build_comment
from cwe.skills import SkillStore, parse_skill


def test_android_setup_reads_sample_gradle():
    scan = scan_gradle("examples/android-sample")
    assert scan["compile_sdk"] == 34 and scan["application_id"] == "com.example.cwesample"
    profile, why = propose_profile("examples/android-sample", "examples/profiles/android")
    assert profile.package == "com.example.cwesample" and profile.test_package == "com.example.cwesample.test"
    assert profile.framework == "native" and "30-google-x64" in profile.image   # public images only go up to 30 -> nearest level at or below
    assert why["framework"] == "native"


def test_skill_store_roundtrip(manager):
    store = SkillStore(manager.store, "_skills")
    store.save("run-tests", "how to run tests", "1. pytest -q\n2. check output", status="draft", session_id="s", run_id="r")
    assert store.list() == [{"name": "run-tests", "description": "how to run tests", "status": "draft"}]
    assert store.list(approved_only=True) == []
    assert store.approve("run-tests") and store.load("run-tests")["status"] == "approved"
    assert parse_skill(store.store.get("_skills", "run-tests/SKILL.md").decode())["body"].startswith("1. pytest")


def test_agent_sees_only_approved_skills(manager):
    from cwe.agent import build_agent
    from cwe.config import Settings

    sess = manager.create()
    sess.skills.save("deploy", "d", "body", status="draft")
    sess.skills.save("build", "b", "body", status="approved")
    agent = build_agent(sess, Settings(region="us-east-1"))
    assert "build" in str(agent.system_prompt) and "deploy" not in str(agent.system_prompt)
    assert {"list_skills", "load_skill"} <= set(agent.tool_names)


def test_android_build_and_install_with_fake_device(manager, monkeypatch):
    from cwe import session as sm

    sess = manager.create()
    sess.begin_run("attach"); sess.attach_android(FakeAndroidDevice()); sess.end_run()
    sess.begin_run("build")
    monkeypatch.setattr(sm, "take_snapshot", lambda *a, **k: type("S", (), {"snapshot_id": "snap_x"})())
    monkeypatch.setattr("cwe.github.presign", lambda *a, **k: "https://example/snap_x.tar.gz")
    res = sess.android_build("app-src")
    assert res["ok"] and len(res["apks"]) == 2
    installed = sess.android_install_built()
    assert all(r["ok"] for r in installed) and sess.info.runs[-1].metadata["android_build"]["ok"]
    assert sess.device.for_device(1).device_index == 1 and sess.device.devices() == ["fake:5555"]


def test_pr_comment_body_and_post(manager):
    sess = manager.create()
    run = sess.begin_run("evidence", metadata={"task": "t"})
    sess.run_command("echo hi"); sess.end_run()
    calls = {}

    def handler(request: httpx.Request):
        calls["url"] = str(request.url); calls["auth"] = request.headers["authorization"]; calls["body"] = request.read()
        return httpx.Response(201, json={"html_url": "https://github.com/o/r/pull/1#issuecomment-1"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    out = attach_evidence(sess, run.run_id, "o/r", 1, "tok", "us-east-1", eval_summary="score=0.9 PASS", client=client)
    assert out["url"].endswith("issuecomment-1") and calls["url"].endswith("/repos/o/r/issues/1/comments") and calls["auth"] == "Bearer tok"
    assert "Executions" in build_comment(run, [], None) and "score=0.9" in out["body"]
    assert any(e["payload"].get("action") == "pr_comment" for e in sess.recorder.events(run.run_id))
