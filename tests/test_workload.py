"""Workload Pod backend: the in-Pod agent, the client, the Job manifest and reattach."""
import importlib.util
import json
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from cwe.workload import EKSWorkloadHost, WorkloadClient, WorkloadProfile

ROOT = Path(__file__).resolve().parents[1]


def _load_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKLOAD_AGENT_TOKEN", "t0k3n")
    monkeypatch.setenv("WORKLOAD_AGENT_SESSION", "sess_123456789abc")
    monkeypatch.setenv("WORKLOAD_WORK", str(tmp_path / "work"))
    spec = importlib.util.spec_from_file_location("workload_agent_under_test", ROOT / "src" / "cwe" / "workload_agent.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop("workload_agent_under_test", None)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def agent(tmp_path, monkeypatch):
    module = _load_agent(tmp_path, monkeypatch)
    server = module.serve("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    yield module, f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_agent_requires_token_and_session(agent):
    module, base = agent
    import httpx

    assert httpx.get(f"{base}/healthz").status_code == 200                       # readiness probe, no auth
    assert httpx.get(f"{base}/health").status_code == 401
    assert httpx.get(f"{base}/health", headers={"authorization": "Bearer wrong"}).status_code == 401
    r = httpx.get(f"{base}/health", headers={"authorization": "Bearer t0k3n", "x-cwe-session": "sess_000000000000"})
    assert r.status_code == 403
    ok = WorkloadClient(base, "t0k3n", "sess_123456789abc").health()
    assert ok["ok"] and ok["work"].endswith("work")


def test_agent_exec_files_procs_and_probe(agent):
    module, base = agent
    c = WorkloadClient(base, "t0k3n", "sess_123456789abc")
    c.write_files({"app/hello.txt": "hi\n", "app/run.sh": "#!/bin/sh\necho started; exec python3 -m http.server $PORT --bind 127.0.0.1\n"})
    r = c.exec("cat app/hello.txt && pwd", timeout=30, cwd=".")
    assert r["exit_code"] == 0 and "hi" in r["output"] and r["output"].strip().endswith("work")
    assert c.read_file("app/hello.txt") == b"hi\n"
    assert c.read_file("app/missing.txt") is None
    bad = c.exec("exit 3", timeout=30)
    assert bad["exit_code"] == 3
    slow = c.exec("sleep 5", timeout=1)
    assert slow["exit_code"] == 124 and slow["timed_out"]
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    c.start("svc", f"PORT={port} sh app/run.sh", cwd=".")
    with pytest.raises(RuntimeError, match="409"):
        c.start("svc", "sleep 1")
    deadline = 50
    while deadline:
        res = c.probe(port, "/app/hello.txt")
        if res.get("status") == 200:
            break
        deadline -= 1
        import time
        time.sleep(0.1)
    assert res["status"] == 200 and "hi" in res["body"]
    logs = c.logs("svc")
    assert logs["running"] and "started" in logs["log"]
    assert any(p["name"] == "svc" and p["running"] for p in c.procs())
    stopped = c.stop("svc")
    assert stopped["name"] == "svc"
    assert not c.logs("svc")["running"]
    # Probe of a closed port is reported, not raised.
    assert c.probe(port, "/")["status"] == 0


def test_agent_confines_paths_and_downloads(agent):
    module, base = agent
    c = WorkloadClient(base, "t0k3n", "sess_123456789abc")
    for path in ("../etc/passwd", "/etc/passwd", "a/../../b"):
        with pytest.raises(RuntimeError, match="400"):
            c.write_files({path: "x"})
    with pytest.raises(RuntimeError, match="400"):
        c.exec("pwd", cwd="../")
    with pytest.raises(RuntimeError, match="400"):
        c.fetch("http://example.com/src.tar.gz")           # https only
    with pytest.raises(RuntimeError, match="400"):
        c.fetch("https://127.0.0.1/src.tar.gz")            # loopback rejected
    with pytest.raises(module.Bad):
        module.under_work("../x")


def test_agent_rejects_escaping_archives(tmp_path, monkeypatch):
    import io
    import tarfile

    module = _load_agent(tmp_path, monkeypatch)
    dest = tmp_path / "work" / "src"
    dest.mkdir(parents=True)
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        data = b"pwned"
        info = tarfile.TarInfo("../../escape.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    with pytest.raises(module.Bad, match="escapes"):
        module._safe_extract(str(archive), str(dest))
    good = tmp_path / "good.tar.gz"
    with tarfile.open(good, "w:gz") as t:
        info = tarfile.TarInfo("ok/file.txt")
        info.size = 2
        t.addfile(info, io.BytesIO(b"ok"))
    assert module._safe_extract(str(good), str(dest)) == 1
    assert (dest / "ok" / "file.txt").read_text() == "ok"


class Cluster:
    def __init__(self):
        self.created = []
        self.deleted = []
        self.pods = {}

    def __call__(self, cmd, **kwargs):
        args = cmd[5:]
        if args[:1] == ["create"]:
            body = json.loads(kwargs["input"])
            self.created.append(body)
            return SimpleNamespace(returncode=0, stdout=json.dumps({"metadata": {"uid": "uid-" + body["metadata"]["name"]}}))
        if args[:2] == ["delete", "job"]:
            self.deleted.append(args[2])
            return SimpleNamespace(returncode=0, stdout="deleted\n")
        if args[:2] == ["get", "pods"]:
            job = args[3].split("=", 1)[1]
            return SimpleNamespace(returncode=0, stdout=json.dumps({"items": self.pods.get(job, [])}))
        raise AssertionError(cmd)


def test_workload_profile_validation():
    with pytest.raises(ValueError, match="quantity"):
        WorkloadProfile(memory="lots")
    with pytest.raises(ValueError, match="env name"):
        WorkloadProfile(env={"WORKLOAD_AGENT_TOKEN": "x"})
    with pytest.raises(ValueError):
        WorkloadProfile(arch="s390x")
    p = WorkloadProfile(image="repo/build:v1", memory="24Gi", ephemeral_storage="100Gi", cpu="6", env={"GRADLE_OPTS": "-Xmx4g"})
    assert p.job_timeout_seconds == 8 * 3600


def test_workload_manifest_and_start(monkeypatch):
    cluster = Cluster()
    h = EKSWorkloadHost(context="test", access="pod", runner=cluster)
    with pytest.raises(ValueError, match="image"):
        h.start(WorkloadProfile(image=""), "sess_123456789abc")
    profile = WorkloadProfile(image="repo/build:v1", memory="24Gi", ephemeral_storage="100Gi", cpu="6", cpu_limit="8", env={"GRADLE_OPTS": "-Xmx4g"})
    monkeypatch.setattr(h, "_wait_pod", lambda name, timeout: {"metadata": {"name": name + "-x"}, "status": {"podIP": "10.0.0.9"}})
    monkeypatch.setattr(WorkloadClient, "wait_ready", lambda self, timeout=600: {"ok": True})
    client = h.start(profile, "sess_123456789abc")
    assert client.base_url == "http://10.0.0.9:8080"
    job = next(v for v in cluster.created if v["kind"] == "Job")
    secret = next(v for v in cluster.created if v["kind"] == "Secret")
    assert secret["metadata"]["ownerReferences"][0]["uid"] == "uid-" + job["metadata"]["name"]
    assert job["metadata"]["labels"]["app.kubernetes.io/name"] == "cwe-workload"
    pod = job["spec"]["template"]["spec"]
    c = pod["containers"][0]
    assert c["image"] == "repo/build:v1"
    assert c["resources"]["requests"] == {"cpu": "6", "memory": "24Gi", "ephemeral-storage": "100Gi"}
    assert c["resources"]["limits"]["cpu"] == "8" and c["resources"]["limits"]["memory"] == "24Gi"
    assert pod["nodeSelector"] == {"cwe/workload": "build", "kubernetes.io/arch": "amd64"}
    assert pod["tolerations"][0]["key"] == "cwe/build"
    assert not pod["automountServiceAccountToken"] and "hostPath" not in json.dumps(pod) and "docker.sock" not in json.dumps(pod)
    assert c["securityContext"]["runAsNonRoot"] and c["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    env = {e["name"]: e for e in c["env"]}
    assert env["GRADLE_OPTS"]["value"] == "-Xmx4g"
    assert env["WORKLOAD_AGENT_TOKEN"]["valueFrom"]["secretKeyRef"]["name"] == job["metadata"]["name"]
    assert secret["stringData"]["token"] not in json.dumps(job)
    assert client.token == secret["stringData"]["token"]
    assert client._c.headers["x-cwe-session"] == "sess_123456789abc"
    desc = h.describe()
    assert desc["kind"] == "workload" and desc["job"] == job["metadata"]["name"] and desc["token"] == client.token
    assert desc["profile"]["memory"] == "24Gi"
    with pytest.raises(RuntimeError, match="already started"):
        h.start(profile, "sess_123456789abc")
    h.stop()
    assert cluster.deleted == [job["metadata"]["name"]] and not h.jobs and h.client is None


def test_workload_start_failure_cleans_up(monkeypatch):
    cluster = Cluster()
    h = EKSWorkloadHost(context="test", access="pod", runner=cluster)

    def fail(*a):
        raise TimeoutError("no node")
    monkeypatch.setattr(h, "_wait_pod", fail)
    with pytest.raises(TimeoutError):
        h.start(WorkloadProfile(image="repo/build:v1"), "sess_123456789abc")
    assert len(cluster.deleted) == 1 and not h.jobs


def test_workload_attach_and_detach(monkeypatch):
    cluster = Cluster()
    cluster.pods["cwe-job-1"] = [{"metadata": {"name": "cwe-job-1-abc"}, "status": {"phase": "Running", "podIP": "10.0.0.5"}}]
    monkeypatch.setattr(WorkloadClient, "wait_ready", lambda self, timeout=600: {"ok": True})
    h = EKSWorkloadHost(context="test", access="pod", runner=cluster)
    record = {"kind": "workload", "session_id": "sess_123456789abc", "job": "cwe-job-1", "token": "tok",
              "profile": WorkloadProfile(image="repo/build:v1", memory="24Gi").model_dump()}
    client = h.attach(record)
    assert client.base_url == "http://10.0.0.5:8080" and client.token == "tok" and h.jobs == ["cwe-job-1"]
    assert h.profile.memory == "24Gi" and h.describe()["token"] == "tok"
    h.detach()                                   # keep the Job for the next process
    assert cluster.deleted == [] and h.jobs == [] and h.client is None
    gone = EKSWorkloadHost(context="test", access="pod", runner=cluster)
    with pytest.raises(RuntimeError, match="no longer running"):
        gone.attach({**record, "job": "cwe-job-2"})
    with pytest.raises(ValueError, match="token"):
        gone.attach({"kind": "workload", "session_id": "sess_123456789abc", "job": "cwe-job-1"})
    with pytest.raises(ValueError, match="session"):
        gone.attach({**record, "session_id": "../x"})


def test_kubeconfig_flag_precedes_context():
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"items": []}))
    h = EKSWorkloadHost(context="arn:aws:eks:us-east-1:1:cluster/c", access="pod", runner=runner, kubeconfig="/home/app/.kube/cwe-c.yaml")
    assert h.reap() == []
    assert calls[0][:5] == ["kubectl", "--kubeconfig", "/home/app/.kube/cwe-c.yaml", "--context", "arn:aws:eks:us-east-1:1:cluster/c"]


def test_session_workload_methods_record_remote_events(manager):
    from cwe.models import ExecKind

    class FakeClient:
        base_url = "http://10.0.0.1:8080"
        token = "tok"

        def __init__(self):
            self.procs_ = []

        def health(self):
            return {"ok": True, "cpus": 8, "mem_total_bytes": 64 << 30, "disk_total_bytes": 200 << 30}

        def exec(self, cmd, timeout=600, cwd=".", max_output=20000):
            return {"exit_code": 0 if "ok" in cmd else 1, "output": f"ran {cmd}", "seconds": 0.5, "timed_out": False}

        def start(self, name, cmd, cwd="."):
            self.procs_.append(name)
            return {"name": name, "pid": 1}

        def stop(self, name):
            return {"name": name, "exit_code": 0}

        def logs(self, name, tail=4000):
            return {"name": name, "running": True, "exit_code": None, "log": "listening"}

        def probe(self, port, path="/", method="GET", body=None, headers=None, timeout=30):
            return {"status": 200, "headers": {}, "body": "pong", "seconds": 0.01}

        def write_files(self, files):
            return {"written": list(files)}

        def read_file(self, path, max_bytes=200000):
            return b"content" if path == "a.txt" else None

        def close(self):
            pass

    class FakeHost:
        def __init__(self):
            self.stopped = False

        def start(self, profile, sid):
            self.profile = profile
            return FakeClient()

        def stop(self):
            self.stopped = True

        def describe(self):
            return {"kind": "workload", "session_id": "sess_x", "job": "j", "token": "tok", "profile": self.profile.model_dump()}

    sess = manager.create()
    host = FakeHost()
    client = sess.start_workload(WorkloadProfile(image="repo/build:v1", memory="32Gi"), host=host)
    assert sess.workload is client and host.profile.memory == "32Gi"
    with pytest.raises(RuntimeError, match="already started"):
        sess.start_workload(WorkloadProfile(image="x"), host=host)
    sess.begin_run("build")
    ok = sess.workload_exec("./gradlew ok")
    bad = sess.workload_exec("./gradlew fail")
    assert ok.kind == ExecKind.REMOTE and ok.ok and not bad.ok and bad.exit_code == 1
    sess.workload_start("svc", "java -jar app.jar")
    assert sess.workload_logs("svc")["running"]
    assert sess.workload_probe(8081, "/health")["status"] == 200
    sess.workload_write_files({"a.txt": "content"})
    assert sess.workload_read_file("a.txt") == b"content"
    sess.workload_stop("svc")
    run = sess.end_run()
    kinds = [e["payload"].get("kind") for e in sess.recorder.events(run.run_id) if e["event_type"] == "exec"]
    assert kinds.count("remote") == 7 and run.error_count == 1
    record = sess.registry_record("rt-1")
    assert record["hosts"][0]["kind"] == "workload" and record["hosts"][0]["token"] == "tok"
    from cwe.models import SnapshotInfo
    import cwe.session as session_module
    monkeypatch_snapshot = lambda sandbox, store, sid, path, description="": SnapshotInfo(session_id=sid, uri="local", size_bytes=1)  # noqa: E731
    original = session_module.take_snapshot
    session_module.take_snapshot = monkeypatch_snapshot
    try:
        with pytest.raises(RuntimeError, match="S3"):   # a local store has no presigned URL a Pod could fetch
            sess.sync_workspace_to_workload()
    finally:
        session_module.take_snapshot = original
    manager.close(sess.info.session_id)
    assert host.stopped


def test_agent_tools_include_remote_when_workload_attached(manager):
    pytest.importorskip("claude_agent_sdk")
    from cwe.agent import cwe_tools, system_prompt_for

    sess = manager.create()
    assert not any(t.name.startswith("remote_") for t in cwe_tools(sess))
    sess.workload = SimpleNamespace(health=lambda: {})
    names = {t.name for t in cwe_tools(sess)}
    assert {"remote_shell", "remote_start", "remote_probe", "remote_sync_workspace", "remote_status"} <= names
    assert "workload Pod on EKS" in system_prompt_for(sess)
    manager.close(sess.info.session_id)


def test_api_workload_endpoints(manager, monkeypatch):
    from fastapi.testclient import TestClient

    from cwe.api import create_app

    class FakeClient:
        base_url = "http://10.0.0.1:8080"
        token = "tok"

        def health(self):
            return {"ok": True, "cpus": 4}

        def exec(self, cmd, timeout=600, cwd=".", max_output=20000):
            return {"exit_code": 0, "output": f"ran {cmd}", "seconds": 0.1, "timed_out": False}

        def probe(self, port, path="/", method="GET", body=None, headers=None, timeout=30):
            return {"status": 204, "headers": {}, "body": "", "seconds": 0.01}

        def close(self):
            pass

    class FakeHost:
        @classmethod
        def from_env(cls, settings):
            return cls()

        def start(self, profile, sid):
            self.profile = profile
            return FakeClient()

        def stop(self):
            pass

        def describe(self):
            return {"kind": "workload", "session_id": "s", "job": "cwe-job", "token": "tok", "profile": self.profile.model_dump()}

    monkeypatch.setattr("cwe.workload.EKSWorkloadHost", FakeHost)
    client = TestClient(create_app(manager))
    sid = client.post("/v1/sessions", json={}).json()["session_id"]
    assert client.post(f"/v1/sessions/{sid}/remote", json={"type": "exec", "input": "ls"}).status_code == 409
    wl = client.post(f"/v1/sessions/{sid}/workload", json={"profile": {"image": "repo/build:v1", "memory": "24Gi"}}).json()
    assert wl["workload"]["job"] == "cwe-job" and "token" not in wl["workload"] and wl["health"]["cpus"] == 4
    r = client.post(f"/v1/sessions/{sid}/remote", json={"type": "exec", "input": "./gradlew build", "timeout": 1200}).json()
    assert r["kind"] == "remote" and r["exit_code"] == 0 and "gradlew" in r["stdout"]
    assert client.post(f"/v1/sessions/{sid}/remote", json={"type": "probe"}).status_code == 422
    assert client.post(f"/v1/sessions/{sid}/remote", json={"type": "probe", "port": 8081, "path": "/health"}).json()["status"] == 204
    assert client.post(f"/v1/sessions/{sid}/remote", json={"type": "exec", "input": "x", "timeout": 99999}).status_code == 422
    assert client.delete(f"/v1/sessions/{sid}").json()["closed"] == sid


def test_inject_agent_mounts_the_packaged_agent_from_the_secret(monkeypatch):
    from cwe.workload import agent_source

    cluster = Cluster()
    h = EKSWorkloadHost(context="test", access="pod", runner=cluster)
    monkeypatch.setattr(h, "_wait_pod", lambda name, timeout: {"metadata": {"name": name}, "status": {"podIP": "10.0.0.2"}})
    monkeypatch.setattr(WorkloadClient, "wait_ready", lambda self, timeout=600: {"ok": True})
    h.start(WorkloadProfile(image="public.ecr.aws/docker/library/python:3.12-slim", inject_agent=True), "sess_123456789abc")
    job = next(v for v in cluster.created if v["kind"] == "Job")
    secret = next(v for v in cluster.created if v["kind"] == "Secret")
    c = job["spec"]["template"]["spec"]["containers"][0]
    assert c["command"] == ["python3", "/opt/cwe/agent/workload_agent.py"]
    assert any(m["mountPath"] == "/opt/cwe/agent" and m["readOnly"] for m in c["volumeMounts"])
    vol = next(v for v in job["spec"]["template"]["spec"]["volumes"] if v["name"] == "agent")
    assert vol["secret"]["secretName"] == job["metadata"]["name"] and vol["secret"]["items"][0]["key"] == "agent.py"
    assert secret["stringData"]["agent.py"] == agent_source() and "def dispatch" in secret["stringData"]["agent.py"]
    h.stop()


def test_start_workload_is_serialized_and_refused_after_close(manager):
    import threading
    import time

    starts = []

    class SlowHost:
        def start(self, profile, sid):
            starts.append(sid)
            time.sleep(0.3)
            return SimpleNamespace(health=lambda: {"ok": True}, close=lambda: None, base_url="u", token="t")

        def stop(self):
            pass

        def describe(self):
            return {"kind": "workload", "session_id": "s", "job": "j", "token": "t", "profile": None}

    sess = manager.create()
    host = SlowHost()
    results = []

    def go():
        try:
            results.append(sess.start_workload(WorkloadProfile(image="x"), host=host))
        except RuntimeError as e:
            results.append(str(e))
    threads = [threading.Thread(target=go) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(starts) == 1                                        # one Pod, three concurrent (retried) requests
    assert sum(1 for r in results if isinstance(r, str) and "already started" in r) == 2
    manager.close(sess.info.session_id)
    with pytest.raises(RuntimeError, match="closed"):
        sess.start_workload(WorkloadProfile(image="x"), host=host)


def test_agent_exec_request_id_joins_the_running_command_instead_of_rerunning(agent, tmp_path):
    import concurrent.futures

    module, base = agent
    c = WorkloadClient(base, "t0k3n", "sess_123456789abc")
    marker = tmp_path / "work" / "runs.txt"
    cmd = "echo run >> runs.txt; sleep 1; echo done"
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(c.exec, cmd, 30, ".", 20_000, "req-0000000001") for _ in range(2)]
        results = [f.result() for f in futures]
    assert marker.read_text().count("run") == 1                      # the command ran once
    assert sorted(r.get("deduplicated", False) for r in results) == [False, True]
    assert all(r["exit_code"] == 0 and "done" in r["output"] for r in results)
    again = c.exec(cmd, 30, ".", 20_000, "req-0000000001")            # a late retry gets the stored result
    assert again["deduplicated"] and marker.read_text().count("run") == 1
    with pytest.raises(RuntimeError, match="409"):
        c.exec("echo other", 30, ".", 20_000, "req-0000000001")       # same id, different command
    with pytest.raises(RuntimeError, match="400"):
        c.exec("echo x", 30, ".", 20_000, "short")
    assert "deduplicated" not in c.exec("echo plain", 30)             # a fresh id runs normally


def test_client_retries_exec_once_on_a_dropped_connection(agent, tmp_path):
    import httpx

    module, base = agent
    c = WorkloadClient(base, "t0k3n", "sess_123456789abc")
    real_post = c._c.post
    dropped = {"n": 0}

    def flaky_post(path, **kwargs):
        if path == "/exec" and dropped["n"] == 0:
            dropped["n"] += 1
            raise httpx.ConnectError("connection dropped")
        return real_post(path, **kwargs)

    c._c.post = flaky_post
    r = c.exec("echo retry >> retry.txt; echo ok", timeout=30)
    assert r["exit_code"] == 0 and dropped["n"] == 1
    assert (tmp_path / "work" / "retry.txt").read_text().count("retry") == 1


def test_workload_manifest_mounts_the_image_read_only():
    host = EKSWorkloadHost(runner=lambda *a, **k: None, context="ctx")
    job = host.manifest(WorkloadProfile(image="repo/build:v1"), "sess_123456789abc", "cwe-job")
    c = job["spec"]["template"]["spec"]["containers"][0]
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert {m["mountPath"] for m in c["volumeMounts"]} >= {"/opt/cwe/work", "/opt/cwe/cache", "/opt/cwe/logs", "/tmp"}
    tmp = next(v for v in job["spec"]["template"]["spec"]["volumes"] if v["name"] == "tmp")
    assert tmp["emptyDir"]["sizeLimit"] == "4Gi"
    relaxed = host.manifest(WorkloadProfile(image="repo/build:v1", read_only_root=False, tmp_size="16Gi"), "sess_123456789abc", "cwe-job")
    rc = relaxed["spec"]["template"]["spec"]["containers"][0]
    assert rc["securityContext"]["readOnlyRootFilesystem"] is False
    assert next(v for v in relaxed["spec"]["template"]["spec"]["volumes"] if v["name"] == "tmp")["emptyDir"]["sizeLimit"] == "16Gi"
    with pytest.raises(ValueError):
        WorkloadProfile(image="x", tmp_size="lots")
