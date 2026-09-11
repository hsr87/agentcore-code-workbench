import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from cwe.android import AndroidDevice, AndroidEmulatorProfile, emulator_host
from cwe.config import Settings
from cwe.eks import EKSEmulatorHost


class Cluster:
    def __init__(self):
        self.created = []
        self.deleted = []
        self.fail_secret = False
        self.listed = []

    def __call__(self, cmd, **kwargs):
        args = cmd[5:]  # kubectl --context test --namespace cwe
        if args[:1] == ["create"]:
            body = json.loads(kwargs["input"])
            if body["kind"] == "Secret" and self.fail_secret:
                return SimpleNamespace(returncode=1, stdout="", stderr="sensitive body")
            self.created.append(body)
            return SimpleNamespace(returncode=0, stdout=json.dumps({"metadata": {"uid": "uid-" + body["metadata"]["name"]}}))
        if args[:2] == ["delete", "job"]:
            assert "-o" not in args, "kubectl delete does not support -o json"
            self.deleted.append(args[2])
            return SimpleNamespace(returncode=0, stdout=f'job.batch "{args[2]}" deleted\n')
        if args[:2] == ["get", "jobs"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps({"items": self.listed}))
        raise AssertionError(cmd)


def host(cluster):
    return EKSEmulatorHost("repo/agent:v1", "repo/builder:v1", context="test", access="pod", runner=cluster)


def test_eks_job_owns_secret_and_routes_multiple_devices(monkeypatch):
    cluster = Cluster()
    h = host(cluster)
    monkeypatch.setattr(h, "_wait_pod", lambda name, timeout: {"metadata": {"name": name}, "status": {"podIP": "10.0.0.1"}})
    monkeypatch.setattr(AndroidDevice, "wait_boot", lambda *a: {})
    group = h.start(AndroidEmulatorProfile(count=2, images=["api30", "api34"]), "sess_123456789abc")
    jobs = [v for v in cluster.created if v["kind"] == "Job"]
    secrets = [v for v in cluster.created if v["kind"] == "Secret"]
    assert len(jobs) == len(secrets) == len(group.devices()) == 2
    assert group.for_device(1) is h.devices[1]
    assert h.devices[0].token != h.devices[1].token
    assert group.for_device(1)._c.headers["x-cwe-session"] == "sess_123456789abc"
    with pytest.raises(ValueError):
        group.for_device(-1)
    for job, secret in zip(jobs, secrets):
        assert secret["metadata"]["ownerReferences"][0]["uid"] == "uid-" + job["metadata"]["name"]
        spec = job["spec"]
        assert spec["activeDeadlineSeconds"] == 14400 and spec["ttlSecondsAfterFinished"] == 300
        pod = spec["template"]["spec"]
        assert not pod["automountServiceAccountToken"]
        assert "hostPath" not in json.dumps(pod) and "docker.sock" not in json.dumps(pod)
        assert not any(c["securityContext"].get("privileged") for c in pod["containers"])
        assert pod["containers"][0]["resources"]["limits"]["devic.es/kvm"] == "1"
        assert not any(e.get("name") == "DEVICE_AGENT_TOKEN" for e in pod["containers"][2].get("env", []))
        assert secret["stringData"]["token"] not in json.dumps(job)
    h.stop()
    h.stop()  # idempotent
    assert len(cluster.deleted) == 2 and not h.jobs


def test_eks_rolls_back_if_secret_creation_fails():
    cluster = Cluster()
    cluster.fail_secret = True
    h = host(cluster)
    with pytest.raises(RuntimeError, match="kubectl create failed") as error:
        h.start(AndroidEmulatorProfile(), "sess_123456789abc")
    assert "sensitive" not in str(error.value)
    assert len(cluster.deleted) == 1 and not h.jobs


def test_eks_cleanup_failure_is_reported_and_can_be_retried():
    cluster = Cluster()
    h = host(cluster)
    h.jobs = ["owned-job"]
    h._runner = lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="forbidden")
    with pytest.raises(RuntimeError, match="could not delete"):
        h.stop()
    assert h.jobs == ["owned-job"]
    h._runner = cluster
    h.stop()
    assert not h.jobs


def test_eks_rolls_back_all_devices_after_boot_failure(monkeypatch):
    cluster = Cluster()
    h = host(cluster)
    def fail(*args):
        raise TimeoutError("no capacity")
    monkeypatch.setattr(h, "_wait_pod", fail)
    with pytest.raises(TimeoutError):
        h.start(AndroidEmulatorProfile(count=2), "sess_123456789abc")
    assert len(cluster.deleted) == 2


def test_eks_validation_happens_before_creation():
    cluster = Cluster()
    h = host(cluster)
    with pytest.raises(ValueError, match="exactly"):
        h.start(AndroidEmulatorProfile(count=2, images=["one"]), "sess_123456789abc")
    with pytest.raises(ValueError, match="session"):
        h.start(AndroidEmulatorProfile(), "../../bad")
    assert cluster.created == []
    with pytest.raises(ValueError, match="images"):
        EKSEmulatorHost("", "", context="test")


def test_eks_reap_only_expired_or_completed_jobs():
    now = datetime.now(timezone.utc)
    def job(name, age):
        return {"metadata": {"name": name, "creationTimestamp": (now - timedelta(seconds=age)).isoformat()},
                "spec": {"activeDeadlineSeconds": 100}, "status": {}}
    cluster = Cluster()
    cluster.listed = [job("old", 200), job("live", 20), job("finished", 10)]
    cluster.listed[-1]["status"] = {"conditions": [{"type": "Failed", "status": "True"}]}
    h = host(cluster)
    assert h.reap() == ["old", "finished"] and cluster.deleted == []
    assert h.reap(apply=True) == ["old", "finished"]
    assert cluster.deleted == ["old", "finished"]


def test_default_backend_and_profile_reach_session(manager, monkeypatch):
    st = Settings(android_device_agent_image="repo/agent:v1", eks_builder_image="repo/builder:v1", eks_context="test")
    assert isinstance(emulator_host(st), EKSEmulatorHost)
    with pytest.raises(ValueError, match="backend|BACKEND"):
        emulator_host(Settings(android_backend="bad"))
    from cwe.android import FakeAndroidDevice
    h = SimpleNamespace(start=lambda profile, sid: FakeAndroidDevice(), stop=lambda: None)
    monkeypatch.setattr("cwe.android.emulator_host", lambda settings: h)
    sess = manager.create()
    profile = AndroidEmulatorProfile(build_tasks="assembleRelease")
    sess.start_android(profile)
    assert sess._android_profile.build_tasks == "assembleRelease"
    manager.close(sess.info.session_id)
