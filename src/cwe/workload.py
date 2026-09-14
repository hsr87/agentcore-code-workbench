"""Heavy workloads on EKS: build and run what does not fit in a Code Interpreter microVM.

The agent keeps orchestrating from AgentCore (Runtime or a laptop); a `WorkloadProfile` says how
much CPU, memory and disk the job needs and which toolchain image to use. One Job per session
runs that image with the workload agent (device_agent/workload_agent.py) on port 8080, and the
`WorkloadClient` here is the only thing the session talks to.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import secrets
import time
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator

from cwe.eks import LABEL, RESTRICTED, WORKLOAD_APP, EKSJobHost, resolve_context

log = logging.getLogger(__name__)
_QUANTITY_RE = re.compile(r"^[0-9]+(\.[0-9]+)?(m|k|M|G|T|Ki|Mi|Gi|Ti)?$")
_LABEL_VALUE_RE = re.compile(r"^[a-z0-9A-Z]([-a-z0-9A-Z_.]{0,61}[a-z0-9A-Z])?$")


class WorkloadProfile(BaseModel):
    """What the Pod looks like. Requests equal limits for memory so the scheduler places the whole build."""

    name: str = "build"
    image: str = Field(default_factory=lambda: os.environ.get("CWE_WORKLOAD_IMAGE") or "",
                       description="Toolchain image built from device_agent/Dockerfile.workload (or any image carrying the workload agent)")
    cpu: str = "4"
    cpu_limit: str | None = None
    memory: str = "16Gi"
    ephemeral_storage: str = Field(default="50Gi", description="Size of the workspace emptyDir; also requested as ephemeral-storage")
    env: dict[str, str] = Field(default_factory=dict, description="Non-secret environment for the toolchain (JAVA_TOOL_OPTIONS, GRADLE_OPTS, ...)")
    boot_timeout: int = Field(default=600, ge=30, le=3600)
    job_timeout_seconds: int = Field(default=8 * 3600, ge=60, le=14 * 24 * 3600)
    node_selector: dict[str, str] = Field(default_factory=lambda: {"cwe/workload": "build"})
    toleration_key: str | None = "cwe/build"
    arch: str = Field(default="amd64", pattern=r"^(amd64|arm64)$")
    inject_agent: bool = Field(default=False, description="Mount cwe/workload_agent.py from the Job's Secret and run it, so any image with python3 works without a rebuild")
    read_only_root: bool = Field(default=True, description="Mount the image read-only; the workspace, cache, logs and /tmp are emptyDirs. Disable for toolchains that write elsewhere")
    tmp_size: str = Field(default="4Gi", description="Size of the /tmp emptyDir (java.io.tmpdir, HOME for the build user)")

    @field_validator("cpu", "cpu_limit", "memory", "ephemeral_storage", "tmp_size")
    @classmethod
    def _quantity(cls, v):
        if v is not None and not _QUANTITY_RE.match(v):
            raise ValueError(f"not a Kubernetes quantity: {v!r}")
        return v

    @field_validator("env")
    @classmethod
    def _env_names(cls, v):
        for k in v:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or k.startswith("WORKLOAD_AGENT_"):
                raise ValueError(f"invalid env name {k!r}")
        return v

    @field_validator("node_selector")
    @classmethod
    def _selector(cls, v):
        for k, val in v.items():
            if not _LABEL_VALUE_RE.match(val):
                raise ValueError(f"invalid node selector value for {k}")
        return v


def agent_source() -> str:
    """The in-Pod agent, shipped inside this package so it can be mounted into any image."""
    from importlib import resources

    return resources.files("cwe").joinpath("workload_agent.py").read_text(encoding="utf-8")


class WorkloadClient:
    """HTTP client for one workload agent."""

    def __init__(self, base_url: str, token: str, session_id: str, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.session_id = session_id
        self._c = httpx.Client(base_url=self.base_url, timeout=timeout,
                               headers={"authorization": f"Bearer {token}", "x-cwe-session": session_id})

    def _post(self, path: str, body: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        r = self._c.post(path, json=body, timeout=timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"workload agent {path} failed ({r.status_code}): {r.text[:800]}")
        return r.json()

    def _get(self, route: str, **params) -> dict[str, Any]:
        r = self._c.get(route, params=params)
        if r.status_code >= 400:
            raise RuntimeError(f"workload agent {route} failed ({r.status_code}): {r.text[:800]}")
        return r.json()

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def wait_ready(self, timeout: int = 600) -> dict[str, Any]:
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            try:
                return self.health()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    raise RuntimeError(f"workload agent rejected the request ({e.response.status_code})") from e
                last = str(e)
            except (httpx.HTTPError, RuntimeError) as e:
                if "401" in str(e) or "403" in str(e):
                    raise
                last = str(e)
            time.sleep(3)
        raise TimeoutError(f"workload agent not ready within {timeout}s (last: {last[:200]})")

    def exec(self, cmd: str, timeout: int = 600, cwd: str = ".", max_output: int = 20_000, request_id: str | None = None) -> dict[str, Any]:
        """Run one command. A dropped connection is retried once with the same request_id, which the agent
        turns into a join on the running command rather than a second run of the build."""
        body = {"cmd": cmd, "timeout": timeout, "cwd": cwd, "max_output": max_output, "request_id": request_id or secrets.token_urlsafe(16)}
        try:
            return self._post("/exec", body, timeout=timeout + 30)
        except httpx.TransportError as e:
            log.warning("workload exec transport error (%s); retrying with the same request_id", type(e).__name__)
            return self._post("/exec", body, timeout=timeout + 30)

    def start(self, name: str, cmd: str, cwd: str = ".") -> dict[str, Any]:
        return self._post("/start", {"name": name, "cmd": cmd, "cwd": cwd})

    def stop(self, name: str) -> dict[str, Any]:
        return self._post("/stop", {"name": name})

    def logs(self, name: str, tail: int = 4000) -> dict[str, Any]:
        return self._get("/logs", name=name, tail=tail)

    def procs(self) -> list[dict[str, Any]]:
        return self._get("/procs")["procs"]

    def write_files(self, files: dict[str, str | bytes]) -> dict[str, Any]:
        enc = {p: base64.b64encode(d if isinstance(d, bytes) else d.encode("utf-8")).decode() for p, d in files.items()}
        return self._post("/files", {"files": enc})

    def read_file(self, path: str, max_bytes: int = 200_000) -> bytes | None:
        try:
            r = self._get("/file", path=path, max_bytes=max_bytes)
        except RuntimeError as e:
            if "(404)" in str(e):
                return None
            raise
        return base64.b64decode(r["content_b64"])

    def fetch(self, url: str, dest: str = ".", extract: bool = True, clean: bool = False, timeout: float = 1800) -> dict[str, Any]:
        return self._post("/fetch", {"url": url, "dest": dest, "extract": extract, "clean": clean}, timeout=timeout)

    def probe(self, port: int, path: str = "/", method: str = "GET", body: str | None = None,
              headers: dict[str, str] | None = None, timeout: float = 30) -> dict[str, Any]:
        return self._post("/probe", {"port": port, "path": path, "method": method, "body": body, "headers": headers or {}, "timeout": timeout},
                          timeout=timeout + 15)

    def close(self) -> None:
        self._c.close()


class EKSWorkloadHost(EKSJobHost):
    """One workload Pod per session."""

    app = WORKLOAD_APP

    def __init__(self, namespace: str = "cwe", context: str | None = None, access: str = "port-forward",
                 project: str = "cwe", runner=None, kubeconfig: str | None = None):
        super().__init__(namespace=namespace, context=context, access=access, project=project, runner=runner, kubeconfig=kubeconfig)
        self.client: WorkloadClient | None = None
        self.profile: WorkloadProfile | None = None
        self._token: str | None = None
        self._session_id: str | None = None
        self.pod_ip: str | None = None

    @classmethod
    def from_env(cls, settings=None, **kwargs):
        from cwe.config import get_settings

        st = settings or get_settings()
        context, kubeconfig = resolve_context(st)
        return cls(namespace=st.eks_namespace, context=context, access=st.eks_access, project=st.project_name,
                   kubeconfig=kubeconfig, **kwargs)

    def manifest(self, profile: WorkloadProfile, session_id: str, name: str) -> dict:
        labels = {LABEL: WORKLOAD_APP, "cwe/project": self.project, "cwe/session": session_id}
        env = [{"name": k, "value": v} for k, v in sorted(profile.env.items())]
        env += [
            {"name": "WORKLOAD_AGENT_TOKEN", "valueFrom": {"secretKeyRef": {"name": name, "key": "token"}}},
            {"name": "WORKLOAD_AGENT_SESSION", "value": session_id},
            {"name": "WORKLOAD_WORK", "value": "/opt/cwe/work"},
        ]
        container: dict[str, Any] = {
            "name": "workload", "image": profile.image, "env": env,
            "ports": [{"name": "http", "containerPort": 8080}],
            "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "periodSeconds": 3},
            "resources": {
                "requests": {"cpu": profile.cpu, "memory": profile.memory, "ephemeral-storage": profile.ephemeral_storage},
                "limits": {"cpu": profile.cpu_limit or profile.cpu, "memory": profile.memory, "ephemeral-storage": profile.ephemeral_storage},
            },
            "securityContext": {**RESTRICTED, "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": True,
                                "readOnlyRootFilesystem": profile.read_only_root},
            "volumeMounts": [{"name": "work", "mountPath": "/opt/cwe/work"}, {"name": "cache", "mountPath": "/opt/cwe/cache"},
                             {"name": "logs", "mountPath": "/opt/cwe/logs"}, {"name": "tmp", "mountPath": "/tmp"}],
        }
        volumes: list[dict[str, Any]] = [{"name": "work", "emptyDir": {"sizeLimit": profile.ephemeral_storage}},
                                         {"name": "cache", "emptyDir": {}}, {"name": "logs", "emptyDir": {"sizeLimit": "1Gi"}},
                                         {"name": "tmp", "emptyDir": {"sizeLimit": profile.tmp_size}}]
        if profile.inject_agent:
            container["command"] = ["python3", "/opt/cwe/agent/workload_agent.py"]
            container["volumeMounts"].append({"name": "agent", "mountPath": "/opt/cwe/agent", "readOnly": True})
            volumes.append({"name": "agent", "secret": {"secretName": name, "items": [{"key": "agent.py", "path": "workload_agent.py"}]}})
        spec: dict[str, Any] = {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "serviceAccountName": "cwe-device",
            "nodeSelector": {**profile.node_selector, "kubernetes.io/arch": profile.arch},
            "securityContext": {"fsGroup": 1000},
            "terminationGracePeriodSeconds": 30,
            "containers": [container],
            "volumes": volumes,
        }
        if profile.toleration_key:
            spec["tolerations"] = [{"key": profile.toleration_key, "operator": "Equal", "value": "true", "effect": "NoSchedule"}]
        return {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "labels": labels, "annotations": {"cwe/profile": profile.name}},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": profile.job_timeout_seconds, "ttlSecondsAfterFinished": 300,
                     "template": {"metadata": {"labels": labels}, "spec": spec}},
        }

    def start(self, profile: WorkloadProfile, session_id: str) -> WorkloadClient:
        if self.jobs:
            raise RuntimeError("host already started")
        self.check_session_id(session_id)
        if not profile.image:
            raise ValueError("WorkloadProfile.image (or CWE_WORKLOAD_IMAGE) is required")
        self.profile, self._session_id = profile, session_id
        name = self.job_name(session_id)
        token = secrets.token_urlsafe(32)
        secret = {"token": token}
        if profile.inject_agent:
            secret["agent.py"] = agent_source()
        try:
            self._create_job_with_secret(self.manifest(profile, session_id, name), secret)
            pod = self._wait_pod(name, profile.boot_timeout)
            self.pod_ip = pod["status"].get("podIP")
            self._token = token
            self.client = WorkloadClient(self._base_url(pod), token=token, session_id=session_id)
            self.client.wait_ready(profile.boot_timeout)
            return self.client
        except Exception:
            self.stop()
            raise

    def describe(self) -> dict[str, Any]:
        return {"kind": "workload", "session_id": self._session_id, "job": self.jobs[0] if self.jobs else None,
                "token": self._token, "pod_ip": self.pod_ip, "profile": self.profile.model_dump() if self.profile else None}

    def attach(self, record: dict[str, Any], timeout: int = 60) -> WorkloadClient:
        if self.jobs:
            raise RuntimeError("host already started")
        session_id = self.check_session_id(record.get("session_id", ""))
        job, token = record.get("job"), record.get("token")
        if not job or not token:
            raise ValueError("record must carry job and token")
        pod = self._pod_of(job)
        if pod is None:
            raise RuntimeError(f"workload Job {job} is no longer running")
        self.jobs.append(job)
        self._session_id, self._token = session_id, token
        self.pod_ip = pod["status"].get("podIP")
        self.profile = WorkloadProfile.model_validate(record["profile"]) if record.get("profile") else None
        self.client = WorkloadClient(self._base_url(pod), token=token, session_id=session_id)
        self.client.wait_ready(timeout)
        return self.client

    def _close_clients(self) -> None:
        if self.client:
            self.client.close()
        self.client = None
        self._token = None
