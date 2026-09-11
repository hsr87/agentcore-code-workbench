"""EKS Android lab: one Job per device, no EC2 lifecycle calls or Docker socket.

kubectl uses the operator's kubeconfig (or an in-cluster service account). Jobs
enforce a lifetime even if the caller dies; owned Secrets disappear with Jobs.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import socket
import subprocess
import time

from cwe.android import AndroidDevice, AndroidEmulatorProfile

log = logging.getLogger(__name__)
LABEL = "app.kubernetes.io/name"
APP = "cwe-android"


class DeviceGroup(AndroidDevice):
    """Default operations use device zero; for_device selects a separate Pod."""

    def __init__(self, devices: list[AndroidDevice]):
        self.__dict__.update(devices[0].__dict__)
        self._devices = devices

    def for_device(self, index: int) -> AndroidDevice:
        if not 0 <= index < len(self._devices):
            raise ValueError("device index out of range")
        return self._devices[index]

    def devices(self) -> list[str]:
        return [d.base_url for d in self._devices]


class EKSEmulatorHost:
    def __init__(self, agent_image: str, builder_image: str, namespace: str = "cwe",
                 context: str | None = None, access: str = "port-forward", project: str = "cwe",
                 runner=None):
        if access not in ("port-forward", "pod"):
            raise ValueError("EKS access must be port-forward | pod")
        if not agent_image or not builder_image:
            raise ValueError("EKS requires device-agent and builder images")
        if not re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?", namespace):
            raise ValueError("invalid Kubernetes namespace")
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,20}", project):
            raise ValueError("invalid project")
        self.agent_image, self.builder_image = agent_image, builder_image
        self.namespace, self.access, self.project = namespace, access, project
        self._runner = runner or subprocess.run
        self.context = context
        # Freeze the local context so another terminal cannot switch our target.
        if not self.context and not os.environ.get("KUBERNETES_SERVICE_HOST"):
            self.context = self._runner(
                ["kubectl", "config", "current-context"], check=True, capture_output=True, text=True
            ).stdout.strip()
            if not self.context:
                raise RuntimeError("CWE_EKS_CONTEXT or an in-cluster service account is required")
        self.jobs: list[str] = []
        self.devices: list[AndroidDevice] = []
        self._forwarders: list[subprocess.Popen] = []

    @classmethod
    def from_env(cls, settings=None, **kwargs):
        from cwe.config import get_settings

        st = settings or get_settings()
        return cls(agent_image=st.android_device_agent_image, builder_image=st.eks_builder_image,
                   namespace=st.eks_namespace, context=st.eks_context, access=st.eks_access,
                   project=st.project_name, **kwargs)

    def _command(self, *args: str) -> list[str]:
        return ["kubectl", *(["--context", self.context] if self.context else []),
                "--namespace", self.namespace, *args]

    def _kubectl(self, *args: str, body: dict | None = None) -> dict:
        result = self._runner(self._command(*args), input=json.dumps(body) if body else None,
                              capture_output=True, text=True, timeout=60)
        if result.returncode:
            # Do not return stderr: kubectl may include a submitted Secret in it.
            raise RuntimeError(f"kubectl {args[0]} failed (exit {result.returncode}); check namespace RBAC and cluster connectivity")
        if args[0] == "delete" or "name" in args:
            return {}  # kubectl delete and -o name emit plain text, not JSON.
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def manifest(self, profile: AndroidEmulatorProfile, session_id: str, name: str, image: str) -> dict:
        labels = {LABEL: APP, "cwe/project": self.project, "cwe/session": session_id}
        restricted = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                      "seccompProfile": {"type": "RuntimeDefault"}}
        work = [{"name": "work", "mountPath": "/opt/cwe"}]
        return {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "labels": labels},
            "spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": profile.job_timeout_seconds,
                "ttlSecondsAfterFinished": 300,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "restartPolicy": "Never", "automountServiceAccountToken": False,
                        "serviceAccountName": "cwe-device",
                        "nodeSelector": {"cwe/workload": "android", "kubernetes.io/arch": "amd64"},
                        "tolerations": [{"key": "cwe/android", "operator": "Equal", "value": "true", "effect": "NoSchedule"}],
                        "securityContext": {"fsGroup": 1000},
                        "terminationGracePeriodSeconds": 20,
                        "containers": [
                            {
                                "name": "emulator", "image": image,
                                "env": [{"name": "EMULATOR_PARAMS", "value": profile.emulator_params}],
                                "resources": {
                                    "requests": {"cpu": "2", "memory": "4Gi", "devic.es/kvm": "1"},
                                    "limits": {"cpu": "3", "memory": "6Gi", "devic.es/kvm": "1"},
                                },
                                "securityContext": restricted,
                                "volumeMounts": [{"name": "shm", "mountPath": "/dev/shm"}],
                            },
                            {
                                "name": "device-agent", "image": self.agent_image,
                                "env": [
                                    {"name": "DEVICE_AGENT_TOKEN", "valueFrom": {"secretKeyRef": {"name": name, "key": "token"}}},
                                    {"name": "BUILD_SIDECAR_TOKEN", "valueFrom": {"secretKeyRef": {"name": name, "key": "builder-token"}}},
                                    {"name": "DEVICE_AGENT_SESSION", "value": session_id},
                                    {"name": "DEVICE_AGENT_HOST", "value": "0.0.0.0"},
                                    {"name": "ADB_SERIAL", "value": "127.0.0.1:5555"},
                                    {"name": "BUILD_BACKEND", "value": "sidecar"},
                                    {"name": "HOME", "value": "/tmp"},
                                ],
                                "ports": [{"name": "http", "containerPort": 8080}],
                                "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "periodSeconds": 3},
                                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "512Mi"}},
                                "securityContext": {**restricted, "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": True},
                                "volumeMounts": work,
                            },
                            {
                                "name": "builder", "image": self.builder_image,
                                # Only the build credential: no device token, no cluster credentials, no KVM.
                                "env": [{"name": "BUILD_SIDECAR_TOKEN", "valueFrom": {"secretKeyRef": {"name": name, "key": "builder-token"}}}],
                                "resources": {"requests": {"cpu": "2", "memory": "4Gi"}, "limits": {"cpu": "4", "memory": "16Gi"}},
                                "securityContext": {**restricted, "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": True},
                                "volumeMounts": work,
                            },
                        ],
                        "volumes": [
                            {"name": "work", "emptyDir": {"sizeLimit": "25Gi"}},
                            {"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "1Gi"}},
                        ],
                    },
                },
            },
        }

    def start(self, profile: AndroidEmulatorProfile, session_id: str) -> AndroidDevice:
        if self.jobs:
            raise RuntimeError("host already started")
        if not re.fullmatch(r"sess_[0-9a-f]{12}", session_id):
            raise ValueError("invalid session id")
        if profile.images and len(profile.images) != profile.count:
            raise ValueError("images must contain exactly count entries")
        if profile.job_timeout_seconds <= 0:
            raise ValueError("job_timeout_seconds must be positive")
        images = profile.images or [profile.image] * profile.count
        try:
            tokens = []
            for i, image in enumerate(images):
                name = f"cwe-{session_id.replace('_', '-')}-{secrets.token_hex(3)}-{i}"
                job = self._kubectl("create", "-f", "-", "-o", "json",
                                    body=self.manifest(profile, session_id, name, image))
                self.jobs.append(name)
                token = secrets.token_urlsafe(32)
                tokens.append(token)
                # -o name so the created Secret never comes back through stdout or an exception.
                self._kubectl("create", "-f", "-", "-o", "name", body={
                    "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                    "metadata": {"name": name, "labels": {LABEL: APP, "cwe/project": self.project},
                                 "ownerReferences": [{"apiVersion": "batch/v1", "kind": "Job", "name": name,
                                                      "uid": job["metadata"]["uid"], "controller": True}]},
                    "stringData": {"token": token, "builder-token": secrets.token_urlsafe(32)},
                })
            for name, token in zip(self.jobs, tokens):
                pod = self._wait_pod(name, profile.boot_timeout)
                base = (self._forward(pod["metadata"]["name"]) if self.access == "port-forward"
                        else f"http://{pod['status']['podIP']}:8080")
                device = AndroidDevice(base, token=token, session_id=session_id)
                self.devices.append(device)
                device.wait_boot(profile.boot_timeout)
            return DeviceGroup(self.devices)
        except Exception:
            self.stop()
            raise

    def _wait_pod(self, job: str, timeout: int) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pods = self._kubectl("get", "pods", "-l", f"job-name={job}", "-o", "json").get("items", [])
            for pod in pods:
                status = pod.get("status", {})
                if status.get("phase") in ("Failed", "Succeeded"):
                    raise RuntimeError(f"Android pod {pod['metadata']['name']} terminated during startup")
                if status.get("podIP") and any(c.get("type") == "Ready" and c.get("status") == "True"
                                               for c in status.get("conditions", [])):
                    return pod
            time.sleep(2)
        raise TimeoutError(f"Job {job} not ready; inspect kubectl describe pod for KVM capacity, image pulls or scheduling")

    def _forward(self, pod: str) -> str:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        proc = subprocess.Popen(self._command("port-forward", f"pod/{pod}", f"{port}:8080", "--address=127.0.0.1"),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._forwarders.append(proc)
        for _ in range(60):
            if proc.poll() is not None:
                raise RuntimeError("kubectl port-forward exited; check pods/portforward RBAC")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    return f"http://127.0.0.1:{port}"
            except OSError:
                time.sleep(0.5)
        raise TimeoutError("kubectl port-forward did not become ready")

    def stop(self) -> None:
        for device in self.devices:
            device._c.close()
        self.devices.clear()
        for proc in self._forwarders:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        self._forwarders.clear()
        for name in list(self.jobs):
            try:
                self._kubectl("delete", "job", name, "--ignore-not-found", "--wait=false")
                self.jobs.remove(name)
            except Exception:
                log.exception("Job cleanup failed for %s; activeDeadlineSeconds and TTL still apply", name)
        if self.jobs:
            raise RuntimeError(f"could not delete Android Jobs: {', '.join(self.jobs)}; retry stop() or use cwe reap")

    def reap(self, apply: bool = False) -> list[str]:
        from datetime import datetime, timezone

        jobs = self._kubectl("get", "jobs", "-l", f"{LABEL}={APP},cwe/project={self.project}", "-o", "json")
        expired = []
        for job in jobs.get("items", []):
            status = job.get("status", {})
            start = status.get("startTime", job["metadata"]["creationTimestamp"])
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds()
            finished = any(c["type"] in ("Complete", "Failed") and c["status"] == "True" for c in status.get("conditions", []))
            deadline = job.get("spec", {}).get("activeDeadlineSeconds") or 0   # a hand-written Job may omit it
            if finished or (deadline and age > deadline):
                name = job["metadata"]["name"]
                expired.append(name)
                if apply:
                    self._kubectl("delete", "job", name, "--ignore-not-found", "--wait=false")
        return expired
