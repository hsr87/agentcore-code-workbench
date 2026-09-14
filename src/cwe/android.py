"""Android emulator support.

Components
- AndroidEmulatorProfile : emulator profile: API level, image, emulator parameters, and app APK for a device session.
- emulator_host          : defaults to EKS (cwe.eks.EKSEmulatorHost), or an explicit choice of the legacy EC2 backend.
- EC2EmulatorHost        : for legacy deployment compatibility, runs the emulator container and device agent on EC2 (c8i, nested virtualization). Supports a custom AMI and a warm pool.
- AndroidDevice          : HTTP API client for the device agent (tap/swipe/text/screenshot/ui/install/instrument/...).
- FakeAndroidDevice      : in-memory device for tests.

AgentCore itself (Code Interpreter/Runtime microVM) has no /dev/kvm, so it cannot host the emulator:
code execution runs on AgentCore, while the device runs on an EKS node that has KVM. (AWS Batch ignores
the launch template's CpuOptions, so KVM cannot be obtained on c8i there.)
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import shlex
import socket
import subprocess
import time
from typing import Any

import httpx
from typing import Literal

from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

# Public API 30 image from Google's emulator container project. Mutable tag: mirror it into ECR for real use.
PUBLIC_EMULATOR_IMAGE = "us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:latest"


def emulator_host(settings=None, **kwargs):
    """Configured Android backend. EC2 remains available for existing deployments."""
    from cwe.config import get_settings

    st = settings or get_settings()
    if st.android_backend == "eks":
        from cwe.eks import EKSEmulatorHost

        return EKSEmulatorHost.from_env(st, **kwargs)
    if st.android_backend == "ec2":
        return EC2EmulatorHost.from_env(st, **kwargs)
    raise ValueError("CWE_ANDROID_BACKEND must be eks | ec2")


class AndroidEmulatorProfile(BaseModel):
    name: str = "android-default"
    # Prefer the image mirrored into ECR by `deploy.sh --stage images --mirror-emulator` (immutable tag,
    # pulled with the node role); the public Google image is only the fallback for a fresh checkout.
    image: str = Field(default_factory=lambda: os.environ.get("CWE_ANDROID_EMULATOR_IMAGE") or PUBLIC_EMULATOR_IMAGE)
    api_level: int = 30
    emulator_params: str = "-gpu swiftshader_indirect -no-audio -memory 3072"
    apk_url: str | None = Field(default=None, description="http(s)/presigned URL of the APK to install")
    package: str | None = None
    test_package: str | None = None
    test_runner: str = "androidx.test.runner.AndroidJUnitRunner"
    boot_timeout: int = 600
    job_timeout_seconds: int = 4 * 3600
    count: int = Field(default=1, ge=1, le=4, description="number of emulators to launch on the host (for parallel verification across multiple API levels/devices)")
    images: list[str] = Field(default_factory=list, description="per-emulator images when count>1. If empty, repeats image")
    build_tasks: str = "assembleDebug assembleDebugAndroidTest"
    app_apk_glob: str = "**/outputs/apk/debug/*.apk"
    test_apk_glob: str = "**/outputs/apk/androidTest/debug/*.apk"
    framework: Literal["native", "react-native", "flutter", "kmp"] = "native"


# ---------------------------------------------------------------------------
# Device agent client
# ---------------------------------------------------------------------------
class AndroidDevice:
    def __init__(self, base_url: str, token: str = "", timeout: float = 120.0, session_id: str = "", device_index: int = 0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.device_index = device_index   # which of the multiple emulators this client operates on
        headers = {}
        if token:
            headers["authorization"] = f"Bearer {token}"
        if session_id:  # lets the device agent reject a session-mismatched request with 403 (prevents accidentally attaching to another session's host)
            headers["x-cwe-session"] = session_id
        self._c = httpx.Client(base_url=self.base_url, timeout=timeout, headers=headers)

    def _post(self, path: str, body: dict[str, Any] | None = None, **params) -> dict[str, Any]:
        params = {"device": self.device_index, **params}
        r = self._c.post(path, json=body, params=params)
        r.raise_for_status()
        return r.json()

    def _get(self, path: str, **params) -> dict[str, Any]:
        params = {"device": self.device_index, **params}
        r = self._c.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def for_device(self, index: int) -> "AndroidDevice":
        """A client that operates on a different emulator on the same host."""
        d = AndroidDevice.__new__(AndroidDevice); d.__dict__.update(self.__dict__); d.device_index = index
        return d

    def devices(self) -> list[str]:
        return self.health().get("devices", [])

    def build(self, source_url: str, tasks: str = "assembleDebug assembleDebugAndroidTest", timeout: int = 1800, build_id: str | None = None) -> dict[str, Any]:
        """Run a Gradle build on the host (source is a presigned tar.gz URL). Returns the list of APK host paths."""
        r = self._c.post("/build", json={"source_url": source_url, "tasks": tasks, "timeout": timeout, "build_id": build_id}, timeout=timeout + 60)
        if r.status_code >= 400:   # surface the reason the device agent included as-is
            raise RuntimeError(f"device agent build failed ({r.status_code}): {r.text[:800]}")
        return r.json()

    def install_path(self, host_path: str) -> dict[str, Any]:
        return self._post("/install", {"path": host_path})

    def bind_session(self, session_id: str) -> dict[str, Any]:
        """Bind a warm-pool host to this session (device agent /bind, once). Subsequent requests carry x-cwe-session."""
        r = self._c.post("/bind", json={"session_id": session_id})
        r.raise_for_status()
        self._c.headers["x-cwe-session"] = session_id
        return r.json()

    def view_url(self) -> str:
        """Live screen a human opens in a browser (based on the SSM tunnel address). Carries a one-time viewer token in the URL instead of the master token (5 minutes; exchanged for an HttpOnly cookie on open)."""
        vt = self._post("/view/session")["viewer_token"]
        return f"{self.base_url}/view?vt={vt}&device={self.device_index}"

    def stream_frame(self) -> bytes:
        """A single first frame from the live stream (for verification)."""
        with self._c.stream("GET", "/stream.mjpeg", params={"device": self.device_index, "fps": 2}) as r:
            r.raise_for_status()
            buf = b""
            for chunk in r.iter_bytes():
                buf += chunk
                start = buf.find(b"\r\n\r\n")
                if start != -1:
                    head = buf[:start].decode(errors="replace")
                    n = int(head.split("Content-Length: ")[1].split("\r\n")[0])
                    body = buf[start + 4:]
                    if len(body) >= n:
                        return body[:n]

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def wait_boot(self, timeout: int = 600) -> dict[str, Any]:
        """Wait for the emulator container to start (including the image pull) and for Android to boot. Retries on 503/connection errors."""
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            try:
                h = self.health()
                if h.get("booted"):
                    return self._post("/wait_boot", timeout=60)
                last = h.get("detail") or h.get("adb_devices", "")
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):   # a token/session mismatch will not resolve itself by waiting
                    raise RuntimeError(f"device agent rejected the request ({e.response.status_code}): {e.response.text[:200]}") from e
                last = str(e)
            except httpx.HTTPError as e:
                last = str(e)
            time.sleep(10)
        raise TimeoutError(f"device did not boot within {timeout}s (last: {last[:200]})")

    def screenshot(self) -> bytes:
        r = self._c.get("/screenshot")
        r.raise_for_status()
        return r.content

    def ui(self) -> list[dict[str, Any]]:
        return self._get("/ui")["nodes"]

    def tap(self, x: int, y: int) -> dict[str, Any]:
        return self._post("/tap", {"x": x, "y": y})

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, Any]:
        return self._post("/swipe", {"x1": x1, "y1": y1, "x2": x2, "y2": y2, "duration_ms": duration_ms})

    def text(self, text: str) -> dict[str, Any]:
        return self._post("/text", {"text": text})

    def key(self, keycode: str) -> dict[str, Any]:
        return self._post("/key", {"keycode": keycode})

    def shell(self, cmd: str, timeout: int = 120) -> dict[str, Any]:
        return self._post("/shell", {"cmd": cmd, "timeout": timeout})

    def install(self, url: str) -> dict[str, Any]:
        return self._post("/install", {"url": url})

    def launch(self, package: str, activity: str | None = None) -> dict[str, Any]:
        return self._post("/launch", {"package": package, "activity": activity})

    def logcat(self, lines: int = 200, grep: str | None = None) -> str:
        return self._get("/logcat", lines=lines, **({"grep": grep} if grep else {}))["logcat"]

    def instrument(self, package: str, runner: str, args: dict[str, str] | None = None, timeout: int = 900) -> dict[str, Any]:
        return self._post("/instrument", {"package": package, "runner": runner, "args": args or {}, "timeout": timeout})

    def screenrecord_start(self, time_limit: int = 180) -> None:
        self._post("/screenrecord/start", time_limit=time_limit)

    def screenrecord_stop(self) -> bytes:
        return base64.b64decode(self._post("/screenrecord/stop")["mp4_base64"])


class FakeAndroidDevice(AndroidDevice):
    """A fake device that works without a network. Mimics screen state with simple strings."""

    _PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")

    def __init__(self):
        self.base_url = "fake://device"
        self.actions: list[tuple[str, Any]] = []
        self.screen = "home"

    def health(self): return {"booted": True, "serial": "fake"}
    def wait_boot(self, timeout=600): return {"booted": True}
    def screenshot(self): return self._PNG
    def devices(self): return ["fake:5555"]
    def build(self, source_url, tasks="assembleDebug assembleDebugAndroidTest", timeout=1800, build_id=None):
        self.actions.append(("build", tasks)); return {"ok": True, "build_id": "b1", "exit_code": 0, "seconds": 1.0, "apks": ["/opt/cwe/builds/b1/app/build/outputs/apk/debug/app-debug.apk", "/opt/cwe/builds/b1/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"], "log_tail": "BUILD SUCCESSFUL"}
    def install_path(self, host_path): self.actions.append(("install_path", host_path)); return {"ok": True, "out": "Success"}
    def view_url(self): return "http://127.0.0.1:1/view?token=fake&device=0"
    def stream_frame(self): return self._PNG
    def ui(self): return [{"text": "Login", "id": "btn_login", "class": "Button", "desc": "", "clickable": True, "center": [540, 1200]}]
    def tap(self, x, y): self.actions.append(("tap", (x, y))); self.screen = "login" if (x, y) == (540, 1200) else self.screen; return {"ok": True}
    def swipe(self, *a, **k): self.actions.append(("swipe", a)); return {"ok": True}
    def text(self, text): self.actions.append(("text", text)); return {"ok": True}
    def key(self, keycode): self.actions.append(("key", keycode)); return {"ok": True}
    def shell(self, cmd, timeout=120): self.actions.append(("shell", cmd)); return {"exit_code": 0, "stdout": f"fake:{cmd}", "stderr": ""}
    def install(self, url): self.actions.append(("install", url)); return {"ok": True, "out": "Success"}
    def launch(self, package, activity=None): self.actions.append(("launch", package)); self.screen = package; return {"ok": True}
    def logcat(self, lines=200, grep=None): return "I/fake: hello"
    def instrument(self, package, runner, args=None, timeout=900): return {"passed": 3, "failed": 0, "raw": "OK (3 tests)", "exit_code": 0}
    def screenrecord_start(self, time_limit=180): self.actions.append(("record", "start"))
    def screenrecord_stop(self): return b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100


def wait_agent(device: "AndroidDevice", timeout: int) -> None:
    """Wait until the device agent responds (instance boot + container startup)."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            device.health()
            return
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
            time.sleep(10)
    raise TimeoutError(f"device agent not reachable at {device.base_url} ({last[:200]})")


def _expires_at(seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# EC2 host user data: KVM -> ECR login -> device agent (host network, docker socket, /opt/cwe build cache) -> N emulators
# The image is always pulled fresh so we never run a stale agent baked into the AMI. bind_host is 127.0.0.1 in ssm mode.
# ---------------------------------------------------------------------------
_EC2_USER_DATA = """#!/bin/bash
set -euo pipefail
# Lifetime cap: the instance shuts itself down even if the external reaper (cwe reap) dies (InstanceInitiatedShutdownBehavior=terminate)
shutdown -h +{ttl_minutes} "cwe host ttl" || true
modprobe kvm_intel || modprobe kvm_amd || modprobe kvm
chmod 666 /dev/kvm || true
ls -l /dev/kvm > /var/log/cwe-kvm.log 2>&1
for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {registry}
mkdir -p /opt/cwe/builds /opt/cwe/gradle
# The host token is not put in user data (anyone can read it via describe-instance-attribute); it is read from an SSM SecureString instead
CWE_TOKEN=$(aws ssm get-parameter --region {region} --name {token_param} --with-decryption --query Parameter.Value --output text)
[ -n "$CWE_TOKEN" ] || {{ echo "no host token" >&2; exit 1; }}
docker pull {agent_image} >> /var/log/cwe-device-agent.log 2>&1
docker rm -f cwe-device-agent 2>/dev/null || true
docker run -d --name cwe-device-agent --restart always --network host \\
  -v /var/run/docker.sock:/var/run/docker.sock -v /opt/cwe:/opt/cwe \\
  -e DEVICE_AGENT_TOKEN="$CWE_TOKEN" -e DEVICE_AGENT_SESSION={session_id} -e DEVICE_AGENT_HOST={bind_host} \\
  -e ADB_SERIAL=auto -e EMULATOR_IMAGE_HINT=android-emulator -e BUILD_IMAGE={build_image} -e BUILD_BACKEND=docker {agent_image} >> /var/log/cwe-device-agent.log 2>&1
{emulator_runs}
"""

_EMULATOR_RUN = """docker pull {emulator_image} >> /var/log/cwe-emulator.log 2>&1
docker run -d --name android-emulator-{i} --device /dev/kvm --shm-size 1g \\
  -e EMULATOR_PARAMS={emulator_params} {emulator_image} >> /var/log/cwe-emulator.log 2>&1"""


class EC2EmulatorHost:
    """Launches one EC2 instance per session (c8i, NestedVirtualization=enabled) running the emulator + device agent.

    access modes:
      ssm     (default) SSM Session Manager port forwarding with no inbound rule. The device agent binds only to 127.0.0.1.
      private an in-VPC agent in the same security group (e.g. AgentCore Runtime in VPC mode) reaches it over the private IP.
      public  reachable over the public IP from a CIDR opted in via --allowed-cidr.

    Launching directly through the EC2 API gets nested virtualization applied (AWS Batch ignores the launch
    template's CpuOptions). Reads the security group, instance profile, and ECR image that scripts/deploy.sh
    created from the .env file.
    """

    def __init__(self, region: str, subnet_id: str, security_group: str, agent_image: str, token: str | None = None,
                 instance_type: str = "c8i.xlarge", instance_profile: str = "cwe-android-instance-profile",
                 ami_id: str | None = None, access: str = "ssm", associate_public_ip: bool = True, project: str = "cwe",
                 build_image: str = "thyrlian/android-sdk:latest", use_pool: bool = True):
        if access not in ("ssm", "private", "public"):
            raise ValueError("access must be ssm | private | public")
        self.project = project   # the IAM condition (aws:RequestTag/project) and the reaper (cwe reap) look at this tag
        self.build_image = build_image
        self.use_pool = use_pool   # prefer a host already booted in the warm pool (tagged cwe:pool=ready), if one exists
        self.from_pool = False
        import boto3

        self.ec2 = boto3.client("ec2", region_name=region)
        self.ssm = boto3.client("ssm", region_name=region)
        self.region = region
        self.subnet_id, self.security_group = subnet_id, security_group
        self.agent_image = agent_image
        self.token = token or secrets.token_urlsafe(24)   # a fresh token per session (host)
        self.token_param: str | None = None               # SSM SecureString parameter holding the token (publish_token)
        self.pool_token_param: str | None = None          # token parameter of a host claimed from the warm pool (deleted on stop)
        self.instance_type, self.instance_profile = instance_type, instance_profile
        self.ami_id = ami_id
        self.access = access
        self.associate_public_ip = associate_public_ip
        self.instance_id: str | None = None
        self.host_ip: str | None = None
        self._forwarder: subprocess.Popen | None = None
        self.local_port: int | None = None

    @classmethod
    def from_env(cls, settings=None, **kw) -> "EC2EmulatorHost":
        """Configure from the .env (CWE_ANDROID_*) that scripts/deploy.sh created."""
        from cwe.config import get_settings

        st = settings or get_settings()
        missing = [n for n, v in (("CWE_ANDROID_SUBNET_ID", st.android_subnet_id), ("CWE_ANDROID_SECURITY_GROUP_ID", st.android_security_group_id),
                                  ("CWE_ANDROID_DEVICE_AGENT_IMAGE", st.android_device_agent_image)) if not v]
        if missing:
            raise RuntimeError(f"Android host not configured; run scripts/deploy.sh (missing {', '.join(missing)})")
        kw.setdefault("instance_type", st.android_instance_type)
        kw.setdefault("instance_profile", st.android_instance_profile)
        kw.setdefault("access", st.android_access)
        kw.setdefault("associate_public_ip", st.android_associate_public_ip)
        kw.setdefault("ami_id", st.android_ami_id)
        kw.setdefault("build_image", st.android_build_image)
        return cls(region=st.region, subnet_id=st.android_subnet_id, security_group=st.android_security_group_id,
                   agent_image=st.android_device_agent_image, **kw)

    def publish_token(self) -> str:
        """Upload the host token to an SSM SecureString and return the parameter name. user data carries only this name."""
        self.token_param = f"/{self.project}/hosts/{secrets.token_hex(8)}/token"
        self.ssm.put_parameter(Name=self.token_param, Value=self.token, Type="SecureString", Overwrite=True)
        return self.token_param

    def _delete_token_param(self) -> None:
        if self.token_param:
            try:
                self.ssm.delete_parameter(Name=self.token_param)
            except Exception as e:  # noqa: BLE001
                log.warning("delete token parameter failed: %s", e)
            self.token_param = None

    def render_user_data(self, profile: AndroidEmulatorProfile, session_id: str, ttl_seconds: int | None = None) -> str:
        """Every value that goes into the root shell script is wrapped with shlex.quote (the profile can be derived from the target repository)."""
        if not self.token_param:
            raise RuntimeError("call publish_token() before render_user_data()")
        bind_host = "127.0.0.1" if self.access == "ssm" else "0.0.0.0"
        images = profile.images or [profile.image] * profile.count
        q = shlex.quote
        runs = "\n".join(_EMULATOR_RUN.format(i=i, emulator_params=q(profile.emulator_params), emulator_image=q(img)) for i, img in enumerate(images[: profile.count]))
        ttl = max(5, int((ttl_seconds or profile.job_timeout_seconds) // 60) + 5)
        return _EC2_USER_DATA.format(region=q(self.region), registry=q(self.agent_image.split("/")[0]), token_param=q(self.token_param), session_id=q(session_id),
                                     bind_host=bind_host, agent_image=q(self.agent_image), build_image=q(self.build_image), emulator_runs=runs, ttl_minutes=ttl)

    def _acquire_pool_instance(self, session_id: str) -> str | None:
        """Claim a host already booted in the warm pool and assign it to this session (attempts an atomic tag swap)."""
        res = self.ec2.describe_instances(Filters=[{"Name": "tag:cwe:pool", "Values": ["ready"]}, {"Name": "tag:project", "Values": [self.project]},
                                                   {"Name": "instance-state-name", "Values": ["running"]}])["Reservations"]
        import random

        for r in res:
            for inst in r["Instances"]:
                iid = inst["InstanceId"]
                try:
                    time.sleep(random.uniform(0, 0.5))   # mitigate concurrent claims (tags are not an atomic CAS)
                    cur = {t["Key"]: t["Value"] for t in self.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0].get("Tags", [])}
                    if cur.get("cwe:pool") != "ready":
                        continue
                    self.ec2.create_tags(Resources=[iid], Tags=[{"Key": "cwe:pool", "Value": f"claimed:{session_id}"}, {"Key": "cwe_session", "Value": session_id},
                                                                {"Key": "Name", "Value": f"cwe-emu-{session_id}"}])
                    time.sleep(random.uniform(0.2, 0.6))
                    tags = {t["Key"]: t["Value"] for t in self.ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]["Tags"]}
                    if tags.get("cwe:pool") == f"claimed:{session_id}":
                        # the pool host's device agent came up with the pool token; read the token from the SSM parameter
                        self.pool_token_param = f"/{self.project}/pool/{iid}/token"
                        self.token = self.ssm.get_parameter(Name=self.pool_token_param, WithDecryption=True)["Parameter"]["Value"]
                        return iid
                except Exception as e:
                    log.warning("pool claim failed for %s: %s", iid, e)
        return None

    def start(self, profile: AndroidEmulatorProfile, session_id: str) -> AndroidDevice:
        if self.use_pool and (iid := self._acquire_pool_instance(session_id)):
            self.instance_id, self.from_pool = iid, True
            log.info("claimed pool host %s", iid)
            return self._connect(profile, session_id)
        ami = self.ami_id or self.ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id")["Parameter"]["Value"]
        self.publish_token()
        user_data = self.render_user_data(profile, session_id)
        r = self.ec2.run_instances(
            ImageId=ami, InstanceType=self.instance_type, MinCount=1, MaxCount=1,
            CpuOptions={"NestedVirtualization": "enabled"},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": self.subnet_id, "Groups": [self.security_group],
                                "AssociatePublicIpAddress": self.associate_public_ip}],
            IamInstanceProfile={"Name": self.instance_profile},
            MetadataOptions={"HttpTokens": "required", "HttpPutResponseHopLimit": 1},   # keeps the build container (bridge network) from reaching the instance role
            BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3", "DeleteOnTermination": True}}],
            UserData=user_data,
            InstanceInitiatedShutdownBehavior="terminate",
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": f"cwe-emu-{session_id}"},
                                                                   {"Key": "project", "Value": self.project},
                                                                   {"Key": "cwe_session", "Value": session_id},
                                                                   {"Key": "cwe:expires-at", "Value": _expires_at(profile.job_timeout_seconds)}]}],
        )
        self.instance_id = r["Instances"][0]["InstanceId"]
        log.info("launched %s (%s)", self.instance_id, self.instance_type)
        return self._connect(profile, session_id)

    def _connect(self, profile: AndroidEmulatorProfile, session_id: str) -> AndroidDevice:
        self.ec2.get_waiter("instance_running").wait(InstanceIds=[self.instance_id])
        inst = self.ec2.describe_instances(InstanceIds=[self.instance_id])["Reservations"][0]["Instances"][0]
        if self.access == "ssm":
            self._start_port_forward()
            base_url = f"http://127.0.0.1:{self.local_port}"
        else:
            self.host_ip = (inst.get("PublicIpAddress") if self.access == "public" else None) or inst["PrivateIpAddress"]
            base_url = f"http://{self.host_ip}:8080"
        device = AndroidDevice(base_url, token=self.token, session_id=session_id)
        wait_agent(device, timeout=600)
        if self.from_pool:
            device.bind_session(session_id)   # bind the pool host to this session (any other session's header gets 403 afterward)
        self._delete_token_param()            # the agent has read the token, so there is no reason to keep the SecureString around
        device.wait_boot(timeout=profile.boot_timeout)
        return device

    # -- SSM port forwarding (no inbound security group rule) -----------------
    def _wait_ssm_managed(self, timeout: int = 300) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            info = self.ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [self.instance_id]}])["InstanceInformationList"]
            if info and info[0].get("PingStatus") == "Online":
                return
            time.sleep(5)
        raise TimeoutError(f"{self.instance_id} did not register with SSM (instance profile needs AmazonSSMManagedInstanceCore)")

    def _start_port_forward(self) -> None:
        self._wait_ssm_managed()
        with socket.socket() as s_:
            s_.bind(("127.0.0.1", 0)); self.local_port = s_.getsockname()[1]
        cmd = ["aws", "ssm", "start-session", "--region", self.region, "--target", self.instance_id,
               "--document-name", "AWS-StartPortForwardingSession",
               "--parameters", json.dumps({"portNumber": ["8080"], "localPortNumber": [str(self.local_port)]})]
        self._forwarder = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._ssm_session_id: str | None = None
        for _ in range(30):  # until the plugin opens the local port
            if self._forwarder.poll() is not None:
                err = self._forwarder.stderr.read().decode(errors="replace") if self._forwarder.stderr else ""
                raise RuntimeError(f"ssm start-session exited: {err.strip()[:400]}")
            try:
                with socket.create_connection(("127.0.0.1", self.local_port), timeout=1):
                    log.info("SSM port forward 127.0.0.1:%s -> %s:8080", self.local_port, self.instance_id)
                    return
            except OSError:
                time.sleep(1)
        raise TimeoutError("SSM port forwarding did not open the local port")

    def _terminate_ssm_session(self) -> None:
        """After ending the plugin process, also explicitly terminate the SSM session record (so it does not linger as Active)."""
        try:
            for sess in self.ssm.describe_sessions(State="Active", Filters=[{"key": "Target", "value": self.instance_id}]).get("Sessions", []):
                self.ssm.terminate_session(SessionId=sess["SessionId"])
        except Exception as e:
            log.debug("terminate ssm session skipped: %s", e)

    def stop(self) -> None:
        if self._forwarder and self._forwarder.poll() is None:
            self._forwarder.terminate()
            try:
                self._forwarder.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._forwarder.kill()
        self._forwarder = None
        if self.instance_id and self.access == "ssm":
            self._terminate_ssm_session()
        if self.instance_id:
            try:
                self.ec2.terminate_instances(InstanceIds=[self.instance_id])
            except Exception as e:
                log.warning("terminate failed: %s", e)
        self._delete_token_param()
        if self.pool_token_param:
            try:
                self.ssm.delete_parameter(Name=self.pool_token_param)
            except Exception as e:  # noqa: BLE001
                log.debug("delete pool token parameter skipped: %s", e)
            self.pool_token_param = None
        self.instance_id = None
