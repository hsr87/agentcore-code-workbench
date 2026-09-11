"""Device agent: exposes adb next to an Android emulator as an HTTP API.

The calling agent needs no adb binary, so the same client code drives a device from a Code
Interpreter sandbox, from AgentCore Runtime, or from a laptop.

Security rules
- Without DEVICE_AGENT_TOKEN the process refuses to start. Every comparison is constant time.
- x-cwe-session is a routing guard against attaching to the wrong host, not a secret. A pooled
  host is bound to one session exactly once through /bind.
- Inputs naming a host path (build_id, install.path) are confined to /opt/cwe/builds, and Gradle
  task names are passed as argv, never through a shell.
- The browser viewer never receives the master token: it exchanges a single-use viewer token for
  an HttpOnly cookie, and that cookie is accepted only on read-only viewer paths.
- Downloads are HTTPS-only and are re-checked after every redirect against private, loopback and
  link-local addresses.
"""

from __future__ import annotations

import base64
import html
import ipaddress
import logging
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field

ADB = os.environ.get("ADB", "adb")
SERIAL = os.environ.get("ADB_SERIAL", "auto")   # "auto": find the emulator container IP via the docker socket. A comma-separated list can supply serials directly instead.
TOKEN = os.environ.get("DEVICE_AGENT_TOKEN", "")
SESSION = os.environ.get("DEVICE_AGENT_SESSION", "")   # If set, the x-cwe-session header must match it. If empty, it can be bound once via /bind.
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
EMULATOR_IMAGE_HINT = os.environ.get("EMULATOR_IMAGE_HINT", "android-emulator")
BUILD_IMAGE = os.environ.get("BUILD_IMAGE", "thyrlian/android-sdk:latest")     # container used on the host for Gradle builds
BUILD_BACKEND = os.environ.get("BUILD_BACKEND", "docker")
BUILD_SIDECAR_URL = os.environ.get("BUILD_SIDECAR_URL", "http://127.0.0.1:9090/build")
BUILD_SIDECAR_TOKEN = os.environ.get("BUILD_SIDECAR_TOKEN", "")   # every container in the Pod shares loopback, so the builder needs its own credential
HOST_WORK = os.environ.get("HOST_WORK", "/opt/cwe")                              # host path (mounted at the same path in both the device agent and the build container)
BUILDS_DIR = os.path.realpath(os.path.join(HOST_WORK, "builds"))
MAX_DOWNLOAD_BYTES = int(os.environ.get("MAX_DOWNLOAD_BYTES", str(512 * 1024 * 1024)))
MAX_EXTRACT_BYTES = int(os.environ.get("MAX_EXTRACT_BYTES", str(4 * 1024 * 1024 * 1024)))
VIEWER_TTL_SECONDS = int(os.environ.get("VIEWER_TTL_SECONDS", "1800"))

if not TOKEN:
    raise SystemExit("DEVICE_AGENT_TOKEN is required (refusing to start unauthenticated)")

LOG = logging.getLogger("cwe.device_agent")
app = FastAPI(title="cwe device agent", docs_url=None, redoc_url=None, openapi_url=None)

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")
_TASK_RE = re.compile(r"[A-Za-z0-9_:.-]{1,80}")
_KEYCODE_RE = re.compile(r"KEYCODE_[A-Z0-9_]{1,32}|[0-9]{1,4}")
_PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,127}")
_RUNNER_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.$]{0,127}")
MAX_SIDECAR_TIMEOUT = 3600   # the builder rejects anything longer
_bind_lock = threading.Lock()
_record_lock = threading.Lock()


def _eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape"))


# ---------------------------------------------------------------------------
# docker Engine API (unix socket) — used only for discovering the emulator container and running the Gradle build container
# ---------------------------------------------------------------------------
def _docker_req(method: str, path: str, body: dict | None = None, timeout: float = 600, raw: bool = False):
    """Calls the docker Engine API (unix socket). Creates and runs containers without the CLI."""
    import http.client, json as _json, socket

    class _Unix(http.client.HTTPConnection):
        def __init__(self, p):
            super().__init__("localhost", timeout=timeout); self._path = p

        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(timeout); self.sock.connect(self._path)

    conn = _Unix(DOCKER_SOCK)
    data = _json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
    resp = conn.getresponse(); payload = resp.read()
    if raw:
        return resp.status, payload
    try:
        return resp.status, (_json.loads(payload) if payload else {})
    except ValueError:
        return resp.status, {"raw": payload.decode("utf-8", "replace")}


def _docker_get(path: str):
    return _docker_req("GET", path, timeout=30)[1]


def _demux_logs(payload: bytes) -> str:
    """Strips the 8-byte frame header from docker logs."""
    out, i = [], 0
    while i + 8 <= len(payload):
        n = int.from_bytes(payload[i + 4:i + 8], "big"); out.append(payload[i + 8:i + 8 + n]); i += 8 + n
    return b"".join(out).decode("utf-8", "replace") if out else payload.decode("utf-8", "replace")


def docker_run(image: str, cmd: list[str], binds: list[str], workdir: str, env: list[str], timeout: int) -> tuple[int, str]:
    """Pulls the image (if missing), runs the container, and returns (exit_code, logs). The caller restricts binds to BUILDS_DIR / the gradle cache."""
    import urllib.parse
    name, _, tag = image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "latest")
    _docker_req("POST", f"/images/create?fromImage={urllib.parse.quote(name)}&tag={urllib.parse.quote(tag or 'latest')}", timeout=timeout, raw=True)
    st, c = _docker_req("POST", "/containers/create", {"Image": image, "Cmd": cmd, "WorkingDir": workdir, "Env": env,
                                                      "HostConfig": {"Binds": binds, "AutoRemove": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]}}, timeout=60)
    if st >= 300:
        raise RuntimeError(f"container create failed: {c}")
    cid = c["Id"]
    try:
        _docker_req("POST", f"/containers/{cid}/start", timeout=60)
        st, w = _docker_req("POST", f"/containers/{cid}/wait", timeout=timeout)
        code = int(w.get("StatusCode", -1))
        _, logs = _docker_req("GET", f"/containers/{cid}/logs?stdout=1&stderr=1", timeout=60, raw=True)
        return code, _demux_logs(logs)
    finally:
        _docker_req("DELETE", f"/containers/{cid}?force=1", timeout=60)


def emulator_serials() -> list[str]:
    """List of emulator serials on the host. If ADB_SERIAL is given a comma-separated list, that value is used without the docker socket."""
    if SERIAL != "auto" and not SERIAL.startswith("auto:"):
        return [s.strip() for s in SERIAL.split(",") if s.strip()]
    out = []
    for c in sorted(_docker_get("/containers/json"), key=lambda c: c.get("Names", [""])[0]):
        if EMULATOR_IMAGE_HINT in c.get("Image", ""):
            nets = c.get("NetworkSettings", {}).get("Networks", {})
            ip = next((n.get("IPAddress") for n in nets.values() if n.get("IPAddress")), None)
            if ip:
                out.append(f"{ip}:5555")
    return out


def discover_serial(index: int = 0) -> str:
    serials = emulator_serials()
    if len(serials) > index:
        return serials[index]
    raise HTTPException(503, f"emulator #{index} not found yet ({len(serials)} running)")


def select_device(device: int = 0) -> int:
    """Endpoint dependency: picks one of multiple emulators via ?device=N (passed per request, no global state)."""
    if device < 0 or device > 15:
        raise HTTPException(400, "device index out of range")
    return device


Dev = Annotated[int, Depends(select_device)]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
_viewer_tokens: dict[str, float] = {}   # single-use exchange token -> expiry
_viewer_cookies: dict[str, float] = {}  # cookie value -> expiry
_VIEWER_PATHS = {"/view", "/stream.mjpeg", "/tap", "/key", "/text", "/swipe"}


def _viewer_ok(request: Request) -> bool:
    if request.url.path not in _VIEWER_PATHS:
        return False
    cookie = request.cookies.get("cwe_view", "")
    exp = _viewer_cookies.get(cookie)
    if not cookie or exp is None:
        return False
    if exp < time.time():
        _viewer_cookies.pop(cookie, None)
        return False
    return True


def auth(request: Request):
    given = request.headers.get("authorization", "")
    if TOKEN and _eq(given, f"Bearer {TOKEN}"):
        if SESSION and not _eq(request.headers.get("x-cwe-session", ""), SESSION):
            raise HTTPException(403, "session mismatch")
        return
    if _viewer_ok(request):   # browser viewer: HttpOnly cookie, viewer paths only
        return
    raise HTTPException(401, "bad token")


def adb(*args: str, device: int = 0, timeout: int = 120, binary: bool = False):
    cmd = [ADB, "-s", discover_serial(device), *args]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if binary:
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def ensure_connected(device: int = 0) -> None:
    subprocess.run([ADB, "connect", discover_serial(device)], capture_output=True, timeout=30)


class Tap(BaseModel):
    x: int
    y: int


class Swipe(BaseModel):
    x1: int
    y1: int
    x2: int
    y2: int
    duration_ms: int = 300


class Text(BaseModel):
    text: str = Field(max_length=4000)


class Key(BaseModel):
    keycode: str = Field(max_length=40, pattern=r"^(KEYCODE_[A-Z0-9_]{1,32}|[0-9]{1,4})$")  # e.g. KEYCODE_BACK, 66


class Shell(BaseModel):
    cmd: str = Field(max_length=20000)
    timeout: int = Field(default=120, ge=1, le=3600)


class Install(BaseModel):
    url: str | None = None      # https or a presigned S3 URL
    path: str | None = None     # host path. Only allowed under /opt/cwe/builds (e.g. /opt/cwe/builds/<id>/app/build/outputs/apk/debug/app-debug.apk)
    reinstall: bool = True


class Build(BaseModel):
    source_url: str                       # source tar.gz (presigned S3 URL, a snapshot)
    tasks: str = "assembleDebug assembleDebugAndroidTest"
    timeout: int = Field(default=1800, ge=30, le=7200)
    build_id: str | None = None


class Launch(BaseModel):
    package: str = Field(max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,127}$")
    activity: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.$]{0,127}$")


class Instrument(BaseModel):
    package: str = Field(max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.]{0,127}$")   # test package, e.g. com.example.app.test
    runner: str = Field(default="androidx.test.runner.AndroidJUnitRunner", max_length=128, pattern=r"^[A-Za-z][A-Za-z0-9_.$]{0,127}$")
    args: dict[str, str] = Field(default_factory=dict, max_length=32)
    timeout: int = Field(default=900, ge=1, le=7200)


class Bind(BaseModel):
    session_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")


# ---------------------------------------------------------------------------
# State / binding
# ---------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    """Unauthenticated liveness check only. Returns no device information."""
    return {"ok": True}


@app.get("/health", dependencies=[Depends(auth)])
def health(device: Dev):
    try:
        serial = discover_serial(device)
    except HTTPException as e:
        return {"serial": None, "booted": False, "detail": e.detail}
    ensure_connected(device)
    rc, out, _ = adb("shell", "getprop", "sys.boot_completed", device=device, timeout=20)
    booted = rc == 0 and out.strip() == "1"
    return {"serial": serial, "booted": booted, "devices": emulator_serials(), "session_bound": bool(SESSION),
            "adb_devices": subprocess.run([ADB, "devices"], capture_output=True, text=True, timeout=20).stdout}


@app.post("/bind", dependencies=[Depends(auth)])
def bind(b: Bind):
    """Binds a pooled host to a single session (once only). Subsequent requests must match x-cwe-session."""
    global SESSION
    with _bind_lock:   # two concurrent binds must not both win
        if SESSION:
            raise HTTPException(409, "already bound")
        SESSION = b.session_id
    return {"bound": SESSION}


@app.post("/wait_boot", dependencies=[Depends(auth)])
def wait_boot(device: Dev, timeout: int = 300):
    deadline = time.time() + min(timeout, 1800)
    while time.time() < deadline:
        try:
            ensure_connected(device)
            rc, out, _ = adb("shell", "getprop", "sys.boot_completed", device=device, timeout=20)
        except HTTPException:  # emulator container not present yet (image still pulling)
            time.sleep(5)
            continue
        if rc == 0 and out.strip() == "1":
            for k in ("window_animation_scale", "transition_animation_scale", "animator_duration_scale"):
                adb("shell", "settings", "put", "global", k, "0", device=device)
            return {"booted": True}
        time.sleep(3)
    raise HTTPException(504, "device did not boot in time")


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------
@app.get("/screenshot", dependencies=[Depends(auth)])
def screenshot(device: Dev):
    rc, png, err = adb("exec-out", "screencap", "-p", device=device, binary=True, timeout=60)
    if rc != 0 or not png.startswith(b"\x89PNG"):
        raise HTTPException(500, f"screencap failed: {err[:300]}")
    return Response(content=png, media_type="image/png")


@app.get("/ui", dependencies=[Depends(auth)])
def ui_dump(device: Dev):
    """uiautomator hierarchy dump (XML). Lets element coordinates be found without vision."""
    adb("shell", "uiautomator", "dump", "/sdcard/cwe_ui.xml", device=device, timeout=60)
    rc, xml, err = adb("shell", "cat", "/sdcard/cwe_ui.xml", device=device, timeout=30)
    if rc != 0:
        raise HTTPException(500, err[:300])
    nodes = []
    for m in re.finditer(r'<node[^>]*?text="([^"]*)"[^>]*?resource-id="([^"]*)"[^>]*?class="([^"]*)"[^>]*?content-desc="([^"]*)"[^>]*?clickable="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        text, rid, cls, desc, clickable, x1, y1, x2, y2 = m.groups()
        if text or desc or clickable == "true":
            nodes.append({"text": text, "id": rid, "class": cls.split(".")[-1], "desc": desc, "clickable": clickable == "true",
                          "center": [(int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2]})
    return {"nodes": nodes[:200], "xml_len": len(xml)}


@app.post("/tap", dependencies=[Depends(auth)])
def tap(t: Tap, device: Dev):
    rc, out, err = adb("shell", "input", "tap", str(t.x), str(t.y), device=device)
    return {"ok": rc == 0, "out": out + err}


@app.post("/swipe", dependencies=[Depends(auth)])
def swipe(s: Swipe, device: Dev):
    rc, out, err = adb("shell", "input", "swipe", str(s.x1), str(s.y1), str(s.x2), str(s.y2), str(s.duration_ms), device=device)
    return {"ok": rc == 0, "out": out + err}


@app.post("/text", dependencies=[Depends(auth)])
def text(t: Text, device: Dev):
    # adb joins argv into one string that the device shell re-parses, so quote before sending.
    rc, out, err = adb("shell", "input", "text", shlex.quote(t.text.replace(" ", "%s")), device=device)
    return {"ok": rc == 0, "out": out + err}


@app.post("/key", dependencies=[Depends(auth)])
def key(k: Key, device: Dev):
    rc, out, err = adb("shell", "input", "keyevent", k.keycode, device=device)
    return {"ok": rc == 0, "out": out + err}


@app.post("/shell", dependencies=[Depends(auth)])
def shell(s: Shell, device: Dev):
    """Shell inside the emulator (the device itself, not the host). A documented purpose that does not cross the host boundary."""
    rc, out, err = adb("shell", s.cmd, device=device, timeout=s.timeout)
    return {"exit_code": rc, "stdout": out[-200000:], "stderr": err[-20000:]}


# ---------------------------------------------------------------------------
# Download / build / install (host filesystem boundary)
# ---------------------------------------------------------------------------
def _check_public_https(url: str) -> None:
    """HTTPS only, and never an address inside the cluster, the VPC or link-local metadata."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise HTTPException(400, "url must be https")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        raise HTTPException(400, "url host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise HTTPException(400, "url resolves to a non-public address")


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    """Re-apply the scheme and address checks to every redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_public_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, dst: str) -> int:
    _check_public_https(url)
    opener = urllib.request.build_opener(_CheckedRedirect)
    deadline = time.monotonic() + 900
    n = 0
    with opener.open(url, timeout=120) as r, open(dst, "wb") as f:   # noqa: S310 (checked https only)
        while chunk := r.read(1 << 20):
            n += len(chunk)
            if n > MAX_DOWNLOAD_BYTES:
                raise HTTPException(413, f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
            if time.monotonic() > deadline:
                raise HTTPException(504, "download exceeded its time budget")
            f.write(chunk)
    return n


def _under_builds(path: str) -> str:
    real = os.path.realpath(path)
    if not real.startswith(BUILDS_DIR + os.sep):
        raise HTTPException(400, f"path must be under {BUILDS_DIR}")
    return real


def _safe_extract(src: str, work: str) -> None:
    """Extracts the tar.gz only under work (filter='data' rejects absolute paths, '..', and links pointing outside)."""
    total = 0
    with tarfile.open(src) as t:
        for m in t:
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                raise HTTPException(413, "archive too large")
        t.extractall(work, filter="data")


def _prune_builds(keep: str, max_age: int = 3600) -> None:
    if not os.path.isdir(BUILDS_DIR):
        return
    for d in os.listdir(BUILDS_DIR):
        p = os.path.join(BUILDS_DIR, d)
        if d != keep and os.path.isdir(p) and time.time() - os.path.getmtime(p) > max_age:
            shutil.rmtree(p, ignore_errors=True)


@app.post("/install", dependencies=[Depends(auth)])
def install(i: Install, device: Dev):
    if i.path:
        path, cleanup = _under_builds(i.path), False
        if not path.endswith(".apk"):
            raise HTTPException(404, "apk not found on host")
        try:  # the builder container shares this volume, so refuse a symlink swapped in after the check
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise HTTPException(404, "apk not found on host")
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HTTPException(404, "apk not found on host")
            # Install the exact file we opened: copy it out of the shared volume into this container's private
            # tmp under a name ending in .apk. adb rejects paths without that suffix, so /proc/self/fd is not usable.
            with os.fdopen(fd, "rb") as src, tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as dst:
                shutil.copyfileobj(src, dst)
                private = dst.name
        except HTTPException:
            os.close(fd)
            raise
        try:
            args = ["install"] + (["-r", "-t"] if i.reinstall else ["-t"]) + [private]
            rc, out, err = adb(*args, device=device, timeout=600)
        finally:
            os.unlink(private)
        return {"ok": rc == 0 and "Success" in out, "out": (out + err)[-4000:]}
    elif i.url:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            path = f.name
        try:
            _download(i.url, path); cleanup = True
        except Exception:
            os.unlink(path); raise
    else:
        raise HTTPException(400, "url or path required")
    args = ["install"] + (["-r", "-t"] if i.reinstall else ["-t"]) + [path]
    try:
        rc, out, err = adb(*args, device=device, timeout=600)
    finally:
        if cleanup:
            os.unlink(path)
    return {"ok": rc == 0 and "Success" in out, "out": (out + err)[-4000:]}


@app.post("/build", dependencies=[Depends(auth)])
def build(b: Build):
    """Extracts the source tar.gz on the host and runs a Gradle build in the Android SDK container. Returns the APK paths.
    The Gradle cache is kept at HOST_WORK/gradle and reused on the same host (or AMI)."""
    import glob, uuid

    bid = b.build_id or uuid.uuid4().hex[:10]
    if not _ID_RE.fullmatch(bid):
        raise HTTPException(400, "bad build_id")
    tasks = b.tasks.split()
    if not tasks or not all(_TASK_RE.fullmatch(t) and not t.startswith("-") for t in tasks):
        raise HTTPException(400, "bad gradle tasks")   # a leading '-' would be a Gradle flag, not a task
    work = _under_builds(os.path.join(BUILDS_DIR, bid))
    gradle_cache = os.path.join(HOST_WORK, "gradle")
    try:
        os.makedirs(work, exist_ok=True); os.makedirs(gradle_cache, exist_ok=True)
        src = os.path.join(work, "src.tar.gz")
        _download(b.source_url, src)
        _safe_extract(src, work)
        os.remove(src)
        _prune_builds(keep=bid)
    except HTTPException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    except Exception as e:  # the cause is logged, not returned: it can carry presigned URLs and host paths
        shutil.rmtree(work, ignore_errors=True)
        LOG.warning("build prep failed for %s: %s", bid, e)
        raise HTTPException(500, f"build prep failed: {type(e).__name__}")
    started = time.time()
    cmd = ["sh", "-c", 'chmod +x ./gradlew && exec ./gradlew --no-daemon -q "$@"', "gradlew", *tasks]   # tasks are passed only as argv (no shell interpretation)
    try:
        if BUILD_BACKEND == "sidecar":
            import json

            timeout = min(b.timeout, MAX_SIDECAR_TIMEOUT)
            request = urllib.request.Request(
                BUILD_SIDECAR_URL,
                data=json.dumps({"build_id": bid, "tasks": tasks, "timeout": timeout}).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {BUILD_SIDECAR_TOKEN}"}, method="POST",
            )
            with urllib.request.urlopen(request, timeout=timeout + 30) as response:
                result = json.load(response)
            code, log = result["exit_code"], result["log_tail"]
        elif BUILD_BACKEND == "docker":
            code, log = docker_run(BUILD_IMAGE, cmd, binds=[f"{work}:/work", f"{gradle_cache}:/root/.gradle"], workdir="/work",
                                   env=["GRADLE_OPTS=-Dorg.gradle.daemon=false"], timeout=b.timeout)
        else:
            raise ValueError("BUILD_BACKEND must be docker | sidecar")
    except Exception as e:
        LOG.warning("build runner failed for %s: %s", bid, e)
        raise HTTPException(500, f"build runner failed: {type(e).__name__}")
    apks = sorted(glob.glob(f"{work}/**/outputs/apk/**/*.apk", recursive=True))
    return {"ok": code == 0 and bool(apks), "build_id": bid, "exit_code": code, "seconds": round(time.time() - started, 1),
            "apks": apks, "log_tail": log[-6000:]}


@app.post("/launch", dependencies=[Depends(auth)])
def launch(l: Launch, device: Dev):
    if l.activity:
        rc, out, err = adb("shell", "am", "start", "-n", f"{l.package}/{l.activity}", device=device)
    else:
        rc, out, err = adb("shell", "monkey", "-p", l.package, "-c", "android.intent.category.LAUNCHER", "1", device=device)
    return {"ok": rc == 0, "out": out + err}


@app.get("/logcat", dependencies=[Depends(auth)])
def logcat(device: Dev, lines: int = 200, grep: str | None = None):
    rc, out, err = adb("logcat", "-d", "-t", str(min(max(lines, 1), 5000)), device=device, timeout=60)
    if grep:
        if len(grep) > 200:
            raise HTTPException(400, "grep pattern too long")
        try:
            pat = re.compile(grep)
        except re.error:
            raise HTTPException(400, "bad grep pattern")
        # Bounded work: a caller-supplied pattern can still backtrack, so cap both line count and line length.
        lines = out[-500000:].splitlines()[-2000:]
        out = "\n".join(l for l in lines if pat.search(l[:1000]))
    return {"logcat": out[-20000:]}


@app.post("/logcat/clear", dependencies=[Depends(auth)])
def logcat_clear(device: Dev):
    adb("logcat", "-c", device=device)
    return {"ok": True}


@app.post("/instrument", dependencies=[Depends(auth)])
def instrument(i: Instrument, device: Dev):
    """Runs an Espresso / UI Automator instrumentation test (am instrument -w -r) and parses the result."""
    extra = sum((["-e", k, v] for k, v in i.args.items()), [])
    rc, out, err = adb("shell", "am", "instrument", "-w", "-r", *extra, f"{i.package}/{i.runner}", device=device, timeout=i.timeout)
    tests = re.findall(r"INSTRUMENTATION_STATUS: test=(\S+).*?INSTRUMENTATION_STATUS_CODE: (-?\d+)", out, re.S)
    passed = sum(1 for _, c in tests if c == "0")
    failed = sum(1 for _, c in tests if c in {"-2", "-1"})
    m = re.search(r"INSTRUMENTATION_RESULT: stream=(.*?)INSTRUMENTATION_CODE", out, re.S)
    return {"passed": passed, "failed": failed, "raw": (m.group(1) if m else out)[-8000:], "exit_code": rc, "stderr": err[-2000:]}


# ---------------------------------------------------------------------------
# Live screen (for a human)
# ---------------------------------------------------------------------------
def _jpeg_frame(device: int) -> bytes:
    rc, png, _ = adb("exec-out", "screencap", "-p", device=device, binary=True, timeout=30)
    if rc != 0 or not png.startswith(b"\x89PNG"):
        return b""
    try:  # PNG -> JPEG (roughly 1/10 the size). Falls back to the raw PNG if Pillow is unavailable
        from io import BytesIO

        from PIL import Image

        im = Image.open(BytesIO(png)).convert("RGB"); im.thumbnail((540, 1200)); buf = BytesIO(); im.save(buf, "JPEG", quality=70); return buf.getvalue()
    except Exception:
        return png


@app.get("/stream.mjpeg", dependencies=[Depends(auth)])
def stream(device: Dev, fps: float = 2.0):
    """Live screen for a human to watch. Streams frames as multipart/x-mixed-replace (opened from a browser over an SSM tunnel)."""
    boundary = "cweframe"
    delay = max(0.1, 1.0 / max(fps, 0.1))

    def gen():
        while True:
            frame = _jpeg_frame(device)
            if frame:
                mime = b"image/jpeg" if frame[:2] == b"\xff\xd8" else b"image/png"
                yield b"--" + boundary.encode() + b"\r\nContent-Type: " + mime + b"\r\nContent-Length: " + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n"
            time.sleep(delay)

    return StreamingResponse(gen(), media_type=f"multipart/x-mixed-replace; boundary={boundary}")


@app.post("/view/session", dependencies=[Depends(auth)])
def view_session():
    """Creates a single-use exchange token for the browser viewer (the master token is never given to the browser)."""
    now = time.time()
    for d in (_viewer_tokens, _viewer_cookies):
        for k in [k for k, exp in d.items() if exp < now]:
            d.pop(k, None)
    vt = secrets.token_urlsafe(24)
    _viewer_tokens[vt] = now + 300   # must be opened in the browser within 5 minutes
    return {"viewer_token": vt, "expires_in": 300}


@app.get("/view", response_class=HTMLResponse)
def view(request: Request, device: Dev, vt: str | None = None):
    """Browser viewer: watch the screen and click (tap), press Back/Home, type text, so a person can step in during a session.
    ?vt= is a single-use exchange token that is immediately converted into an HttpOnly cookie (safe even if it lingers in the address bar or logs, since it cannot be reused)."""
    if vt is not None:
        exp = _viewer_tokens.pop(vt, None)
        if exp is None or exp < time.time():
            raise HTTPException(401, "viewer token expired")
        cookie = secrets.token_urlsafe(24)
        _viewer_cookies[cookie] = time.time() + VIEWER_TTL_SECONDS
        resp = RedirectResponse(url=f"/view?device={device}", status_code=303)
        resp.set_cookie("cwe_view", cookie, httponly=True, samesite="strict", max_age=VIEWER_TTL_SECONDS)
        return resp
    if not _viewer_ok(request):
        raise HTTPException(401, "open /view with a viewer token from POST /view/session")
    d = html.escape(str(device))
    return f"""<!doctype html><html><head><meta charset=utf-8><title>cwe device {d}</title>
<style>body{{font-family:system-ui;margin:16px;background:#111;color:#eee}} img{{border:1px solid #444;max-height:85vh;cursor:crosshair}} button,input{{margin:4px}}</style></head>
<body><div><img id=s src="/stream.mjpeg?device={d}">
<div><button onclick="key('KEYCODE_BACK')">Back</button><button onclick="key('KEYCODE_HOME')">Home</button>
<input id=t placeholder="text"><button onclick="typeText()">Type</button><span id=m></span></div></div>
<script>
const H={{'Content-Type':'application/json'}};
const D='device={d}';
async function post(p,b){{const r=await fetch(p+'?'+D,{{method:'POST',headers:H,credentials:'same-origin',body:JSON.stringify(b)}});document.getElementById('m').textContent=p+' '+r.status;}}
document.getElementById('s').onclick=e=>{{const im=e.target,r=im.getBoundingClientRect();post('/tap',{{x:Math.round((e.clientX-r.left)/r.width*1080),y:Math.round((e.clientY-r.top)/r.height*1920)}});}};
function key(k){{post('/key',{{keycode:k}})}} function typeText(){{post('/text',{{text:document.getElementById('t').value}})}}
</script></body></html>"""


# ---------------------------------------------------------------------------
# Screen recording
# ---------------------------------------------------------------------------
_record_procs: dict[int, subprocess.Popen] = {}
_record_path = "/sdcard/cwe_record.mp4"


@app.post("/screenrecord/start", dependencies=[Depends(auth)])
def screenrecord_start(device: Dev, time_limit: int = 180):
    with _record_lock:
        proc = _record_procs.get(device)
        if proc and proc.poll() is None:
            raise HTTPException(409, "already recording")
        _record_procs[device] = subprocess.Popen([ADB, "-s", discover_serial(device), "shell", "screenrecord", "--time-limit", str(min(max(time_limit, 1), 180)),
                                              "--bit-rate", "2000000", _record_path])
    return {"recording": True}


@app.post("/screenrecord/stop", dependencies=[Depends(auth)])
def screenrecord_stop(device: Dev):
    with _record_lock:
        proc = _record_procs.pop(device, None)
    if proc and proc.poll() is None:
        adb("shell", "pkill", "-INT", "screenrecord", device=device)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    time.sleep(1)
    rc, mp4, err = adb("exec-out", "cat", _record_path, device=device, binary=True, timeout=120)
    if rc != 0 or len(mp4) < 100:
        raise HTTPException(500, f"no recording: {err[:300]}")
    return {"mp4_base64": base64.b64encode(mp4).decode(), "bytes": len(mp4)}
