"""Workload agent: a small HTTP control plane inside a heavy build/run Pod.

The Code Interpreter microVM has fixed memory and disk. Anything that does not fit there (a
Gradle build of a large Java service, running that service for an integration test) runs in an
EKS Pod whose toolchain image contains this file. The agent on AgentCore Runtime talks to it
over HTTP; nothing here knows about Kubernetes, AWS or the model.

Standard library only, so it can be dropped into any toolchain image that has python3.

Security rules
- WORKLOAD_AGENT_TOKEN is required; without it the process refuses to start. Comparisons are
  constant time. WORKLOAD_AGENT_SESSION, when set, must match the x-cwe-session header.
- Paths are confined to WORKLOAD_WORK. Downloads are HTTPS-only and re-checked after every
  redirect against private, loopback and link-local addresses. Archives are extracted with a
  filter that rejects path escapes.
- Commands run as this process's user inside the Pod. The Pod is one trust domain per session:
  the customer's own build scripts run here, so this is isolation from the cluster, not from
  the code being built.
- /exec accepts an optional request_id. A retry that carries the same request_id and the same
  command joins the running command or gets its stored result instead of running the build a
  second time; the same request_id with a different command is refused.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = os.environ.get("WORKLOAD_AGENT_TOKEN", "")
SESSION = os.environ.get("WORKLOAD_AGENT_SESSION", "")
WORK = os.path.realpath(os.environ.get("WORKLOAD_WORK", "/opt/cwe/work"))
LOGS = os.path.join(os.path.dirname(WORK), "logs")
HOST = os.environ.get("WORKLOAD_AGENT_HOST", "0.0.0.0")
PORT = int(os.environ.get("WORKLOAD_AGENT_PORT", "8080"))
MAX_BODY = 16 * 1024 * 1024
MAX_OUTPUT = 200_000
MAX_DOWNLOAD_BYTES = int(os.environ.get("MAX_DOWNLOAD_BYTES", str(2 * 1024 * 1024 * 1024)))
MAX_EXTRACT_BYTES = int(os.environ.get("MAX_EXTRACT_BYTES", str(20 * 1024 * 1024 * 1024)))
MAX_EXEC_TIMEOUT = 4 * 3600
MAX_REQUESTS = 256
_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,40}")
_REQUEST_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
_STARTED = time.time()


class Bad(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _eq(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape"))


def under_work(rel: str) -> str:
    """Resolve a workspace-relative path and refuse anything that escapes WORK."""
    if not isinstance(rel, str) or rel.startswith("/") or any(seg in ("..",) for seg in rel.split("/")):
        raise Bad(400, "path must be relative to the workspace and contain no '..'")
    real = os.path.realpath(os.path.join(WORK, rel))
    if real != WORK and not real.startswith(WORK + os.sep):
        raise Bad(400, "path escapes the workspace")
    return real


def _tail(path: str, limit: int) -> str:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - limit))
        data = f.read()
    text = data.decode("utf-8", "replace")
    return ("...[truncated]\n" + text) if size > limit else text


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("WORKLOAD_AGENT_")}
    env.setdefault("HOME", "/tmp")
    return env


# ---------------------------------------------------------------------------
# Synchronous commands
# ---------------------------------------------------------------------------
def _exec_once(cmd: str, timeout: int, cwd: str, max_output: int) -> dict:
    workdir = under_work(cwd)
    os.makedirs(workdir, exist_ok=True)
    started = time.monotonic()
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["/bin/sh", "-lc", cmd], cwd=workdir, env=_env(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            code, timed_out = 124, True
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)   # children a successful command leaves behind
            except ProcessLookupError:
                pass
            process.wait()
        output.seek(0, os.SEEK_END)
        size = output.tell()
        output.seek(max(0, size - max_output))
        text = output.read().decode("utf-8", "replace")
    if size > max_output:
        text = f"...[{size - max_output} bytes omitted]\n" + text
    return {"exit_code": code, "output": text, "seconds": round(time.monotonic() - started, 2), "timed_out": timed_out}


# request_id -> {"fingerprint", "done": Event, "result" | "error", "created"}; a retry after a dropped
# connection joins the command that is already running instead of starting it again.
_requests: dict[str, dict] = {}
_requests_lock = threading.Lock()


def _claim_request(request_id: str, fingerprint: str) -> tuple[dict, bool]:
    with _requests_lock:
        entry = _requests.get(request_id)
        if entry is not None:
            if entry["fingerprint"] != fingerprint:
                raise Bad(409, "request_id already used for a different command")
            return entry, False
        if len(_requests) >= MAX_REQUESTS:
            finished = sorted((k for k, v in _requests.items() if v["done"].is_set()), key=lambda k: _requests[k]["created"])
            for key in finished[: max(1, len(finished) // 4)]:
                _requests.pop(key, None)
            if len(_requests) >= MAX_REQUESTS:
                raise Bad(429, "too many commands in flight")
        entry = {"fingerprint": fingerprint, "done": threading.Event(), "result": None, "error": None, "created": time.monotonic()}
        _requests[request_id] = entry
        return entry, True


def run_exec(cmd: str, timeout: int, cwd: str = ".", max_output: int = 20_000, request_id: str | None = None) -> dict:
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 100_000:
        raise Bad(400, "cmd must be a non-empty string")
    if not isinstance(timeout, int) or not 1 <= timeout <= MAX_EXEC_TIMEOUT:
        raise Bad(400, f"timeout must be 1..{MAX_EXEC_TIMEOUT}")
    max_output = max(200, min(int(max_output), MAX_OUTPUT))
    if request_id is None:
        return _exec_once(cmd, timeout, cwd, max_output)
    if not isinstance(request_id, str) or not _REQUEST_RE.fullmatch(request_id):
        raise Bad(400, "request_id must match [A-Za-z0-9_-]{8,64}")
    fingerprint = hashlib.sha256(json.dumps([cmd, cwd, timeout, max_output]).encode()).hexdigest()
    entry, owner = _claim_request(request_id, fingerprint)
    if owner:
        try:
            entry["result"] = _exec_once(cmd, timeout, cwd, max_output)
        except BaseException as e:   # noqa: BLE001  the retry must see the same failure, not run the command again
            entry["error"] = e
            raise
        finally:
            entry["done"].set()
        return entry["result"]
    if not entry["done"].wait(timeout + 30):
        raise Bad(504, "the original request is still running; retry later with the same request_id")
    if entry["error"] is not None:
        raise entry["error"]
    return {**entry["result"], "deduplicated": True}


# ---------------------------------------------------------------------------
# Background processes (a service under test, a long build)
# ---------------------------------------------------------------------------
_procs: dict[str, dict] = {}
_procs_lock = threading.Lock()


def _check_name(name) -> str:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise Bad(400, "name must match [A-Za-z0-9_-]{1,40}")
    return name


def start_proc(name: str, cmd: str, cwd: str = ".") -> dict:
    name = _check_name(name)
    if not isinstance(cmd, str) or not cmd.strip():
        raise Bad(400, "cmd must be a non-empty string")
    workdir = under_work(cwd)
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)
    log_path = os.path.join(LOGS, f"{name}.log")
    with _procs_lock:
        existing = _procs.get(name)
        if existing and existing["process"].poll() is None:
            raise Bad(409, f"process {name} is already running")
        log = open(log_path, "ab")
        process = subprocess.Popen(["/bin/sh", "-lc", cmd], cwd=workdir, env=_env(), stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        log.close()
        _procs[name] = {"process": process, "cmd": cmd, "started_at": time.time(), "log": log_path}
    return {"name": name, "pid": process.pid, "log": log_path}


def stop_proc(name: str, grace: float = 5.0) -> dict:
    name = _check_name(name)
    with _procs_lock:
        entry = _procs.get(name)
    if not entry:
        raise Bad(404, f"no process named {name}")
    process = entry["process"]
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return {"name": name, "exit_code": process.returncode}


def proc_logs(name: str, tail: int = 4000) -> dict:
    name = _check_name(name)
    with _procs_lock:
        entry = _procs.get(name)
    if not entry:
        raise Bad(404, f"no process named {name}")
    tail = max(100, min(int(tail), MAX_OUTPUT))
    running = entry["process"].poll() is None
    text = _tail(entry["log"], tail) if os.path.exists(entry["log"]) else ""
    return {"name": name, "running": running, "exit_code": entry["process"].returncode, "log": text}


def list_procs() -> list[dict]:
    with _procs_lock:
        return [{"name": n, "cmd": e["cmd"][:200], "running": e["process"].poll() is None, "exit_code": e["process"].returncode,
                 "started_at": e["started_at"]} for n, e in _procs.items()]


# ---------------------------------------------------------------------------
# Files: write, read, fetch a source archive
# ---------------------------------------------------------------------------
def write_files(files: dict) -> dict:
    if not isinstance(files, dict) or not files:
        raise Bad(400, "files must be a non-empty object of path -> base64 content")
    written = []
    for rel, b64 in files.items():
        path = under_work(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(base64.b64decode(b64))
        written.append(rel)
    return {"written": written}


def read_file(rel: str, max_bytes: int = 200_000) -> dict:
    path = under_work(rel)
    if not os.path.isfile(path):
        raise Bad(404, f"{rel} not found")
    max_bytes = max(1, min(int(max_bytes), 8 * 1024 * 1024))
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(max_bytes)
    return {"path": rel, "size": size, "truncated": size > max_bytes, "content_b64": base64.b64encode(data).decode()}


def _check_public_https(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise Bad(400, "url must be https")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except OSError:
        raise Bad(400, "url host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise Bad(400, "url resolves to a non-public address")


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_public_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, dst: str) -> int:
    _check_public_https(url)
    opener = urllib.request.build_opener(_CheckedRedirect)
    deadline = time.monotonic() + 1800
    n = 0
    with opener.open(url, timeout=120) as r, open(dst, "wb") as f:   # noqa: S310 (checked https only)
        while chunk := r.read(1 << 20):
            n += len(chunk)
            if n > MAX_DOWNLOAD_BYTES:
                raise Bad(413, f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
            if time.monotonic() > deadline:
                raise Bad(504, "download exceeded its time budget")
            f.write(chunk)
    return n


def _safe_extract(src: str, dest: str) -> int:
    """Extract a tar.gz under dest. Every member is checked against the destination before anything is written."""
    count = 0
    total = 0
    dest_real = os.path.realpath(dest)
    with tarfile.open(src) as t:
        members = []
        for m in t:
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                raise Bad(413, "archive too large")
            if m.isdev():
                raise Bad(400, "archive contains a device node")
            target = os.path.realpath(os.path.join(dest_real, m.name))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise Bad(400, f"archive member escapes the destination: {m.name}")
            if m.issym() or m.islnk():
                link = os.path.realpath(os.path.join(os.path.dirname(target), m.linkname)) if m.issym() else os.path.realpath(os.path.join(dest_real, m.linkname))
                if not link.startswith(dest_real + os.sep):
                    raise Bad(400, f"archive link points outside the destination: {m.name}")
            members.append(m)
        kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        t.extractall(dest_real, members=members, **kwargs)
        count = len(members)
    return count


def fetch(url: str, dest: str = ".", extract: bool = True, clean: bool = False) -> dict:
    if not isinstance(url, str):
        raise Bad(400, "url is required")
    target = under_work(dest)
    if clean and os.path.isdir(target) and target != WORK:
        shutil.rmtree(target)
    os.makedirs(target if extract else os.path.dirname(target), exist_ok=True)
    started = time.monotonic()
    if extract:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            archive = tmp.name
        try:
            size = _download(url, archive)
            files = _safe_extract(archive, target)
        finally:
            os.unlink(archive)
        return {"bytes": size, "files": files, "dest": dest, "seconds": round(time.monotonic() - started, 2)}
    size = _download(url, target)
    return {"bytes": size, "dest": dest, "seconds": round(time.monotonic() - started, 2)}


# ---------------------------------------------------------------------------
# Probe a service the Pod is running (the network policy only admits port 8080 from outside)
# ---------------------------------------------------------------------------
def probe(port: int, path: str = "/", method: str = "GET", body: str | None = None, headers: dict | None = None,
          timeout: float = 30.0, max_bytes: int = 20_000) -> dict:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise Bad(400, "port must be 1..65535")
    if not isinstance(path, str) or not path.startswith("/"):
        raise Bad(400, "path must start with /")
    method = str(method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        raise Bad(400, "unsupported method")
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    data = body.encode("utf-8") if isinstance(body, str) else None
    if data is not None and "content-type" not in {k.lower() for k in hdrs}:
        hdrs["Content-Type"] = "application/json"
    started = time.monotonic()
    conn = HTTPConnection("127.0.0.1", port, timeout=float(timeout))
    try:
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read(int(max_bytes) + 1)
        return {"status": resp.status, "headers": dict(resp.getheaders()), "body": payload[:int(max_bytes)].decode("utf-8", "replace"),
                "truncated": len(payload) > int(max_bytes), "seconds": round(time.monotonic() - started, 3)}
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return {"status": 0, "error": f"{type(e).__name__}: {e}", "seconds": round(time.monotonic() - started, 3)}
    finally:
        conn.close()


def health() -> dict:
    usage = shutil.disk_usage(WORK) if os.path.isdir(WORK) else None
    mem = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in ("MemTotal", "MemAvailable"):
                    mem[key] = int(rest.split()[0]) * 1024
    except OSError:
        pass
    return {"ok": True, "work": WORK, "uptime_seconds": round(time.time() - _STARTED, 1), "cpus": os.cpu_count(),
            "disk_free_bytes": usage.free if usage else None, "disk_total_bytes": usage.total if usage else None,
            "mem_total_bytes": mem.get("MemTotal"), "mem_available_bytes": mem.get("MemAvailable"), "procs": list_procs()}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def dispatch(method: str, path: str, query: dict, body: dict) -> dict:
    if method == "GET" and path == "/health":
        return health()
    if method == "POST" and path == "/exec":
        return run_exec(body.get("cmd"), int(body.get("timeout") or 600), body.get("cwd") or ".", int(body.get("max_output") or 20_000),
                        body.get("request_id"))
    if method == "POST" and path == "/start":
        return start_proc(body.get("name"), body.get("cmd"), body.get("cwd") or ".")
    if method == "POST" and path == "/stop":
        return stop_proc(body.get("name"))
    if method == "GET" and path == "/logs":
        return proc_logs(query.get("name", [""])[0], int(query.get("tail", ["4000"])[0]))
    if method == "GET" and path == "/procs":
        return {"procs": list_procs()}
    if method == "POST" and path == "/files":
        return write_files(body.get("files"))
    if method == "GET" and path == "/file":
        return read_file(query.get("path", [""])[0], int(query.get("max_bytes", ["200000"])[0]))
    if method == "POST" and path == "/fetch":
        return fetch(body.get("url"), body.get("dest") or ".", bool(body.get("extract", True)), bool(body.get("clean", False)))
    if method == "POST" and path == "/probe":
        return probe(body.get("port"), body.get("path") or "/", body.get("method") or "GET", body.get("body"),
                     body.get("headers"), float(body.get("timeout") or 30), int(body.get("max_bytes") or 20_000))
    raise Bad(404, "no such route")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def log_message(self, *args):   # tokens travel in headers; keep the default request log quiet
        pass

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        given = self.headers.get("Authorization", "") or ""
        if not TOKEN or not _eq(given, f"Bearer {TOKEN}"):
            return False
        if SESSION and not _eq(self.headers.get("x-cwe-session", "") or "", SESSION):
            raise Bad(403, "session mismatch")
        return True

    def _handle(self, method: str) -> None:
        parts = urlsplit(self.path)
        if method == "GET" and parts.path == "/healthz":
            self._send(200, {"ok": True})
            return
        try:
            if not self._authorized():
                self._send(401, {"error": "bad token"})
                return
            size = int(self.headers.get("Content-Length") or 0)
            if size > MAX_BODY:
                self._send(413, {"error": "body too large"})
                return
            body = json.loads(self.rfile.read(size) or b"{}") if method == "POST" else {}
            if not isinstance(body, dict):
                raise Bad(400, "body must be a JSON object")
            self._send(200, dispatch(method, parts.path, parse_qs(parts.query), body))
        except Bad as e:
            self._send(e.status, {"error": str(e)})
        except (ValueError, KeyError, TypeError) as e:
            self._send(400, {"error": f"invalid request: {type(e).__name__}"})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"agent failure: {type(e).__name__}"})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def serve(host: str = HOST, port: int = PORT) -> ThreadingHTTPServer:
    os.makedirs(WORK, exist_ok=True)
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("WORKLOAD_AGENT_TOKEN is required (refusing to start unauthenticated)")
    serve().serve_forever()
