"""Pod-local Gradle runner. No Docker/Kubernetes API, credentials or host mounts.

Every container in the Pod shares one network namespace, and the emulator forwards its guest to
the same loopback, so binding to 127.0.0.1 is not an authentication boundary. Requests must carry
BUILD_SIDECAR_TOKEN, which only the device agent receives.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
ROOT = Path("/opt/cwe/builds")
TOKEN = os.environ.get("BUILD_SIDECAR_TOKEN", "")


def authorized(headers) -> bool:
    given = headers.get("Authorization", "") or ""
    return bool(TOKEN) and secrets.compare_digest(given.encode("utf-8", "surrogateescape"),
                                                  f"Bearer {TOKEN}".encode("utf-8"))


def run_build(build_id: str, tasks: list[str], timeout: int) -> dict:
    if not isinstance(build_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", build_id):
        raise ValueError("invalid build_id")
    if not isinstance(tasks, list) or not tasks or len(tasks) > 50 or not all(
        isinstance(t, str) and re.fullmatch(r"[A-Za-z0-9_:.-]{1,80}", t) and not t.startswith("-") for t in tasks
    ):
        raise ValueError("invalid tasks")
    if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ValueError("timeout must be 1..3600")
    work = (ROOT / build_id).resolve()
    if work.parent != ROOT.resolve() or not (work / "gradlew").is_file():
        raise ValueError("build workspace or gradlew missing")
    if not (work / "gradlew").resolve().is_relative_to(work):
        raise ValueError("gradlew must remain inside workspace")
    # Build scripts get SDK paths, but no inherited credentials.
    env = {k: os.environ[k] for k in ("PATH", "JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "LANG") if k in os.environ}
    env.update(HOME="/tmp", GRADLE_USER_HOME="/opt/cwe/gradle", GRADLE_OPTS="-Dorg.gradle.daemon=false")
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(["sh", "./gradlew", "--no-daemon", "-q", *tasks], cwd=work, env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            code = 124
        finally:
            # Also kill children left behind by a successful Gradle invocation.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        output.seek(0, os.SEEK_END)
        output.seek(max(0, output.tell() - 6000))
        return {"exit_code": code, "log_tail": output.read().decode("utf-8", "replace")}


class Handler(BaseHTTPRequestHandler):
    timeout = 30            # a peer that opens a socket must not hold a thread forever
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        try:
            if not authorized(self.headers):
                self.send_error(401, "unauthorized")
                return
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/build" or not 0 < size <= 16384:
                raise ValueError("invalid request")
            body = json.loads(self.rfile.read(size))
            if not LOCK.acquire(blocking=False):
                self.send_error(409, "build already running")
                return
            try:
                result = run_build(body["build_id"], body["tasks"], body["timeout"])
            finally:
                LOCK.release()
            payload = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (ValueError, KeyError, TypeError):
            self.send_error(400, "invalid build request")
        except Exception:
            self.send_error(500, "build runner failed")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("BUILD_SIDECAR_TOKEN is required (refusing to start unauthenticated)")
    ThreadingHTTPServer(("127.0.0.1", 9090), Handler).serve_forever()
