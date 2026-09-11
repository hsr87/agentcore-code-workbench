"""Environment emulator.

Provides three senses of "emulation".
1. EnvironmentEmulator : provisions an EmulatorProfile (runtime, packages, env vars, setup commands) into the sandbox
                         to mimic the target execution environment.
2. MockServiceEmulator : runs a fake HTTP server inside the sandbox that mimics an external API.
3. ReplaySandbox       : (sandbox.py) an offline emulator that replays a recording.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from typing import Any

import yaml

from cwe.models import EmulatorProfile, ExecKind, ExecResult, MockService
from cwe.sandbox import Sandbox

log = logging.getLogger(__name__)

# Tiny mock server planted inside the sandbox. Uses only the standard library so it runs with no dependencies.
_MOCK_SERVER_PY = r'''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROUTES = json.load(open(sys.argv[1]))
PORT = int(sys.argv[2])
LOG = open(sys.argv[3], "a")

class H(BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        key = f"{self.command} {self.path.split('?')[0]}"
        LOG.write(json.dumps({"key": key, "body": body.decode("utf-8", "replace")}) + "\n"); LOG.flush()
        spec = ROUTES.get(key) or ROUTES.get(f"* {self.path.split('?')[0]}")
        if spec is None:
            self.send_response(404); self.end_headers(); self.wfile.write(b'{"error":"no mock route"}'); return
        status = spec.get("status", 200)
        payload = spec.get("body", {})
        data = payload if isinstance(payload, str) else json.dumps(payload)
        self.send_response(status)
        self.send_header("Content-Type", spec.get("content_type", "application/json"))
        self.end_headers()
        self.wfile.write(data.encode())
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''


_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MOCK_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


def load_profile(path: str) -> EmulatorProfile:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) if path.endswith((".yml", ".yaml")) else json.load(f)
    return EmulatorProfile.model_validate(data)


class EnvironmentEmulator:
    """Applies a profile to the sandbox. Each step is returned as an ExecResult and recorded."""

    def __init__(self, sandbox: Sandbox, profile: EmulatorProfile):
        self.sandbox = sandbox
        self.profile = profile
        self.workspace_path: str | None = None

    ENV_FILE = ".cwe/env"   # the profile's env is passed via this file, not the command line (so values don't leak into recordings/transcripts/judge prompts)

    def _env_prefix(self) -> str:
        if not self.profile.env:
            return ""
        return f"set -a && . ./{self.ENV_FILE} && set +a && "

    def _write_env_file(self) -> ExecResult:
        for k in self.profile.env:
            if not _ENV_KEY_RE.fullmatch(k):
                raise ValueError(f"invalid env name {k!r}")
        body = "".join(f"{k}={shlex.quote(v)}\n" for k, v in self.profile.env.items())
        r = self.sandbox.write_files({f"{self.profile.workspace.strip('/')}/{self.ENV_FILE}": body})   # only the path is left in the recording
        r.kind = ExecKind.SETUP
        return r

    def provision(self) -> list[ExecResult]:
        p = self.profile
        steps: list[ExecResult] = []

        # 1) create the working directory and confirm the absolute path (executeCommand's cwd is undocumented, so pin it explicitly)
        r = self.sandbox.execute_command(f"mkdir -p {shlex.quote(p.workspace)}/.cwe && cd {shlex.quote(p.workspace)} && pwd")
        r.kind = ExecKind.SETUP
        steps.append(r)
        self.workspace_path = (r.output.strip().splitlines() or [p.workspace])[-1].strip()
        if p.env:
            steps.append(self._write_env_file())
            r = self.sandbox.execute_command(f"chmod 600 {shlex.quote(self.workspace_path)}/{self.ENV_FILE}"); r.kind = ExecKind.SETUP; steps.append(r)

        # 2) confirm the runtime
        probe = {"python": "python --version", "node": "node --version", "polyglot": "python --version && node --version"}[p.runtime]
        r = self.sandbox.execute_command(probe); r.kind = ExecKind.SETUP; steps.append(r)

        # 3) install packages
        if p.python_packages:
            pkgs = " ".join(shlex.quote(x) for x in p.python_packages)
            r = self.sandbox.execute_command(f"python -m pip install -q {pkgs}"); r.kind = ExecKind.SETUP; steps.append(r)
        if p.node_packages:
            pkgs = " ".join(shlex.quote(x) for x in p.node_packages)
            r = self.sandbox.execute_command(f"cd {shlex.quote(self.workspace_path)} && npm install --silent {pkgs}")
            r.kind = ExecKind.SETUP; steps.append(r)

        # 4) user-defined setup
        for cmd in p.system_setup:
            r = self.sandbox.execute_command(f"cd {shlex.quote(self.workspace_path)} && {self._env_prefix()}{cmd}")
            r.kind = ExecKind.SETUP; steps.append(r)

        # 5) mock services
        if p.mock_services:
            steps.extend(MockServiceEmulator(self.sandbox, self.workspace_path).start_all(p.mock_services))
        return steps

    def wrap_command(self, command: str) -> str:
        """Wraps a user command in the working-directory + profile environment-variable context."""
        ws = shlex.quote(self.workspace_path or self.profile.workspace)
        return f"cd {ws} && {self._env_prefix()}{command}"


class MockServiceEmulator:
    def __init__(self, sandbox: Sandbox, workspace_path: str | None):
        self.sandbox = sandbox
        self.ws = workspace_path or "workspace"
        self.tasks: dict[str, str] = {}

    def start_all(self, services: list[MockService]) -> list[ExecResult]:
        for s in services:   # the name becomes a file name and part of a sandbox command
            if not _MOCK_NAME_RE.fullmatch(s.name):
                raise ValueError(f"invalid mock service name {s.name!r}")
        out: list[ExecResult] = []
        files: dict[str, str | bytes] = {".cwe/mock_server.py": _MOCK_SERVER_PY}
        for s in services:
            files[f".cwe/mock_{s.name}.json"] = json.dumps(s.routes)
        # writeFiles paths are relative to the sandbox root
        w = self.sandbox.write_files(files); w.kind = ExecKind.MOCK_SERVICE; out.append(w)
        for s in services:
            cmd = f"python .cwe/mock_server.py .cwe/mock_{s.name}.json {s.port} .cwe/mock_{s.name}.log"
            r = self.sandbox.start_background(cmd)
            r.kind = ExecKind.MOCK_SERVICE
            if r.task_id:
                self.tasks[s.name] = r.task_id
            out.append(r)
        # wait for readiness (until the port opens)
        for s in services:
            r = self.sandbox.execute_command(
                f"for i in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:{s.port}/ && break || sleep 0.25; done; echo mock:{s.name}:ready"
            )
            r.kind = ExecKind.MOCK_SERVICE; out.append(r)
        return out

    def requests_log(self, name: str) -> list[dict[str, Any]]:
        """List of requests received by the mock service (used in evaluation to verify "did it call the external API correctly")."""
        data = self.sandbox.read_files([f".cwe/mock_{name}.log"]).get(f".cwe/mock_{name}.log", "")
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        return [json.loads(l) for l in data.splitlines() if l.strip()]

    def stop_all(self) -> None:
        for name, tid in self.tasks.items():
            try:
                self.sandbox.stop_task(tid)
            except Exception as e:
                log.warning("stop mock %s failed: %s", name, e)
