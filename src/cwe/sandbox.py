"""Sandbox abstraction.

- AgentCoreSandbox: runs for real on Amazon Bedrock AgentCore Code Interpreter
- ReplaySandbox : an offline emulator that replays a recording (JSONL) (no AWS needed, for tests/CI/demos)
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any, Protocol

from cwe.models import ExecKind, ExecResult, utcnow

log = logging.getLogger(__name__)


class Sandbox(Protocol):
    session_id: str | None

    def start(self) -> str: ...
    def stop(self) -> None: ...
    def execute_code(self, code: str, language: str = "python", clear_context: bool = False) -> ExecResult: ...
    def execute_command(self, command: str) -> ExecResult: ...
    def start_background(self, command: str) -> ExecResult: ...
    def get_task(self, task_id: str) -> ExecResult: ...
    def stop_task(self, task_id: str) -> ExecResult: ...
    def write_files(self, files: dict[str, str | bytes]) -> ExecResult: ...
    def read_files(self, paths: list[str]) -> dict[str, str | bytes]: ...
    def list_files(self, path: str = "") -> list[dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# Result normalization
# ---------------------------------------------------------------------------
def _collect_result(response: dict[str, Any]) -> dict[str, Any]:
    """Pull the last result event out of invoke_code_interpreter's EventStream."""
    result: dict[str, Any] = {}
    stream = response.get("stream")
    if stream is None:
        return response.get("result", response)
    for event in stream:
        if "result" in event:
            result = event["result"]
    return result


def normalize(kind: ExecKind, inp: str, result: dict[str, Any], language: str | None = None, started_at=None) -> ExecResult:
    sc = result.get("structuredContent") or {}
    text_parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    stdout = sc.get("stdout") or ""
    stderr = sc.get("stderr") or ""
    if not stdout and not stderr and text_parts:
        stdout = "\n".join(text_parts)
    return ExecResult(
        kind=kind,
        input=inp,
        language=language,
        stdout=stdout,
        stderr=stderr,
        exit_code=sc.get("exitCode"),
        is_error=bool(result.get("isError", False)),
        execution_time=sc.get("executionTime"),
        task_id=sc.get("taskId"),
        task_status=sc.get("taskStatus"),
        started_at=started_at or utcnow(),
        finished_at=utcnow(),
        raw=result,
    )


# ---------------------------------------------------------------------------
# AgentCore Code Interpreter
# ---------------------------------------------------------------------------
class AgentCoreSandbox:
    """A thin wrapper around bedrock_agentcore.tools.code_interpreter_client.CodeInterpreter.

    Sandbox spec (as of 2026-09, managed aws.codeinterpreter.v1):
      Linux aarch64, 2 vCPU, 8 GB RAM, ~9 GB disk, Python 3.12, Node 24, gcc. No Docker.
    """

    def __init__(self, region: str, identifier: str = "aws.codeinterpreter.v1", timeout_seconds: int = 1800):
        from bedrock_agentcore.tools.code_interpreter_client import CodeInterpreter

        self._client = CodeInterpreter(region)
        self._identifier = identifier
        self._timeout = timeout_seconds
        self.session_id: str | None = None
        self.trace_parent: str | None = None   # W3C traceparent; when set, passed on every call (for AgentCore Observability correlation)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> str:
        self.session_id = self._client.start(identifier=self._identifier, session_timeout_seconds=self._timeout)
        log.info("sandbox started: %s", self.session_id)
        return self.session_id

    def stop(self) -> None:
        try:
            self._client.stop()
        finally:
            self.session_id = None

    def attach(self, session_id: str) -> str:
        """Adopt a session another process started (sticky sessions across Runtime microVM replacement).
        Verified against the service first, so a session that timed out is reported instead of failing on the first command."""
        status = self._client.data_plane_client.get_code_interpreter_session(
            codeInterpreterIdentifier=self._identifier, sessionId=session_id).get("status")
        if status != "READY":
            raise RuntimeError(f"code interpreter session {session_id} is {status or 'gone'}")
        self._client.identifier = self._identifier
        self._client.session_id = session_id
        self.session_id = session_id
        log.info("sandbox attached: %s", session_id)
        return session_id

    def _invoke(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.trace_parent:
            return _collect_result(self._client.invoke(method, params))
        if not self._client.session_id:
            self._client.start(identifier=self._identifier, session_timeout_seconds=self._timeout)
        resp = self._client.data_plane_client.invoke_code_interpreter(
            codeInterpreterIdentifier=self._client.identifier, sessionId=self._client.session_id,
            name=method, arguments=params or {}, traceParent=self.trace_parent, traceId=self.trace_parent.split("-")[1],
        )
        return _collect_result(resp)

    # -- execution ----------------------------------------------------------
    def execute_code(self, code: str, language: str = "python", clear_context: bool = False) -> ExecResult:
        started = utcnow()
        res = self._invoke("executeCode", {"code": code, "language": language, "clearContext": clear_context})
        return normalize(ExecKind.CODE, code, res, language=language, started_at=started)

    def execute_command(self, command: str) -> ExecResult:
        started = utcnow()
        res = self._invoke("executeCommand", {"command": command})
        return normalize(ExecKind.COMMAND, command, res, started_at=started)

    def start_background(self, command: str) -> ExecResult:
        started = utcnow()
        res = self._invoke("startCommandExecution", {"command": command})
        return normalize(ExecKind.BACKGROUND, command, res, started_at=started)

    def get_task(self, task_id: str) -> ExecResult:
        res = self._invoke("getTask", {"taskId": task_id})
        r = normalize(ExecKind.BACKGROUND, f"getTask:{task_id}", res)
        r.task_id = r.task_id or task_id
        return r

    def stop_task(self, task_id: str) -> ExecResult:
        res = self._invoke("stopTask", {"taskId": task_id})
        return normalize(ExecKind.BACKGROUND, f"stopTask:{task_id}", res)

    def wait_task(self, task_id: str, timeout: float = 300, interval: float = 2.0) -> ExecResult:
        deadline = time.time() + timeout
        last: ExecResult | None = None
        while time.time() < deadline:
            last = self.get_task(task_id)
            if last.task_status in {"completed", "failed", "stopped", "error"}:
                return last
            time.sleep(interval)
        assert last is not None
        last.task_status = last.task_status or "timeout"
        return last

    # -- files ----------------------------------------------------------------
    def write_files(self, files: dict[str, str | bytes]) -> ExecResult:
        content = []
        for path, data in files.items():
            if path.startswith("/"):
                raise ValueError(f"path must be relative to sandbox root: {path}")
            entry: dict[str, Any] = {"path": path}
            if isinstance(data, bytes):
                entry["blob"] = data
            else:
                entry["text"] = data
            content.append(entry)
        res = self._invoke("writeFiles", {"content": content})
        return normalize(ExecKind.FILE_WRITE, ",".join(files.keys()), res)

    def read_files(self, paths: list[str]) -> dict[str, str | bytes]:
        # readFiles returns the uri as file:///path, so even after the SDK strips it a leading "/" remains -> normalize to the requested relative path
        raw = self._client.download_files(paths)
        return {k.lstrip("/"): v for k, v in raw.items()}

    def list_files(self, path: str = "") -> list[dict[str, Any]]:
        res = self._invoke("listFiles", {"path": path})
        out = []
        for c in res.get("content", []):
            if c.get("type") == "resource_link":
                out.append({"name": c.get("name"), "uri": c.get("uri"), "is_dir": c.get("description") == "Directory", "mime": c.get("mimeType")})
        return out


# ---------------------------------------------------------------------------
# Replay emulator (offline)
# ---------------------------------------------------------------------------
class ReplaySandbox:
    """Replays a recorded execution (JSONL).

    Given the same input (code/command), it returns the recorded output as-is,
    so workflow and evaluation logic can be reproduced deterministically without AWS.
    If strict=True, an input with no recording raises an exception.
    """

    def __init__(self, events: list[dict[str, Any]], strict: bool = True):
        # the session records under kind=setup/mock_service too, so match on the input string alone
        self._by_input: dict[str, list[dict[str, Any]]] = {}
        self._files: dict[str, str | bytes] = {}
        self.strict = strict
        self.session_id: str | None = None
        for ev in events:
            if ev.get("event_type") != "exec":
                continue
            p = ev["payload"]
            self._by_input.setdefault(p.get("input", ""), []).append(p)
            if p.get("kind") == ExecKind.FILE_WRITE.value:
                for path, data in (p.get("files") or {}).items():
                    self._files[path] = base64.b64decode(data["b64"]) if isinstance(data, dict) and "b64" in data else data
        self._cursor: dict[str, int] = {}

    @classmethod
    def from_jsonl(cls, path: str, strict: bool = True) -> "ReplaySandbox":
        with open(path, encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]
        return cls(events, strict=strict)

    def start(self) -> str:
        self.session_id = "replay"
        return self.session_id

    def attach(self, session_id: str) -> str:
        self.session_id = session_id
        return session_id

    def stop(self) -> None:
        self.session_id = None

    def _replay(self, kind: ExecKind, inp: str, **extra) -> ExecResult:
        key = inp
        seq = self._by_input.get(key)
        if not seq:
            if self.strict:
                raise LookupError(f"no recording for {kind.value}: {inp[:80]!r}")
            return ExecResult(kind=kind, input=inp, stdout="", exit_code=0, finished_at=utcnow(), **extra)
        i = self._cursor.get(key, 0)
        p = seq[min(i, len(seq) - 1)]
        self._cursor[key] = i + 1
        return ExecResult(
            kind=kind, input=inp, language=p.get("language"),
            stdout=p.get("stdout", ""), stderr=p.get("stderr", ""),
            exit_code=p.get("exit_code"), is_error=p.get("is_error", False),
            execution_time=p.get("execution_time"), task_id=p.get("task_id"),
            task_status=p.get("task_status"), finished_at=utcnow(),
        )

    def execute_code(self, code: str, language: str = "python", clear_context: bool = False) -> ExecResult:
        return self._replay(ExecKind.CODE, code, language=language)

    def execute_command(self, command: str) -> ExecResult:
        return self._replay(ExecKind.COMMAND, command)

    def start_background(self, command: str) -> ExecResult:
        return self._replay(ExecKind.BACKGROUND, command)

    def get_task(self, task_id: str) -> ExecResult:
        return self._replay(ExecKind.BACKGROUND, f"getTask:{task_id}")

    def stop_task(self, task_id: str) -> ExecResult:
        return self._replay(ExecKind.BACKGROUND, f"stopTask:{task_id}")

    def wait_task(self, task_id: str, timeout: float = 300, interval: float = 0) -> ExecResult:
        return self.get_task(task_id)

    def write_files(self, files: dict[str, str | bytes]) -> ExecResult:
        self._files.update(files)
        return ExecResult(kind=ExecKind.FILE_WRITE, input=",".join(files), stdout=f"Successfully wrote all {len(files)} files", exit_code=0, finished_at=utcnow())

    def read_files(self, paths: list[str]) -> dict[str, str | bytes]:
        return {p: self._files[p] for p in paths if p in self._files}

    def list_files(self, path: str = "") -> list[dict[str, Any]]:
        prefix = path.rstrip("/") + "/" if path else ""
        return [{"name": p[len(prefix):], "uri": f"file:///{p}", "is_dir": False, "mime": None}
                for p in self._files if p.startswith(prefix)]


class FakeSandbox(ReplaySandbox):
    """For tests: mimics execution even with no recording (just echo commands and simple prints)."""

    def __init__(self):
        super().__init__([], strict=False)

    def execute_command(self, command: str) -> ExecResult:
        # ignore the "cd <ws> && export ... && " prefix the session attaches, and mimic only the last command
        last = command.split("&&")[-1].strip()
        if last.startswith("echo "):
            return ExecResult(kind=ExecKind.COMMAND, input=command, stdout=last[5:].strip("'\"") + "\n", exit_code=0, finished_at=utcnow())
        if last.startswith("exit ") and last != "exit 0":
            return ExecResult(kind=ExecKind.COMMAND, input=command, stderr="failed", exit_code=int(last.split()[1]), is_error=True, finished_at=utcnow())
        if last == "pwd":
            return ExecResult(kind=ExecKind.COMMAND, input=command, stdout="/fake/workspace\n", exit_code=0, finished_at=utcnow())
        return super().execute_command(command)
