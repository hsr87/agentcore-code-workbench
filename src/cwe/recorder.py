"""Execution recording.

Logs every execution event to JSONL, and optionally also loads them into S3 and AgentCore Memory.
- Local/S3 JSONL: input for auditing, the replay emulator, and evaluation
- AgentCore Memory: cross-session long-term memory (e.g. "this repo is tested with pytest -q") the agent can draw on
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import threading
from typing import Any, Iterable

from cwe.models import ExecResult, RunEvent

log = logging.getLogger(__name__)


_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")   # a leading '_' is a reserved namespace (_skills, etc.). Server-generated IDs use the sess_/run_/snap_ prefixes
MAX_RECORDED_OUTPUT = 200_000   # max stdout/stderr length kept per recorded entry (the full output lives in DevSession.full_output)


def validate_key(session_id: str, name: str) -> None:
    """Validates a store key: the session id may only contain alphanumerics and _.- (the first character can't be '.'), and the name must be a relative path with no '..' segments. Keeps an ID coming in through the API from escaping its path."""
    if not _ID_RE.fullmatch(session_id or "") or session_id in (".", ".."):
        raise ValueError(f"invalid session id: {session_id!r}")
    if not name or name.startswith("/") or any(seg in ("", ".", "..") for seg in name.split("/")):
        raise ValueError(f"invalid object name: {name!r}")


def _clip(text: str, limit: int = MAX_RECORDED_OUTPUT) -> str:
    if text is None or len(text) <= limit:
        return text
    return text[: limit // 2] + f"\n... ({len(text) - limit} chars truncated in recording) ...\n" + text[-limit // 2:]


class _LocalStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def path(self, session_id: str, name: str) -> str:
        validate_key(session_id, name)
        return os.path.join(self.root, session_id, name)

    def _writable(self, session_id: str, name: str) -> str:
        p = self.path(session_id, name)   # the read path does not create directories (prevents creating empty directories with arbitrary IDs)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def append_line(self, session_id: str, name: str, line: str) -> None:
        with open(self._writable(session_id, name), "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def put(self, session_id: str, name: str, data: bytes) -> str:
        p = self._writable(session_id, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def get(self, session_id: str, name: str) -> bytes:
        with open(self.path(session_id, name), "rb") as f:
            return f.read()

    def delete(self, session_id: str, name: str) -> None:
        try:
            os.unlink(self.path(session_id, name))
        except FileNotFoundError:
            pass

    def read_lines(self, session_id: str, name: str) -> list[str]:
        p = self.path(session_id, name)
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [l.rstrip("\n") for l in f if l.strip()]


class _S3Store:
    """s3://bucket/prefix. JSONL append is implemented as a full object rewrite (fine at the scale of thousands of events per session)."""

    def __init__(self, uri: str, region: str):
        import boto3
        from botocore.config import Config

        assert uri.startswith("s3://")
        bucket, _, prefix = uri[5:].partition("/")
        self.bucket, self.prefix = bucket, prefix.strip("/")
        # Presigned URLs are handed to Pods in any region. Pin SigV4 and virtual-host addressing so the URL names the
        # bucket's regional endpoint; the default can emit the global endpoint with a regional signature scope, which S3
        # rejects with SignatureDoesNotMatch outside us-east-1.
        self.s3 = boto3.client("s3", region_name=region, config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}))
        self._cache: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def key(self, session_id: str, name: str) -> str:
        validate_key(session_id, name)
        return "/".join(p for p in (self.prefix, session_id, name) if p)

    def append_line(self, session_id: str, name: str, line: str) -> None:
        k = self.key(session_id, name)
        with self._lock:
            lines = self._cache.setdefault(k, self.read_lines(session_id, name))
            lines.append(line)
            self.s3.put_object(Bucket=self.bucket, Key=k, Body=("\n".join(lines) + "\n").encode("utf-8"))

    def evict(self, session_id: str) -> None:
        """Clears the append cache when a session closes (so process memory doesn't grow proportionally to the number of sessions)."""
        with self._lock:
            for k in [k for k in self._cache if k.startswith(self.key(session_id, "x")[:-1])]:
                self._cache.pop(k, None)

    def put(self, session_id: str, name: str, data: bytes) -> str:
        k = self.key(session_id, name)
        self.s3.put_object(Bucket=self.bucket, Key=k, Body=data)
        return f"s3://{self.bucket}/{k}"

    def get(self, session_id: str, name: str) -> bytes:
        return self.s3.get_object(Bucket=self.bucket, Key=self.key(session_id, name))["Body"].read()

    def read_lines(self, session_id: str, name: str) -> list[str]:
        try:
            body = self.get(session_id, name).decode("utf-8")
        except self.s3.exceptions.NoSuchKey:
            return []
        return [l for l in body.splitlines() if l.strip()]


def make_store(uri: str, region: str):
    return _S3Store(uri, region) if uri.startswith("s3://") else _LocalStore(uri)


class Recorder:
    """Event log writer for a single session."""

    EVENTS_FILE = "events.jsonl"

    def __init__(self, session_id: str, store, memory_client=None, memory_id: str | None = None, actor_id: str = "developer"):
        self.session_id = session_id
        self.store = store
        self.memory_client = memory_client
        self.memory_id = memory_id
        self.actor_id = actor_id
        self._seq = len(store.read_lines(session_id, self.EVENTS_FILE))
        self._lock = threading.Lock()

    # -- writing --------------------------------------------------------------
    def _emit(self, event: RunEvent) -> RunEvent:
        line = event.model_dump_json()
        self.store.append_line(self.session_id, self.EVENTS_FILE, line)
        return event

    def record_exec(self, run_id: str, result: ExecResult, actor: str = "user", files: dict[str, str | bytes] | None = None) -> RunEvent:
        payload: dict[str, Any] = {
            "kind": result.kind.value,
            "input": result.input,
            "language": result.language,
            "stdout": _clip(result.stdout),
            "stderr": _clip(result.stderr),
            "exit_code": result.exit_code,
            "is_error": result.is_error,
            "execution_time": result.execution_time,
            "task_id": result.task_id,
            "task_status": result.task_status,
        }
        if files:
            payload["files"] = {
                p: ({"b64": base64.b64encode(d).decode()} if isinstance(d, bytes) else d) for p, d in files.items()
            }
        with self._lock:
            self._seq += 1
            ev = RunEvent(seq=self._seq, session_id=self.session_id, run_id=run_id, event_type="exec", actor=actor, payload=payload)
        return self._emit(ev)

    def record(self, run_id: str, event_type: str, payload: dict[str, Any], actor: str = "system") -> RunEvent:
        with self._lock:
            self._seq += 1
            ev = RunEvent(seq=self._seq, session_id=self.session_id, run_id=run_id, event_type=event_type, actor=actor, payload=payload)  # type: ignore[arg-type]
        ev = self._emit(ev)
        if event_type == "message" and self.memory_client and self.memory_id:
            self._to_memory(payload)
        return ev

    def _to_memory(self, payload: dict[str, Any]) -> None:
        """Stores a conversation/task message as an AgentCore Memory event (auto-extracted if a long-term memory strategy is configured)."""
        role = "USER" if payload.get("role", "user") == "user" else "ASSISTANT"
        try:
            self.memory_client.create_event(
                memory_id=self.memory_id,
                actor_id=self.actor_id,
                session_id=self.session_id,
                messages=[(str(payload.get("text", "")), role)],
            )
        except Exception as e:  # a recording failure must not block execution
            log.warning("memory write failed: %s", e)

    # -- reading --------------------------------------------------------------
    def events(self, run_id: str | None = None) -> list[dict[str, Any]]:
        out = [json.loads(l) for l in self.store.read_lines(self.session_id, self.EVENTS_FILE)]
        if run_id:
            out = [e for e in out if e.get("run_id") == run_id]
        return out

    def transcript(self, run_id: str | None = None, max_chars: int = 20000) -> str:
        """A text transcript readable by the LLM judge or a person."""
        lines: list[str] = []
        for e in self.events(run_id):
            p = e["payload"]
            if e["event_type"] == "exec":
                head = f"[{e['seq']}] {p['kind']} (exit={p.get('exit_code')}, {p.get('execution_time') or 0:.2f}s)"
                lines.append(head)
                if p.get("files"):
                    # include the content of written files so the judge can see the code (max 4000 chars per file)
                    for path, data in p["files"].items():
                        body = "<binary>" if isinstance(data, dict) else strip_ansi(str(data))[:4000]
                        lines.append(f"  --- wrote {path} ---\n" + body.rstrip().replace("\n", "\n  ") if body != "<binary>" else f"  --- wrote {path} (binary) ---")
                else:
                    lines.append("  $ " + strip_ansi(p["input"]).strip().replace("\n", "\n    "))
                out = (p.get("stdout") or "") + (("\n" + p["stderr"]) if p.get("stderr") else "")
                out = strip_ansi(out)
                if out.strip():
                    lines.append("  > " + out.strip().replace("\n", "\n  > "))
            elif e["event_type"] == "message":
                lines.append(f"[{e['seq']}] {p.get('role','user')}: {p.get('text','')}")
            else:
                lines.append(f"[{e['seq']}] {e['event_type']}: {json.dumps(p, ensure_ascii=False)[:300]}")
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = text[: max_chars // 2] + "\n... (truncated) ...\n" + text[-max_chars // 2 :]
        return text


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "").replace("\r\n", "\n")


def load_events(path_or_lines: str | Iterable[str]) -> list[dict[str, Any]]:
    if isinstance(path_or_lines, str):
        with open(path_or_lines, encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]
    return [json.loads(l) for l in path_or_lines if l.strip()]
