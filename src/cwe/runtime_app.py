"""AgentCore Runtime entry point.

One runtime session (runtimeSessionId) maps to one DevSession. The Runtime pins a runtimeSessionId to a
microVM, but replaces that microVM after the idle timeout or maximum lifetime; the session registry
(cwe.registry) records the Code Interpreter session and the EKS Pods so the next microVM reattaches to
them instead of starting over. With the DynamoDB registry every invocation also holds a conditional lease
on the runtime session, so two cold processes serving the same runtimeSessionId cannot each create an
environment; requests for one runtime session are serialized within a process as well. Example payloads:
  {"action": "exec", "type": "command", "input": "pytest -q"}
  {"action": "task", "text": "Add input validation to app.py and make tests pass"}
  {"action": "workload", "profile": {"memory": "24Gi", "ephemeral_storage": "100Gi"}}
  {"action": "remote", "type": "exec", "input": "./gradlew build", "timeout": 1800}
  {"action": "evaluate", "criteria": {...}, "task": "..."}
  {"action": "snapshot"} / {"action": "events"} / {"action": "status"} / {"action": "close"}
"""

from __future__ import annotations

import atexit
import logging
import secrets
import threading
import time
from contextlib import contextmanager
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from cwe.models import EmulatorProfile, EvalCriteria
from cwe.registry import make_registry
from cwe.session import SessionManager

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
app = BedrockAgentCoreApp()
manager = SessionManager()
registry = make_registry(manager.settings, manager.store)
_by_runtime_session: dict[str, str] = {}
_locks_guard = threading.Lock()
_session_locks: dict[str, list] = {}   # rid -> [RLock, waiters]
_FALLBACK_RUNTIME_SESSION = f"local-{secrets.token_hex(8)}"   # one private slot per process, never a shared "default"
_PROCESS = {"id": secrets.token_hex(4), "started_at": time.time()}   # changes when the microVM is replaced; `status` reports it
# On exit keep sandboxes and Pods: the registry points at them and the next microVM reattaches. Code Interpreter
# idle timeouts and Job deadlines reclaim whatever no session comes back for (see cwe reap).
atexit.register(manager.detach_all)


def _runtime_session_id(context) -> str:
    """Isolation is per runtimeSessionId. The payload must never be able to name someone else's session."""
    return getattr(context, "session_id", None) or _FALLBACK_RUNTIME_SESSION


@contextmanager
def _serialized(rid: str):
    """Serialize every call for one runtime session inside this process, including its first creation.

    Waiters keep the lock entry alive until the last of them leaves; unrelated runtime sessions proceed concurrently.
    """
    with _locks_guard:
        entry = _session_locks.setdefault(rid, [threading.RLock(), 0])
        entry[1] += 1
    try:
        with entry[0]:
            yield
    finally:
        with _locks_guard:
            entry[1] -= 1
            if not entry[1]:
                _session_locks.pop(rid, None)


def _remember(rid: str, sess, lease=None, created: bool = False) -> None:
    """Write the registry record. Under a lease a failed write is an error: the next microVM could not find the Pod."""
    if sess.info.status == "closed":
        return
    _by_runtime_session[rid] = sess.info.session_id
    try:
        registry.put(rid, sess.registry_record(rid), ttl_seconds=manager.settings.session_registry_ttl_seconds)
    except Exception as e:  # noqa: BLE001
        if lease is not None and lease.authoritative:
            _by_runtime_session.pop(rid, None)
            if created:   # nothing else knows about this session yet: do not leave its sandbox and Pod behind
                try:
                    manager.close(sess.info.session_id)
                except Exception as close_error:  # noqa: BLE001
                    log.warning("close after registry failure for %s failed: %s", sess.info.session_id, close_error)
            raise RuntimeError("session registry write failed; refusing to continue without a durable record") from e
        log.warning("session registry write failed for %s: %s", sess.info.session_id, e)   # the session still works for this microVM's lifetime


def _forget_local(rid: str) -> None:
    """Drop this process's view of a runtime session without touching the sandbox or Pods."""
    sid = _by_runtime_session.pop(rid, None)
    if sid:
        manager.detach(sid)


def _session(context, payload: dict[str, Any], lease=None):
    rid = _runtime_session_id(context)
    record = None
    if lease is not None and lease.authoritative:
        # Another process may have served the previous call. The record read under the lease is the truth;
        # this process's cache is only valid if it names the same session.
        record = lease.record
        cached = _by_runtime_session.get(rid)
        if cached and record and record.get("session_id") == cached:
            try:
                return manager.get(cached)
            except KeyError:
                _by_runtime_session.pop(rid, None)
        elif cached:
            _forget_local(rid)
    elif rid in _by_runtime_session:
        return manager.get(_by_runtime_session[rid])
    else:
        try:
            record = registry.get(rid)
        except Exception as e:  # noqa: BLE001
            log.warning("session registry read failed: %s", e)
    if record:
        try:
            sess = manager.attach(record)
            sess._lease_guard = lease.check if lease is not None else None
            _by_runtime_session[rid] = sess.info.session_id
            log.info("reattached %s to sandbox %s and %d host(s)", sess.info.session_id, record.get("sandbox_session_id"), len(record.get("hosts") or []))
            _remember(rid, sess, lease)   # refresh the TTL and drop hosts that did not come back
            return sess
        except Exception as e:  # noqa: BLE001
            log.warning("reattach of %s failed (%s); starting a fresh session", record.get("session_id"), e)
            try:
                registry.delete(rid)
            except Exception:  # noqa: BLE001
                pass
    profile = EmulatorProfile.model_validate(payload["profile"]) if payload.get("profile") and payload.get("action") != "workload" else None
    sess = manager.create(profile=profile, tags={"runtime_session_id": rid})
    sess._lease_guard = lease.check if lease is not None else None
    _remember(rid, sess, lease, created=True)
    return sess


def _status(sess) -> dict[str, Any]:
    hosts = sess.registry_record("")["hosts"]
    return {"session_id": sess.info.session_id, "status": sess.info.status, "sandbox_session_id": sess.info.sandbox_session_id,
            "workspace_path": sess.info.workspace_path, "runs": len(sess.info.runs), "process": _PROCESS,
            "workload": {k: v for k, v in next((h for h in hosts if h["kind"] == "workload"), {}).items() if k != "token"} or None,
            "android": {k: v for k, v in next((h for h in hosts if h["kind"] == "android"), {}).items() if k != "tokens"} or None}


@app.entrypoint
def invoke(payload: dict[str, Any], context=None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    rid = _runtime_session_id(context)
    if not isinstance(rid, str) or not rid or len(rid) > 256:
        raise ValueError("invalid runtime session id")
    with _serialized(rid), registry.lease(rid) as lease:
        result = _invoke(payload, context, rid, lease)
        if lease.authoritative and payload.get("action") != "close":
            sid = _by_runtime_session.get(rid)
            if sid:   # hosts may have been added during this call; keep the durable record current
                try:
                    _remember(rid, manager.get(sid), lease)
                except KeyError:
                    pass
        return result


def _invoke(payload: dict[str, Any], context, rid: str, lease) -> dict[str, Any]:
    action = payload.get("action", "task")
    if action == "close" and rid not in _by_runtime_session and (lease.authoritative and not lease.record):
        return {"closed": None}   # nothing to close: do not create a session only to close it
    sess = _session(context, payload, lease)
    if action == "exec":
        t = payload.get("type", "command")
        if t == "code":
            r = sess.run_code(payload["input"], language=payload.get("language", "python"))
        elif t == "pytest":
            r = sess.run_pytest(payload.get("input", "-q"))
        else:
            r = sess.run_command(payload["input"])
        return {"session_id": sess.info.session_id, "result": r.model_dump(mode="json", exclude={"raw"})}
    if action == "files":
        return {"result": sess.write_files(payload["files"]).model_dump(mode="json", exclude={"raw"})}
    if action == "workload":
        from cwe.workload import WorkloadProfile

        if sess.workload is None:
            try:
                sess.start_workload(WorkloadProfile.model_validate(payload.get("profile") or {}))
            except RuntimeError as e:
                if "already started" not in str(e) or sess.workload is None:   # a concurrent request won the race
                    raise
            _remember(rid, sess, lease)
        return {"session_id": sess.info.session_id, "workload": _status(sess)["workload"], "health": sess.workload.health()}
    if action == "remote":
        t = payload.get("type", "exec")
        if t == "exec":
            r = sess.workload_exec(payload["input"], timeout=int(payload.get("timeout") or 600), cwd=payload.get("cwd") or ".", actor="user")
        elif t == "sync":
            return {"result": sess.sync_workspace_to_workload(payload.get("source_dir") or ".", payload.get("dest") or ".", bool(payload.get("clean")), actor="user")}
        elif t == "start":
            r = sess.workload_start(payload["name"], payload["input"], cwd=payload.get("cwd") or ".", actor="user")
        elif t == "stop":
            r = sess.workload_stop(payload["name"], actor="user")
        elif t == "logs":
            return {"result": sess.workload_logs(payload["name"], int(payload.get("tail") or 4000), actor="user")}
        elif t == "probe":
            return {"result": sess.workload_probe(int(payload["port"]), payload.get("path") or "/", payload.get("method") or "GET",
                                                  payload.get("body"), payload.get("headers"), actor="user")}
        else:
            return {"error": f"unknown remote type {t}"}
        return {"session_id": sess.info.session_id, "result": r.model_dump(mode="json", exclude={"raw"})}
    if action == "task":
        from cwe.agent import run_task

        return {"session_id": sess.info.session_id, **run_task(sess, payload["text"], manager.settings)}
    if action == "evaluate":
        rep = sess.evaluate(EvalCriteria.model_validate(payload["criteria"]), task=payload.get("task", ""), run_id=payload.get("run_id"), manager=manager)
        return rep.model_dump(mode="json")
    if action == "snapshot":
        return sess.snapshot(payload.get("description", "")).model_dump(mode="json")
    if action == "events":
        return {"events": sess.recorder.events(payload.get("run_id"))}
    if action == "status":
        return _status(sess)
    if action == "close":
        manager.close(sess.info.session_id)
        _by_runtime_session.pop(rid, None)   # the next call must not reach a closed session
        try:
            registry.delete(rid)
        except Exception as e:  # noqa: BLE001
            log.warning("session registry delete failed: %s", e)
        return {"closed": sess.info.session_id}
    return {"error": f"unknown action {action}"}


if __name__ == "__main__":
    app.run()
