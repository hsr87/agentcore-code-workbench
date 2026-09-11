"""AgentCore Runtime entry point.

One runtime session (runtimeSessionId) maps to one DevSession. Example payloads:
  {"action": "exec", "type": "command", "input": "pytest -q"}
  {"action": "task", "text": "Add input validation to app.py and make tests pass"}
  {"action": "evaluate", "criteria": {...}, "task": "..."}
  {"action": "snapshot"} / {"action": "events"} / {"action": "close"}
"""

from __future__ import annotations

import logging
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from cwe.models import EmulatorProfile, EvalCriteria
from cwe.session import SessionManager

import atexit
import secrets

logging.basicConfig(level=logging.INFO)
app = BedrockAgentCoreApp()
manager = SessionManager()
_by_runtime_session: dict[str, str] = {}
_FALLBACK_RUNTIME_SESSION = f"local-{secrets.token_hex(8)}"   # one private slot per process, never a shared "default"
# clean up so sandbox sessions and EC2 hosts aren't left orphaned when the microVM is terminated by idle timeout
atexit.register(manager.close_all)


def _runtime_session_id(context) -> str:
    """Isolation is per runtimeSessionId. The payload must never be able to name someone else's session."""
    return getattr(context, "session_id", None) or _FALLBACK_RUNTIME_SESSION


def _session(context, payload: dict[str, Any]):
    rid = _runtime_session_id(context)
    if rid in _by_runtime_session:
        return manager.get(_by_runtime_session[rid])
    profile = EmulatorProfile.model_validate(payload["profile"]) if payload.get("profile") else None
    sess = manager.create(profile=profile, tags={"runtime_session_id": rid})
    _by_runtime_session[rid] = sess.info.session_id
    return sess


@app.entrypoint
def invoke(payload: dict[str, Any], context=None) -> dict[str, Any]:
    action = payload.get("action", "task")
    sess = _session(context, payload)
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
    if action == "close":
        manager.close(sess.info.session_id)
        _by_runtime_session.pop(_runtime_session_id(context), None)   # the next call must not reach a closed session
        return {"closed": sess.info.session_id}
    return {"error": f"unknown action {action}"}


if __name__ == "__main__":
    app.run()
