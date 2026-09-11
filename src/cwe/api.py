"""REST interface for driving sessions from CI or other services (FastAPI).

  POST   /v1/sessions                          create a session (restore from profile/snapshot)
  GET    /v1/sessions                          list sessions
  GET    /v1/sessions/{id}                     session detail
  DELETE /v1/sessions/{id}                     close session
  POST   /v1/sessions/{id}/runs                start a run
  POST   /v1/sessions/{id}/runs/{run}/finish   finish a run
  POST   /v1/sessions/{id}/exec                execute code/command (recorded)
  POST   /v1/sessions/{id}/files               upload files
  GET    /v1/sessions/{id}/files/{path}        download a file
  POST   /v1/sessions/{id}/message             hand a task to the agent
  POST   /v1/sessions/{id}/snapshots           create a snapshot
  POST   /v1/sessions/{id}/evaluate            evaluate a run
  GET    /v1/sessions/{id}/events              read the recorded events (replay input)
  GET    /v1/sessions/{id}/transcript          human-readable transcript
"""

from __future__ import annotations

import hmac
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from cwe.models import EmulatorProfile, EvalCriteria, SessionInfo
from cwe.session import SessionManager

log = logging.getLogger(__name__)

_SESSION_ID_RE = re.compile(r"sess_[0-9a-f]{12}")   # only accept the format the server generates (so it can't reach reserved namespaces like _skills)
_SNAPSHOT_ID_RE = re.compile(r"snap_[0-9a-f]{12}")
MAX_INPUT_CHARS = 200_000
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_MESSAGE_CHARS = 20_000
MAX_BODY_BYTES = 12 * 1024 * 1024   # refused before the body is buffered and parsed


class RestoreRequest(BaseModel):
    """Restore request. The client sends ids only; the server reads the snapshot metadata from the source session."""
    session_id: str = Field(pattern=rf"^{_SESSION_ID_RE.pattern}$")     # anchored: pydantic patterns search, not fullmatch
    snapshot_id: str = Field(pattern=rf"^{_SNAPSHOT_ID_RE.pattern}$")


class CreateSessionRequest(BaseModel):
    profile: EmulatorProfile | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    restore_snapshot: RestoreRequest | None = None

    @field_validator("tags")
    @classmethod
    def _small_tags(cls, v):
        if len(v) > 20 or any(len(k) > 64 or len(x) > 256 for k, x in v.items()):
            raise ValueError("too many or too long tags")
        return v


class ExecRequest(BaseModel):
    type: Literal["code", "command", "background", "pytest"] = "command"
    input: str = Field(default="", max_length=MAX_INPUT_CHARS)
    language: Literal["python", "javascript", "typescript"] = "python"
    clear_context: bool = False
    wait: bool = True


class FilesRequest(BaseModel):
    files: dict[str, str]

    @field_validator("files")
    @classmethod
    def _bounded(cls, v):
        if sum(len(k) + len(x.encode("utf-8")) for k, x in v.items()) > MAX_UPLOAD_BYTES:
            raise ValueError(f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
        for k in v:
            if not k or k.startswith("/") or any(seg in ("", ".", "..") for seg in k.split("/")):
                raise ValueError(f"invalid path {k!r}")
        return v


class MessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class RunRequest(BaseModel):
    title: str = Field(default="", max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvaluateRequest(BaseModel):
    criteria: EvalCriteria
    task: str = ""
    run_id: str | None = None
    use_llm: bool | None = None


def create_app(manager: SessionManager | None = None) -> FastAPI:
    manager = manager or SessionManager()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        manager.close_all()

    app = FastAPI(title="code-workflow-emulator", version="0.1.0", lifespan=lifespan)
    app.state.manager = manager

    api_key = os.environ.get("CWE_API_KEY", "")
    if not api_key:
        log.warning("CWE_API_KEY is not set: the REST API is unauthenticated. Bind to 127.0.0.1 only, or put AgentCore Identity / ALB+Cognito in front.")

    @app.middleware("http")
    async def _limit_body(request: Request, call_next):
        """Reject oversized requests before Starlette buffers and parses them."""
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.middleware("http")
    async def _require_api_key(request: Request, call_next):
        """When CWE_API_KEY is set, require an x-api-key header on /v1/* (except /ping). In production, put Identity/ALB auth in front of this.
        A key holder can access every session (per-user authorization is left to Runtime session isolation or upstream auth)."""
        if api_key and (request.url.path.startswith("/v1/") or request.url.path in ("/docs", "/redoc", "/openapi.json")):
            given = request.headers.get("x-api-key", "")
            if not hmac.compare_digest(given.encode("utf-8", "surrogateescape"), api_key.encode("utf-8")):
                from fastapi.responses import JSONResponse

                return JSONResponse({"detail": "invalid api key"}, status_code=401)
        return await call_next(request)

    def _get(sid: str):
        if not _SESSION_ID_RE.fullmatch(sid):
            raise HTTPException(404, "session not found")
        try:
            return manager.get(sid)
        except KeyError:
            raise HTTPException(404, "session not found")

    def _public(info: SessionInfo) -> dict[str, Any]:
        """Session metadata for responses: mask the profile's env values (a place secrets can end up)."""
        d = info.model_dump(mode="json")
        if d.get("profile", {}).get("env"):
            d["profile"]["env"] = {k: "***" for k in d["profile"]["env"]}
        return d

    @app.get("/ping")
    def ping():
        return {"status": "Healthy"}

    @app.post("/v1/sessions")
    def create_session(req: CreateSessionRequest):
        restore = None
        if req.restore_snapshot:
            try:
                src = manager.load_session_info(req.restore_snapshot.session_id)
            except Exception:
                raise HTTPException(404, "snapshot source session not found")
            restore = next((s for s in src.snapshots if s.snapshot_id == req.restore_snapshot.snapshot_id), None)
            if restore is None:
                raise HTTPException(404, "snapshot not found")
        sess = manager.create(profile=req.profile, tags=req.tags, restore_from=restore)
        return _public(sess.info)

    @app.get("/v1/sessions")
    def list_sessions():
        return [_public(i) for i in manager.list()]

    @app.get("/v1/sessions/{sid}")
    def get_session(sid: str):
        return _public(_get(sid).info)

    @app.delete("/v1/sessions/{sid}")
    def close_session(sid: str):
        _get(sid)
        manager.close(sid)
        return {"closed": sid}

    @app.post("/v1/sessions/{sid}/runs")
    def begin_run(sid: str, req: RunRequest):
        return _get(sid).begin_run(req.title, metadata=req.metadata)

    @app.post("/v1/sessions/{sid}/runs/{run_id}/finish")
    def end_run(sid: str, run_id: str, status: Literal["succeeded", "failed", "cancelled"] = "succeeded"):
        sess = _get(sid)
        if not sess._current_run or sess._current_run.run_id != run_id:
            raise HTTPException(409, "run is not the active run")
        return sess.end_run(status)

    @app.post("/v1/sessions/{sid}/exec")
    def exec_(sid: str, req: ExecRequest):
        sess = _get(sid)
        if req.type == "code":
            r = sess.run_code(req.input, language=req.language, clear_context=req.clear_context)
        elif req.type == "command":
            r = sess.run_command(req.input)
        elif req.type == "pytest":
            r = sess.run_pytest(req.input or "-q")
        else:
            r = sess.run_background(req.input)
            if req.wait and r.task_id:
                r = sess.wait_background(r.task_id)
        return r.model_dump(exclude={"raw"})

    @app.post("/v1/sessions/{sid}/files")
    def upload(sid: str, req: FilesRequest):
        return _get(sid).write_files(req.files).model_dump(exclude={"raw"})

    @app.get("/v1/sessions/{sid}/files/{path:path}", response_class=PlainTextResponse)
    def download(sid: str, path: str):
        segments = path.strip("/").split("/")
        if any(seg in ("..", "") for seg in segments):
            raise HTTPException(400, "invalid path")
        if segments[0] == ".cwe":   # the profile environment file and mock service state live here
            raise HTTPException(403, "reserved path")
        data = _get(sid).read_file(path)
        if data is None:
            raise HTTPException(404, path)
        return data.decode("utf-8", "replace") if isinstance(data, bytes) else data

    @app.post("/v1/sessions/{sid}/message")
    def message(sid: str, req: MessageRequest):
        from cwe.agent import run_task

        return run_task(_get(sid), req.text, manager.settings)

    @app.post("/v1/sessions/{sid}/snapshots")
    def snapshot(sid: str, description: str = ""):
        return _get(sid).snapshot(description)

    @app.post("/v1/sessions/{sid}/evaluate")
    def evaluate(sid: str, req: EvaluateRequest):
        return _get(sid).evaluate(req.criteria, task=req.task, run_id=req.run_id, use_llm=req.use_llm, manager=manager)

    @app.post("/v1/recorded/{sid}/evaluate")
    def evaluate_recorded(sid: str, req: EvaluateRequest):
        """Open a closed session from its recording alone for post-hoc grading (for comparison/re-grading)."""
        if not _SESSION_ID_RE.fullmatch(sid):
            raise HTTPException(404, "recorded session not found")
        try:
            sess = manager.open_recorded(sid)
        except Exception as e:  # do not put internal paths or bucket names in the response
            log.info("open_recorded %s failed: %s", sid, e)
            raise HTTPException(404, "recorded session not found")
        return sess.evaluate(req.criteria, task=req.task, run_id=req.run_id, use_llm=req.use_llm)

    @app.get("/v1/sessions/{sid}/events")
    def events(sid: str, run_id: str | None = None):
        return _get(sid).recorder.events(run_id)

    @app.get("/v1/sessions/{sid}/transcript", response_class=PlainTextResponse)
    def transcript(sid: str, run_id: str | None = None):
        return _get(sid).recorder.transcript(run_id)

    return app


app = create_app()
