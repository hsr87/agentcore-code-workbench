"""Domain models: Session, Run, Snapshot and Evaluation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Execution results
# ---------------------------------------------------------------------------
class ExecKind(str, Enum):
    CODE = "code"          # executeCode (python/javascript/typescript, stateful REPL)
    COMMAND = "command"    # executeCommand (synchronous shell)
    BACKGROUND = "background"  # startCommandExecution (asynchronous task)
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    SETUP = "setup"        # emulator profile provisioning step
    MOCK_SERVICE = "mock_service"
    DEVICE = "device"          # Android device operations (tap/swipe/screenshot/instrument, ...)


class ExecResult(BaseModel):
    """Normalized form of an AgentCore Code Interpreter stream result."""

    kind: ExecKind
    input: str
    language: str | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    is_error: bool = False
    execution_time: float | None = None
    task_id: str | None = None
    task_status: str | None = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    raw: dict[str, Any] | None = None

    @property
    def output(self) -> str:
        """AgentCore executeCommand sends output to stderr when the exit code is non-zero, so we merge them to view together."""
        parts = [p for p in (self.stdout, self.stderr) if p]
        return "\n".join(parts)

    @property
    def ok(self) -> bool:
        return not self.is_error and (self.exit_code in (None, 0))


# ---------------------------------------------------------------------------
# Emulator profile
# ---------------------------------------------------------------------------
class MockService(BaseModel):
    """A fake HTTP service started inside the sandbox. Emulates external dependencies (payment APIs, internal company APIs, etc.)."""

    name: str
    port: int
    routes: dict[str, Any] = Field(
        default_factory=dict,
        description='Path -> response mapping. Example: {"GET /health": {"status": 200, "body": {"ok": true}}}',
    )


class EmulatorProfile(BaseModel):
    """Declaratively describes the target execution environment. Provisioned as-is into the sandbox when the session starts."""

    name: str = "default"
    description: str = ""
    runtime: Literal["python", "node", "polyglot"] = "python"
    python_packages: list[str] = Field(default_factory=list)
    node_packages: list[str] = Field(default_factory=list)
    system_setup: list[str] = Field(default_factory=list, description="Shell commands to run in order inside the sandbox")
    env: dict[str, str] = Field(default_factory=dict)
    mock_services: list[MockService] = Field(default_factory=list)
    workspace: str = "workspace"
    timeout_seconds: int | None = Field(default=None, ge=60, le=8 * 3600)


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------
class RunEvent(BaseModel):
    """One line of the execution record. Stored as JSONL and used as input for the replay emulator."""

    seq: int
    session_id: str
    run_id: str
    ts: datetime = Field(default_factory=utcnow)
    event_type: Literal["exec", "message", "note", "snapshot", "eval"]
    actor: Literal["user", "agent", "system"] = "user"
    payload: dict[str, Any] = Field(default_factory=dict)


class RunBudget(BaseModel):
    """Execution budget enforced by the harness. Exceeding it aborts the run (rules approve instead of a human)."""

    max_executions: int | None = None
    max_seconds: float | None = None
    max_cost_usd: float | None = None


class BudgetExceeded(RuntimeError):
    pass


class RunRecord(BaseModel):
    """Summary of one Run, the unit of work inside a session."""

    run_id: str = Field(default_factory=lambda: new_id("run"))
    session_id: str
    title: str = ""
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    status: Literal["running", "succeeded", "failed", "cancelled"] = "running"
    exec_count: int = 0
    error_count: int = 0
    total_execution_time: float = 0.0
    artifacts: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    trace_id: str | None = None                      # W3C trace id (for AgentCore Observability correlation)
    usage: dict[str, int] = Field(default_factory=dict)   # inputTokens / outputTokens / totalTokens (agent run)
    cost_usd_estimate: float | None = None           # estimate based on model list price
    budget: RunBudget | None = None
    harness: dict[str, Any] = Field(default_factory=dict)  # executions, human_approvals, budget_exceeded, verification


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
class EvalCheck(BaseModel):
    """Rule-based evaluation item. Supports several types."""

    type: Literal[
        "exit_code",
        "stdout_contains",
        "stdout_regex",
        "stdout_not_contains",
        "file_exists",
        "pytest",
        "max_execution_time",
        "no_errors",
        "instrumented_tests",
        "device_action_count",
        "harness_verification",
    ]
    value: Any = None
    weight: float = 1.0
    description: str = ""


class EvalCriteria(BaseModel):
    checks: list[EvalCheck] = Field(default_factory=list)
    rubric: str | None = Field(default=None, description="Grading criteria to give the LLM judge (natural language)")
    expected_outcome: str | None = None
    pass_threshold: float = 0.7
    verify_command: str | None = Field(default=None, description="Verification command the harness runs directly to accept the result (e.g. python -m pytest -q). The agent's own output is ignored")
    verify_mode: Literal["same", "fresh"] = Field(default="same", description="same: run in the same session / fresh: restore the snapshot into a new session for black-box verification")


class EvalItem(BaseModel):
    name: str
    score: float  # 0.0 ~ 1.0
    passed: bool
    weight: float = 1.0
    explanation: str = ""
    source: Literal["rule", "llm", "agentcore"] = "rule"


class EvalReport(BaseModel):
    eval_id: str = Field(default_factory=lambda: new_id("eval"))
    session_id: str
    run_id: str
    created_at: datetime = Field(default_factory=utcnow)
    items: list[EvalItem] = Field(default_factory=list)
    overall_score: float = 0.0
    passed: bool = False
    summary: str = ""


# ---------------------------------------------------------------------------
# Snapshot / Session
# ---------------------------------------------------------------------------
class SnapshotInfo(BaseModel):
    snapshot_id: str = Field(default_factory=lambda: new_id("snap"))
    session_id: str
    created_at: datetime = Field(default_factory=utcnow)
    uri: str
    size_bytes: int = 0
    description: str = ""


class SessionInfo(BaseModel):
    session_id: str = Field(default_factory=lambda: new_id("sess"))
    created_at: datetime = Field(default_factory=utcnow)
    status: Literal["starting", "ready", "closed", "error"] = "starting"
    profile: EmulatorProfile = Field(default_factory=EmulatorProfile)
    sandbox_session_id: str | None = None
    workspace_path: str | None = None
    runs: list[RunRecord] = Field(default_factory=list)
    snapshots: list[SnapshotInfo] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
