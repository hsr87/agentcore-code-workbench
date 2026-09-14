"""DevSession: the orchestrator behind a development session.

A session = sandbox (AgentCore Code Interpreter) + emulator profile + recorder + evaluator + snapshots.
"""

from __future__ import annotations

import logging
import os
import secrets
import re
import threading
from typing import Any

from cwe.config import Settings, get_settings
from cwe.emulator import EnvironmentEmulator, MockServiceEmulator
from cwe.evaluator import AgentCoreEvaluator, LLMJudgeEvaluator, RuleEvaluator, RunContext, aggregate, parse_pytest_output
from cwe.models import (BudgetExceeded, EmulatorProfile, EvalCriteria, EvalReport, ExecKind, ExecResult, RunBudget, RunRecord,
                        SessionInfo, SnapshotInfo, utcnow)
from cwe.recorder import Recorder, _clip, make_store
from cwe.sandbox import AgentCoreSandbox, Sandbox
from cwe.snapshots import restore_snapshot, take_snapshot

log = logging.getLogger(__name__)
MAX_REMOTE_RECORD = 20_000


class DevSession:
    def __init__(self, info: SessionInfo, sandbox: Sandbox, recorder: Recorder, settings: Settings, store):
        self.info = info
        self.sandbox = sandbox
        self.recorder = recorder
        self.settings = settings
        self.store = store
        self.emulator = EnvironmentEmulator(sandbox, info.profile)
        self.mocks = MockServiceEmulator(sandbox, None)
        self._current_run: RunRecord | None = None
        self.device = None          # cwe.android.AndroidDevice (connected via attach_android)
        self._device_host = None    # EKS/EC2 host implementing start/stop
        self.workload = None        # cwe.workload.WorkloadClient (heavy build/run Pod)
        self._workload_host = None
        self._workload_profile = None
        self._workload_lock = threading.Lock()   # one Pod per session even when a caller retries the request
        self._lease_guard = None    # callable set by the Runtime entry point: raises once this process lost the session lease
        self._run_results: dict[str, list[ExecResult]] = {}
        self._outputs: dict[str, str] = {}   # 'run_id:exec_no' -> full output (for on-demand context retrieval)
        self._lock = threading.RLock()

    # -- lifecycle ------------------------------------------------------------
    def start(self, restore_from: SnapshotInfo | None = None) -> "DevSession":
        self.info.sandbox_session_id = self.sandbox.start()
        run = self.begin_run("provision", actor="system")
        try:
            for r in self.emulator.provision():
                self._record(r, actor="system")
            self.info.workspace_path = self.emulator.workspace_path
            self.mocks = MockServiceEmulator(self.sandbox, self.info.workspace_path)
            if restore_from:
                restore_snapshot(self.sandbox, self.store, restore_from, self.info.workspace_path or self.info.profile.workspace)
                self.recorder.record(run.run_id, "snapshot", {"action": "restore", "snapshot_id": restore_from.snapshot_id})
            self.info.status = "ready"
            self.end_run("succeeded")
        except Exception:
            self.info.status = "error"
            self.end_run("failed")
            raise
        self._persist()
        return self

    def close(self) -> None:
        try:
            self.mocks.stop_all()
            if self._device_host:
                self._device_host.stop()
            if self._workload_host:
                self._workload_host.stop()
        finally:
            self.sandbox.stop()
            self.info.status = "closed"
            self._persist()

    def detach(self) -> None:
        """Let go of live resources without stopping them. Used when this process is about to exit but the
        session registry still points at the sandbox and Pods, so the next Runtime microVM can reattach."""
        for host in (self._device_host, self._workload_host):
            if host is not None and hasattr(host, "detach"):
                host.detach()
        self._persist()

    # -- sticky sessions (AgentCore Runtime) -------------------------------------
    def registry_record(self, runtime_session_id: str) -> dict[str, Any]:
        """Everything a fresh process needs to find this session again. Tokens are sealed by the registry, not here."""
        hosts = [h.describe() for h in (self._device_host, self._workload_host) if h is not None and hasattr(h, "describe")]
        return {"runtime_session_id": runtime_session_id, "session_id": self.info.session_id,
                "sandbox_session_id": self.info.sandbox_session_id, "workspace_path": self.info.workspace_path,
                "hosts": hosts}

    # -- runs -----------------------------------------------------------------
    def begin_run(self, title: str = "", actor: str = "user", metadata: dict[str, Any] | None = None, budget: RunBudget | None = None) -> RunRecord:
        with self._lock:
            run = RunRecord(session_id=self.info.session_id, title=title, metadata=metadata or {}, trace_id=secrets.token_hex(16), budget=budget,
                            harness={"executions": 0, "human_approvals": 0, "budget_exceeded": None})
            self.info.runs.append(run)
            self._current_run = run
            self._run_results[run.run_id] = []
            # attach a W3C traceparent to sandbox calls per run, linking AgentCore Observability traces to our recordings
            if hasattr(self.sandbox, "trace_parent"):
                self.sandbox.trace_parent = f"00-{run.trace_id}-{secrets.token_hex(8)}-01"
            self.recorder.record(run.run_id, "note", {"action": "begin_run", "title": title}, actor=actor)  # type: ignore[arg-type]
            return run

    def end_run(self, status: str = "succeeded") -> RunRecord:
        with self._lock:
            run = self._require_run()
            run.status = status  # type: ignore[assignment]
            run.finished_at = utcnow()
            self.recorder.record(run.run_id, "note", {"action": "end_run", "status": status, "usage": run.usage, "cost_usd_estimate": run.cost_usd_estimate})
            self._current_run = None
            if hasattr(self.sandbox, "trace_parent"):
                self.sandbox.trace_parent = None
            self._persist()
            return run

    def _require_run(self) -> RunRecord:
        if self._current_run is None:
            return self.begin_run("adhoc")
        return self._current_run

    def current_run_or_none(self) -> RunRecord | None:
        """The run in progress (None if there isn't one). Used by the harness hooks to read budget state."""
        return self._current_run

    def check_budget(self, cost_usd: float | None = None) -> None:
        """Raises BudgetExceeded when the budget is exceeded. Called by the harness before a tool call and between model turns (approval is by rule, not by a human)."""
        run = self._current_run
        if not run or not run.budget:
            return
        b = run.budget
        reason = None
        if b.max_executions is not None and run.exec_count >= b.max_executions:
            reason = f"max_executions {b.max_executions} reached"
        elif b.max_seconds is not None and (utcnow() - run.started_at).total_seconds() > b.max_seconds:
            reason = f"max_seconds {b.max_seconds} exceeded"
        elif b.max_cost_usd is not None and cost_usd is not None and cost_usd > b.max_cost_usd:
            reason = f"max_cost_usd {b.max_cost_usd} exceeded (now {cost_usd:.3f})"
        if reason:
            run.harness["budget_exceeded"] = reason
            raise BudgetExceeded(reason)

    def _record(self, result: ExecResult, actor: str = "user", files: dict[str, str | bytes] | None = None) -> ExecResult:
        with self._lock:   # do the budget check and counter increment together (so concurrent requests can't both slip past the limit)
            run = self._require_run()
            if self._lease_guard is not None:
                self._lease_guard()
            if actor != "system":
                self.check_budget()
            run.exec_count += 1
            run.harness["executions"] = run.exec_count
            # Full output for read_full_output; clipped like the recording so a long session cannot grow without bound.
            self._outputs[f"{run.run_id}:{run.exec_count}"] = _clip(result.output)
            run.total_execution_time += result.execution_time or 0.0
            if result.is_error:
                run.error_count += 1
            self._run_results.setdefault(run.run_id, []).append(result)
        self.recorder.record_exec(run.run_id, result, actor=actor, files=files)
        return result

    def full_output(self, ref: str) -> str | None:
        """Returns the full output of a tool result that was clipped in the summary, keyed by reference (run_id:exec_no)."""
        return self._outputs.get(ref)

    def last_exec_ref(self) -> str:
        run = self._require_run()
        return f"{run.run_id}:{run.exec_count}"

    # -- execution API: run code and commands ------------------------
    def run_code(self, code: str, language: str = "python", clear_context: bool = False, actor: str = "user") -> ExecResult:
        # the REPL has a notion of cwd, so change into the profile's workspace before executing
        if language == "python" and self.info.workspace_path:
            code = f"import os as _os; _os.chdir({self.info.workspace_path!r})\n" + code
        return self._record(self.sandbox.execute_code(code, language=language, clear_context=clear_context), actor=actor)

    def run_command(self, command: str, actor: str = "user", raw: bool = False) -> ExecResult:
        cmd = command if raw else self.emulator.wrap_command(command)   # env values are read from the sandbox's .cwe/env, not the command, so they don't leak into recordings
        return self._record(self.sandbox.execute_command(cmd), actor=actor)

    def run_background(self, command: str, actor: str = "user") -> ExecResult:
        return self._record(self.sandbox.start_background(self.emulator.wrap_command(command)), actor=actor)

    def wait_background(self, task_id: str, timeout: float = 600) -> ExecResult:
        r = self.sandbox.wait_task(task_id, timeout=timeout)  # type: ignore[attr-defined]
        return self._record(r, actor="system")

    def write_files(self, files: dict[str, str | bytes], actor: str = "user") -> ExecResult:
        """Write files at paths relative to the workspace."""
        ws = self.info.profile.workspace.strip("/")
        rel = {f"{ws}/{p.lstrip('/')}": d for p, d in files.items()}
        return self._record(self.sandbox.write_files(rel), actor=actor, files=files)

    def read_file(self, path: str) -> str | bytes | None:
        ws = self.info.profile.workspace.strip("/")
        full = f"{ws}/{path.lstrip('/')}"
        return self.sandbox.read_files([full]).get(full)

    def list_workspace(self) -> list[str]:
        r = self.sandbox.execute_command(self.emulator.wrap_command("find . -type f -not -path '*/node_modules/*' -not -path '*/.venv/*' -not -path '*/__pycache__/*' | sed 's|^./||' | head -500"))
        return [l.strip() for l in r.output.splitlines() if l.strip() and not l.startswith("find:")]

    def run_pytest(self, args: str = "-q", actor: str = "user") -> ExecResult:
        r = self.run_command(f"python -m pytest --color=no {args}", actor=actor)
        run = self._require_run()
        run.metadata["pytest"] = parse_pytest_output(r.output)
        return r

    def message(self, text: str, role: str = "user") -> None:
        """Records a conversation message or instruction. Also loaded into long-term memory when Memory is configured."""
        self.recorder.record(self._require_run().run_id, "message", {"role": role, "text": text}, actor="user" if role == "user" else "agent")

    # -- Android device: emulator support ---------------------
    def attach_android(self, device, host=None) -> None:
        """Connect to a device agent that is already running. If host is given, it is torn down together when the session closes."""
        self.device = device
        self._device_host = host
        self.recorder.record(self._require_run().run_id, "note", {"action": "attach_android", "device": getattr(device, "base_url", "?")})

    def start_android(self, profile, host=None) -> None:
        """Start the emulator on the configured EKS/EC2 backend."""
        if host is None:
            from cwe.android import emulator_host

            host = emulator_host(self.settings)
        self._android_profile = profile
        self.begin_run("android-provision", actor="system")
        try:
            device = host.start(profile, self.info.session_id)
        except Exception:
            host.stop()  # clean up so the instance/job doesn't linger
            self.end_run("failed")
            raise
        self.attach_android(device, host)
        if profile.apk_url:
            # A presigned URL is a credential: record the location, not the signature.
            from urllib.parse import urlsplit

            recorded = urlsplit(profile.apk_url)._replace(query="", fragment="").geturl()
            self.device_action("install", {"url": recorded}, device.install(profile.apk_url))
        self.end_run("succeeded")

    def device_action(self, name: str, params: dict, result, artifact: bytes | None = None, artifact_ext: str = "png", actor: str = "user") -> ExecResult:
        """Records one device action as an ExecResult. Screenshots/recordings are saved to the store as artifacts."""
        import json as _json

        ok = True
        text = result if isinstance(result, str) else _json.dumps(result, ensure_ascii=False)
        if isinstance(result, dict):
            ok = result.get("ok", result.get("exit_code", 0) == 0)
            if "failed" in result:
                ok = int(result.get("failed", 0)) == 0
        r = ExecResult(kind=ExecKind.DEVICE, input=f"{name} {_json.dumps(params, ensure_ascii=False)}", stdout=text[:20000],
                       exit_code=0 if ok else 1, is_error=not ok, finished_at=utcnow())
        if artifact is not None:
            run = self._require_run()
            uri = self.store.put(self.info.session_id, f"artifacts/{run.run_id}_{run.exec_count + 1:04d}.{artifact_ext}", artifact)
            run.artifacts.append(uri)
            r.stdout = f"artifact:{uri} ({len(artifact)} bytes)"
        return self._record(r, actor=actor)

    def screenshot(self, actor: str = "user") -> bytes:
        png = self.device.screenshot()
        self.device_action("screenshot", {}, "ok", artifact=png, actor=actor)
        return png

    def run_instrumented_tests(self, test_package: str, runner: str, args: dict | None = None, actor: str = "user") -> dict:
        rep = self.device.instrument(test_package, runner, args or {})
        self._require_run().metadata["instrument"] = {"passed": rep.get("passed", 0), "failed": rep.get("failed", 0)}
        self.device_action("instrument", {"package": test_package, "runner": runner, "args": args or {}}, rep, actor=actor)
        return rep

    # -- android build on host: build inside the emulator loop -----------
    def android_build(self, source_dir: str = ".", tasks: str | None = None, timeout: int = 1800) -> dict[str, Any]:
        """Tars up the workspace (or a subfolder), uploads it to the store, and has the emulator host fetch it via a presigned URL and run the Gradle build.
        The sandbox has no Java/Android SDK (PFR R2), so building on the host is the workaround. The resulting APKs come back as host paths."""
        from cwe.github import presign

        if self.device is None:
            raise RuntimeError("no Android device attached")
        prof = getattr(self, "_android_profile", None)
        tasks = tasks or (prof.build_tasks if prof else "assembleDebug assembleDebugAndroidTest")
        snap = take_snapshot(self.sandbox, self.store, self.info.session_id, f"{self.info.workspace_path or self.info.profile.workspace}/{source_dir}".rstrip("/."),
                             description=f"build source {source_dir}")
        url = presign(self.store, self.info.session_id, f"{snap.snapshot_id}.tar.gz", self.settings.region, expires=3600)
        if not url or not url.startswith("http"):
            raise RuntimeError("android_build needs an S3 recordings store (CWE_STORAGE_URI=s3://...) so the host can fetch the source")
        started = utcnow()
        res = self.device.build(url, tasks=tasks, timeout=timeout)
        r = ExecResult(kind=ExecKind.DEVICE, input=f"android_build {tasks}", stdout=res.get("log_tail", ""), exit_code=res.get("exit_code"),
                       is_error=not res.get("ok"), execution_time=res.get("seconds"), started_at=started, finished_at=utcnow())
        self._record(r, actor="agent")
        run = self._require_run()
        run.metadata["android_build"] = {"build_id": res.get("build_id"), "apks": res.get("apks", []), "seconds": res.get("seconds"), "ok": res.get("ok")}
        return res

    def android_install_built(self, apks: list[str] | None = None) -> list[dict[str, Any]]:
        """Installs the APKs built on the host (app + test) onto the emulator."""
        run = self._require_run()
        apks = apks or run.metadata.get("android_build", {}).get("apks", [])
        out = []
        for path in apks:
            res = self.device.install_path(path)
            self.device_action("install", {"path": path}, res)
            out.append(res)
        return out

    # -- heavy workload on EKS: build and run what the microVM cannot ----------------
    def start_workload(self, profile=None, host=None):
        """Start a build/run Pod for this session. Returns the WorkloadClient; the agent's remote_* tools use it."""
        from cwe.workload import EKSWorkloadHost, WorkloadProfile

        # A retried or concurrent request waits here and then sees the Pod the first one started.
        with self._workload_lock:
            if self.info.status == "closed":
                raise RuntimeError("session is closed")
            if self._workload_host is not None:
                raise RuntimeError("workload already started")
            profile = profile or WorkloadProfile()
            if not profile.image and self.settings.workload_image:
                profile = profile.model_copy(update={"image": self.settings.workload_image})
            host = host or EKSWorkloadHost.from_env(self.settings)
            owns_run = self._current_run is None   # inside a caller's run, record there instead of closing it
            if owns_run:
                self.begin_run("workload-provision", actor="system")
            try:
                client = host.start(profile, self.info.session_id)
            except Exception:
                if owns_run:
                    self.end_run("failed")
                raise
            if self.info.status == "closed":   # closed while the Pod was starting: do not leave it behind
                host.stop()
                raise RuntimeError("session was closed while the workload was starting")
            self._attach_workload(client, host, profile)
            if owns_run:
                self.end_run("succeeded")
            return client

    def _attach_workload(self, client, host, profile=None) -> None:
        self.workload, self._workload_host, self._workload_profile = client, host, profile
        try:
            health = client.health()
        except Exception as e:  # noqa: BLE001
            health = {"error": str(e)[:200]}
        self.recorder.record(self._require_run().run_id, "note",
                             {"action": "attach_workload", "image": getattr(profile, "image", None),
                              "cpus": health.get("cpus"), "mem_total_bytes": health.get("mem_total_bytes"),
                              "disk_total_bytes": health.get("disk_total_bytes")})

    def _record_remote(self, name: str, params: dict, result: dict, ok: bool | None = None, actor: str = "agent") -> ExecResult:
        import json as _json

        if ok is None:
            if "exit_code" in result:
                ok = result.get("exit_code") == 0
            elif "status" in result:
                ok = 0 < int(result.get("status") or 0) < 500
            else:
                ok = True
        text = result.get("output") or result.get("log") or result.get("body") or _json.dumps({k: v for k, v in result.items() if k != "headers"}, ensure_ascii=False)
        r = ExecResult(kind=ExecKind.REMOTE, input=f"{name} {_json.dumps(params, ensure_ascii=False)[:2000]}", stdout=str(text)[:MAX_REMOTE_RECORD],
                       exit_code=result.get("exit_code", 0 if ok else 1), is_error=not ok, execution_time=result.get("seconds"), finished_at=utcnow())
        return self._record(r, actor=actor)

    def _require_workload(self):
        if self.workload is None:
            raise RuntimeError("no workload attached; call start_workload first")
        return self.workload

    def workload_exec(self, cmd: str, timeout: int = 600, cwd: str = ".", actor: str = "agent") -> ExecResult:
        res = self._require_workload().exec(cmd, timeout=timeout, cwd=cwd)
        return self._record_remote("remote_shell", {"cmd": cmd, "cwd": cwd, "timeout": timeout}, res, actor=actor)

    def workload_start(self, name: str, cmd: str, cwd: str = ".", actor: str = "agent") -> ExecResult:
        res = self._require_workload().start(name, cmd, cwd=cwd)
        return self._record_remote("remote_start", {"name": name, "cmd": cmd, "cwd": cwd}, res, ok=True, actor=actor)

    def workload_stop(self, name: str, actor: str = "agent") -> ExecResult:
        res = self._require_workload().stop(name)
        return self._record_remote("remote_stop", {"name": name}, res, ok=True, actor=actor)

    def workload_logs(self, name: str, tail: int = 4000, actor: str = "agent") -> dict[str, Any]:
        res = self._require_workload().logs(name, tail=tail)
        self._record_remote("remote_logs", {"name": name, "tail": tail}, res, ok=True, actor=actor)
        return res

    def workload_probe(self, port: int, path: str = "/", method: str = "GET", body: str | None = None,
                       headers: dict[str, str] | None = None, actor: str = "agent") -> dict[str, Any]:
        res = self._require_workload().probe(port, path, method, body, headers)
        ok = 0 < int(res.get("status") or 0) < 500
        self._record_remote("remote_probe", {"port": port, "path": path, "method": method}, res, ok=ok, actor=actor)
        return res

    def workload_write_files(self, files: dict[str, str | bytes], actor: str = "agent") -> ExecResult:
        res = self._require_workload().write_files(files)
        return self._record_remote("remote_write_files", {"paths": list(files)}, res, ok=True, actor=actor)

    def workload_read_file(self, path: str, max_bytes: int = 200_000) -> bytes | None:
        return self._require_workload().read_file(path, max_bytes)

    def sync_workspace_to_workload(self, source_dir: str = ".", dest: str = ".", clean: bool = False, actor: str = "agent") -> dict[str, Any]:
        """Copy the sandbox workspace (or a subfolder) into the Pod: snapshot -> S3 -> presigned fetch.
        For a large repository prefer `git clone` inside the Pod via remote_shell and sync only the diff."""
        from cwe.github import presign

        self._require_workload()
        src = f"{self.info.workspace_path or self.info.profile.workspace}/{source_dir}".rstrip("/.")
        snap = take_snapshot(self.sandbox, self.store, self.info.session_id, src, description=f"workload sync {source_dir}")
        url = presign(self.store, self.info.session_id, f"{snap.snapshot_id}.tar.gz", self.settings.region, expires=1800)
        if not url or not url.startswith("http"):
            raise RuntimeError("sync_workspace_to_workload needs an S3 recordings store (CWE_STORAGE_URI=s3://...) so the Pod can fetch the source")
        res = self.workload.fetch(url, dest=dest, extract=True, clean=clean)
        res["snapshot_id"] = snap.snapshot_id
        self._record_remote("remote_sync_workspace", {"source_dir": source_dir, "dest": dest, "snapshot_id": snap.snapshot_id}, res, ok=True, actor=actor)
        return res

    @property
    def skills(self):
        from cwe.skills import SkillStore

        return SkillStore(self.store, self.settings.skills_prefix)

    def distill_skill(self, run_id: str | None = None) -> dict[str, str]:
        """Builds a skill draft from a successful run's transcript and saves it (status=draft; the agent reads it once a human approves it)."""
        from cwe.skills import distill_skill

        run_id = run_id or self.info.runs[-1].run_id
        run = next(r for r in self.info.runs if r.run_id == run_id)
        draft = distill_skill(self.recorder.transcript(run_id), run.metadata.get("task", run.title), self.settings.region, self.settings.judge_model)
        self.skills.save(draft["name"], draft["description"], draft["body"], status="draft", session_id=self.info.session_id, run_id=run_id)
        self.recorder.record(run_id, "note", {"action": "skill_draft", "name": draft["name"]})
        return draft

    # -- snapshots ------------------------------------------------------------
    def snapshot(self, description: str = "") -> SnapshotInfo:
        info = take_snapshot(self.sandbox, self.store, self.info.session_id, self.info.workspace_path or self.info.profile.workspace, description)
        self.info.snapshots.append(info)
        self.recorder.record(self._require_run().run_id, "snapshot", {"action": "take", **info.model_dump(mode="json")})
        self._persist()
        return info

    # -- evaluation -----------------------------------------------------------
    def results_from_events(self, run_id: str) -> list[ExecResult]:
        """Reconstructs a run's execution results from the recordings (events.jsonl). For post-hoc scoring after a process restart or on a different host."""
        out: list[ExecResult] = []
        for e in self.recorder.events(run_id):
            if e.get("event_type") != "exec":
                continue
            p = e["payload"]
            out.append(ExecResult(kind=ExecKind(p.get("kind", "command")), input=p.get("input", ""), language=p.get("language"),
                                  stdout=p.get("stdout") or "", stderr=p.get("stderr") or "", exit_code=p.get("exit_code"),
                                  is_error=bool(p.get("is_error")), execution_time=p.get("execution_time"),
                                  task_id=p.get("task_id"), task_status=p.get("task_status")))
        return out

    def files_from_events(self, run_id: str | None = None) -> list[str]:
        files: list[str] = []
        for e in self.recorder.events(run_id):
            if e.get("event_type") == "exec":
                files += [p for p in (e["payload"].get("files") or {}) if p not in files]
        return files

    def verify(self, command: str, mode: str = "same", manager=None, run: RunRecord | None = None) -> dict[str, Any]:
        """The harness runs the verification command itself; output the agent produced is never trusted (separation of author and verifier).
        With mode=fresh, restores the snapshot into a new session and runs it as a black box (needs a manager). The result attaches to run (default: the current or last run)."""
        run = run or (self._current_run if self._current_run else self.info.runs[-1])
        if mode == "fresh":
            if manager is None:
                raise ValueError("fresh verification needs a SessionManager")
            snap = self.snapshot("verification")
            fresh = manager.create(profile=self.info.profile, restore_from=snap, tags={"verification_of": self.info.session_id})
            try:
                fresh.begin_run("verify", actor="system")
                r = fresh.run_command(command, actor="system")
                fresh.end_run()
            finally:
                manager.close(fresh.info.session_id)
        else:
            r = self.run_command(command, actor="system")
        report = {"command": command, "mode": mode, "exit_code": r.exit_code, "output": r.output[-4000:], "pytest": parse_pytest_output(r.output)}
        run.harness["verification"] = report
        self.recorder.record(run.run_id, "note", {"action": "harness_verification", **{k: v for k, v in report.items() if k != "output"}})
        return report

    def evaluate(self, criteria: EvalCriteria, task: str = "", run_id: str | None = None, use_llm: bool | None = None, manager=None) -> EvalReport:
        run_id = run_id or (self._current_run.run_id if self._current_run else self.info.runs[-1].run_id)
        run = next((r for r in self.info.runs if r.run_id == run_id), None)
        run_meta = run.metadata if run else {}
        verification = (run.harness.get("verification") if run else None)
        if criteria.verify_command and self.sandbox.session_id:   # if the sandbox is alive, the harness always verifies directly
            verification = self.verify(criteria.verify_command, criteria.verify_mode, manager=manager, run=run)
        results = self._run_results.get(run_id) or self.results_from_events(run_id)   # restore from recordings if not in memory
        files = self._safe_list_files() if self.sandbox.session_id else self.files_from_events()
        # when a verification command exists, the pytest rule looks only at the harness's run result (ignores agent output)
        pytest_report = verification["pytest"] if verification and verification.get("pytest", {}).get("passed", 0) + verification.get("pytest", {}).get("failed", 0) > 0 else run_meta.get("pytest")
        ctx = RunContext(results=results, files=files, pytest_report=pytest_report, instrument_report=run_meta.get("instrument"), verification=verification)
        items = RuleEvaluator().evaluate(criteria.checks, ctx)

        use_llm = self.settings.enable_llm_judge if use_llm is None else use_llm
        if use_llm and (criteria.rubric or criteria.expected_outcome or task):
            judge = LLMJudgeEvaluator(self.settings.region, self.settings.judge_model)
            items.append(judge.evaluate(task or run_meta.get("task", ""), self.recorder.transcript(run_id), criteria, verification=verification))

        report = aggregate(self.info.session_id, run_id, items, criteria.pass_threshold)
        self.recorder.record(run_id, "eval", report.model_dump(mode="json"))
        self._persist()
        return report

    def evaluate_agent_session(self, runtime_session_id: str, evaluator_ids: list[str] | None = None) -> list[dict[str, Any]]:
        ev = AgentCoreEvaluator(self.settings.region, agent_runtime_id=self.settings.agent_runtime_id)
        return [i.model_dump() for i in ev.evaluate(runtime_session_id, evaluator_ids)]

    def _safe_list_files(self) -> list[str]:
        try:
            return self.list_workspace()
        except Exception as e:
            log.warning("list_workspace failed: %s", e)
            return []

    # -- persistence ----------------------------------------------------------
    def _persist(self) -> None:
        """Session metadata for post-hoc scoring. Profile env values stay in the sandbox, never in the store."""
        import json as _json

        data = self.info.model_dump(mode="json")
        if data.get("profile", {}).get("env"):
            data["profile"]["env"] = {k: "***" for k in data["profile"]["env"]}
        self.store.put(self.info.session_id, "session.json", _json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))


class SessionManager:
    """Session registry. Keep a single shared instance in the API server/runtime."""

    def __init__(self, settings: Settings | None = None, sandbox_factory=None):
        self.settings = settings or get_settings()
        self.store = make_store(self.settings.storage_uri, self.settings.region)
        self._sessions: dict[str, DevSession] = {}
        self._lock = threading.Lock()   # FastAPI runs synchronous handlers in a thread pool
        self._sandbox_factory = sandbox_factory or self._default_sandbox
        self._memory_client = None
        if self.settings.memory_id:
            from bedrock_agentcore.memory import MemoryClient

            self._memory_client = MemoryClient(region_name=self.settings.region)

    def _default_sandbox(self, profile: EmulatorProfile) -> Sandbox:
        return AgentCoreSandbox(
            self.settings.region,
            identifier=self.settings.code_interpreter_id,
            timeout_seconds=profile.timeout_seconds or self.settings.session_timeout_seconds,
        )

    def create(self, profile: EmulatorProfile | None = None, tags: dict[str, str] | None = None,
               restore_from: SnapshotInfo | None = None, actor_id: str = "developer") -> DevSession:
        profile = profile or EmulatorProfile()
        info = SessionInfo(profile=profile, tags=tags or {})
        sandbox = self._sandbox_factory(profile)
        recorder = Recorder(info.session_id, self.store, memory_client=self._memory_client, memory_id=self.settings.memory_id, actor_id=actor_id)
        sess = DevSession(info, sandbox, recorder, self.settings, self.store)
        with self._lock:
            self._sessions[info.session_id] = sess
        try:
            sess.start(restore_from=restore_from)
        except Exception:
            with self._lock:   # so the sandbox doesn't keep accruing charges if provisioning fails
                self._sessions.pop(info.session_id, None)
            try:
                sandbox.stop()
            except Exception as e:  # noqa: BLE001
                log.warning("sandbox stop after failed start: %s", e)
            raise
        return sess

    def get(self, session_id: str) -> DevSession:
        with self._lock:
            if session_id not in self._sessions:
                raise KeyError(session_id)
            return self._sessions[session_id]

    def list(self) -> list[SessionInfo]:
        with self._lock:
            return [s.info for s in self._sessions.values()]

    def close(self, session_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess:
            try:
                sess.close()
            finally:
                if hasattr(self.store, "evict"):
                    self.store.evict(session_id)

    def close_all(self) -> None:
        for sid in list(self._sessions):
            try:
                self.close(sid)
            except Exception as e:
                log.warning("close %s failed: %s", sid, e)

    def detach(self, session_id: str) -> None:
        """Forget one session in this process without stopping its sandbox or Pods (another process owns them now)."""
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess is not None:
            sess.detach()

    def detach_all(self) -> None:
        """Process exit under a session registry: keep sandboxes and Pods for the next microVM."""
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in sessions:
            try:
                sess.detach()
            except Exception as e:  # noqa: BLE001
                log.warning("detach %s failed: %s", sess.info.session_id, e)

    def attach(self, record: dict[str, Any]) -> DevSession:
        """Rebuild a DevSession from a registry record: adopt the Code Interpreter session and reconnect to its Pods.
        Raises if the sandbox is gone; a caller then creates a fresh session and lets Job deadlines reclaim the Pods."""
        session_id = record.get("session_id")
        if not isinstance(session_id, str) or not re.fullmatch(r"sess_[0-9a-f]{12}", session_id):
            raise ValueError("registry record has an invalid session id")
        with self._lock:
            if session_id in self._sessions:
                return self._sessions[session_id]
        info = self.load_session_info(session_id)
        sandbox = self._sandbox_factory(info.profile)
        if not record.get("sandbox_session_id"):
            raise RuntimeError("record has no sandbox session")
        if hasattr(sandbox, "attach"):
            sandbox.attach(record["sandbox_session_id"])
        else:
            sandbox.start()
        recorder = Recorder(session_id, self.store, memory_client=self._memory_client, memory_id=self.settings.memory_id)
        sess = DevSession(info, sandbox, recorder, self.settings, self.store)
        info.sandbox_session_id = sandbox.session_id
        info.workspace_path = record.get("workspace_path") or info.workspace_path
        sess.emulator.workspace_path = info.workspace_path
        sess.mocks = MockServiceEmulator(sandbox, info.workspace_path)
        info.status = "ready"
        sess.begin_run("reattach", actor="system")
        try:
            for host_record in record.get("hosts") or []:
                self._attach_host(sess, host_record)
            sess.end_run("succeeded")
        except Exception:
            sess.detach()
            sess.end_run("failed")
            raise
        with self._lock:
            self._sessions[session_id] = sess
        return sess

    def _attach_host(self, sess: DevSession, host_record: dict[str, Any]) -> None:
        kind = host_record.get("kind")
        if kind == "workload":
            from cwe.workload import EKSWorkloadHost, WorkloadProfile

            host = EKSWorkloadHost.from_env(self.settings)
            client = host.attach(host_record)
            profile = WorkloadProfile.model_validate(host_record["profile"]) if host_record.get("profile") else None
            sess._attach_workload(client, host, profile)
        elif kind == "android":
            from cwe.eks import EKSEmulatorHost

            host = EKSEmulatorHost.from_env(self.settings)
            sess.attach_android(host.attach(host_record), host)
        else:
            raise ValueError(f"unknown host kind {kind!r}")

    def load_session_info(self, session_id: str) -> SessionInfo:
        """Reads (closed) session metadata from the store. Used for snapshot restore/replay."""
        return SessionInfo.model_validate_json(self.store.get(session_id, "session.json").decode("utf-8"))

    def open_recorded(self, session_id: str) -> DevSession:
        """Opens a closed session from its recordings only (no sandbox). Used for post-hoc scoring, replay, and comparison."""
        from cwe.sandbox import ReplaySandbox

        info = self.load_session_info(session_id)
        recorder = Recorder(session_id, self.store)
        sandbox = ReplaySandbox(recorder.events(), strict=False)   # session_id is None -> offline mode
        sess = DevSession(info, sandbox, recorder, self.settings, self.store)
        for run in info.runs:
            sess._run_results[run.run_id] = sess.results_from_events(run.run_id)
        return sess

    def events_path(self, session_id: str) -> str | None:
        if hasattr(self.store, "path"):
            p = self.store.path(session_id, Recorder.EVENTS_FILE)
            return p if os.path.exists(p) else None
        return None
