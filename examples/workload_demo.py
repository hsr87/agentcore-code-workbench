"""Backend service on an EKS workload Pod: the "code emulator" story, driven from a laptop or CI.

    set -a; source .env.eks; set +a
    python examples/workload_demo.py            # build, run and probe the Java sample on the Pod
    python examples/workload_demo.py --agent    # also seed a bug and let the agent fix it using remote_* tools

Flow: the Java sample lands in the Code Interpreter sandbox (where the agent edits code), a workload Pod is started from
`WorkloadProfile` (memory and disk the microVM does not have), the workspace is synced into the Pod, `./gradlew test
installDist` runs there, the service is started and probed over HTTP from inside the Pod. With --agent a bug is seeded in
/health, and the agent has to fix it in the sandbox, rebuild and restart on the Pod, and prove it with a probe; the harness
then re-runs the tests itself. Cloud resources are used; everything is closed at the end even after a failure.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import time

from cwe.models import RunBudget
from cwe.session import SessionManager
from cwe.workload import WorkloadProfile

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples/java-service-sample"
PORT = 8081
BUILD = "./gradlew --no-daemon -q test installDist"
RUN = f"PORT={PORT} build/install/order-service/bin/order-service"


def sample_files() -> dict[str, bytes]:
    return {str(p.relative_to(SAMPLE)): p.read_bytes() for p in SAMPLE.rglob("*")
            if p.is_file() and not any(part in ("build", ".gradle") for part in p.relative_to(SAMPLE).parts)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent", action="store_true")
    parser.add_argument("--memory", default="16Gi")
    parser.add_argument("--disk", default="50Gi")
    parser.add_argument("--image", default=None, help="workload image (default: CWE_WORKLOAD_IMAGE)")
    parser.add_argument("--output", type=Path, default=ROOT / ".cwe_data/workload-demo")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report: dict = {"started_at": stamp, "stages": {}, "passed": False}
    started = time.monotonic()

    def stage(name, **kw):
        kw["t"] = round(time.monotonic() - started, 1)
        report["stages"][name] = kw
        print(f"[{kw['t']:7.1f}s] {name}: {json.dumps({k: v for k, v in kw.items() if k != 't'}, default=str)[:700]}", flush=True)

    manager = SessionManager()
    session = manager.create()
    try:
        stage("sandbox", session_id=session.info.session_id, sandbox=session.info.sandbox_session_id)
        session.begin_run("prepare")
        session.write_files(sample_files())
        session.run_command("chmod +x gradlew && ls")
        session.end_run()

        session.start_workload(WorkloadProfile(image=args.image or os.environ.get("CWE_WORKLOAD_IMAGE", ""), memory=args.memory, ephemeral_storage=args.disk))
        h = session.workload.health()
        stage("workload", job=session.registry_record("")["hosts"][0]["job"], cpus=h.get("cpus"),
              mem_gib=round((h.get("mem_total_bytes") or 0) / 2**30, 1), disk_free_gib=round((h.get("disk_free_bytes") or 0) / 2**30, 1))

        session.begin_run("build-and-run")
        sync = session.sync_workspace_to_workload()
        stage("sync", bytes=sync.get("bytes"), files=sync.get("files"), seconds=sync.get("seconds"))
        session.workload_exec("chmod +x gradlew", timeout=30)
        build = session.workload_exec(BUILD, timeout=1800)
        stage("build", exit_code=build.exit_code, seconds=build.execution_time, tail=build.stdout[-400:])
        if build.exit_code != 0:
            raise RuntimeError("gradle build failed")
        session.workload_start("svc", RUN)
        probe = None
        for _ in range(30):
            probe = session.workload_probe(PORT, "/health")
            if probe.get("status"):
                break
            time.sleep(1)
        order = session.workload_probe(PORT, "/orders/1001")
        stage("service", health=probe.get("status"), health_body=probe.get("body"), order=order.get("status"), order_body=order.get("body"))
        session.end_run()
        report["stages"]["service"]["ok"] = probe.get("status") == 200 and order.get("status") == 200

        if args.agent:
            from cwe.agent import run_task

            src = "src/main/java/com/example/svc/Main.java"
            session.begin_run("seed-bug")
            code = session.read_file(src)
            code = code.decode() if isinstance(code, bytes) else code
            session.write_files({src: code.replace('return "{\\"status\\":\\"ok\\"}";', 'return "{\\"status\\":\\"degraded\\"}";')})
            session.workload_stop("svc")
            session.end_run()
            task = (f"The order-service in the workspace has a regression: GET /health must return {{\"status\":\"ok\"}} but the unit test "
                    f"healthReportsOk fails. Fix the source in the sandbox workspace, then verify on the workload Pod: run remote_sync_workspace, "
                    f"then `{BUILD}` with remote_shell, start the service with remote_start (name: svc, command: `{RUN}`), and confirm with "
                    f"remote_probe on port {PORT} path /health that the body contains \"ok\". Report what you changed.")
            result = run_task(session, task, manager.settings, budget=RunBudget(max_executions=25, max_seconds=900, max_cost_usd=2.0))
            stage("agent", status=result["status"], executions=result["exec_count"], cost_usd=result["cost_usd_estimate"],
                  turns=result["harness"].get("num_turns"), response=result["response"][-600:])
            # The harness does not trust the agent: it re-syncs, re-runs the tests and probes the service itself.
            session.begin_run("harness-verify", actor="system")
            session.sync_workspace_to_workload(actor="system")
            tests = session.workload_exec("./gradlew --no-daemon -q test", timeout=900, actor="system")
            try:
                session.workload_stop("svc", actor="system")
            except Exception:  # noqa: BLE001
                pass
            session.workload_exec(BUILD, timeout=900, actor="system")
            session.workload_start("svc", RUN, actor="system")
            time.sleep(3)
            probe = session.workload_probe(PORT, "/health", actor="system")
            session.end_run()
            stage("harness_verify", tests_exit=tests.exit_code, health=probe.get("status"), body=probe.get("body"))
            report["stages"]["harness_verify"]["ok"] = tests.exit_code == 0 and probe.get("status") == 200 and '"ok"' in (probe.get("body") or "")
        report["passed"] = all(s.get("ok", True) for s in report["stages"].values())
    except Exception as e:  # noqa: BLE001
        stage("error", error=str(e)[:800])
    finally:
        manager.close(session.info.session_id)
        report["events"] = f"{manager.settings.storage_uri}/{session.info.session_id}/events.jsonl"
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / f"{stamp}.json").write_text(json.dumps(report, indent=2, default=str))
        print("PASSED" if report["passed"] else "FAILED", "->", args.output / f"{stamp}.json")


if __name__ == "__main__":
    main()
