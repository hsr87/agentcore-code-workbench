"""Live proof: AgentCore source → EKS build/install/UI/tests → S3 evidence.

    python examples/eks_demo.py --env-file .env.eks --agent

Requires deployed Terraform roots and pushed images. Cloud resources are used.
Session Jobs and Code Interpreter sessions are closed even after a failed stage.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

import httpx

from cwe.android import AndroidEmulatorProfile
from cwe.models import EvalCheck, EvalCriteria, RunBudget
from cwe.session import SessionManager

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "com.example.cwesample"


def load_env(path: Path) -> None:
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if sep:
            parsed = shlex.split(value, comments=True)
            os.environ[key.strip()] = parsed[0] if parsed else ""


def sample_files() -> dict[str, bytes]:
    root = ROOT / "examples/android-sample"
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in root.rglob("*") if p.is_file()
        and not any(part in (".gradle", "build", ".DS_Store", "local.properties") for part in p.relative_to(root).parts)
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env.eks")
    parser.add_argument("--agent", action="store_true", help="Also demonstrate an agent fixing a seeded Android bug")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image", help="Override the emulator image")
    parser.add_argument("--operator-role-arn", help="Assume the Terraform operator role for this process only")
    args = parser.parse_args()
    load_env(args.env_file)
    principal = None
    if args.operator_role_arn:
        import boto3

        assumed = boto3.client("sts").assume_role(
            RoleArn=args.operator_role_arn, RoleSessionName="cwe-eks-proof", DurationSeconds=3600,
        )
        credentials = assumed["Credentials"]
        for name, key in (("AWS_ACCESS_KEY_ID", "AccessKeyId"), ("AWS_SECRET_ACCESS_KEY", "SecretAccessKey"),
                          ("AWS_SESSION_TOKEN", "SessionToken")):
            os.environ[name] = credentials[key]
        os.environ.pop("AWS_PROFILE", None)
        os.environ.pop("AWS_DEFAULT_PROFILE", None)
        boto3.DEFAULT_SESSION = None
        principal = assumed["AssumedRoleUser"]["Arn"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output or ROOT / ".cwe_data/eks-demo" / stamp
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = {"started_at": stamp, "stages": {}, "passed": False}
    started = time.monotonic()
    manager = SessionManager()
    session = None

    def save():
        (output / "report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, default=str) + "\n")

    def stage(name, value):
        result["stages"][name] = value
        save()
        print(f"{name}: {json.dumps(value, ensure_ascii=False, default=str)}", flush=True)

    try:
        if principal:
            # Prove that this identity cannot administer nodes or read Secrets.
            permissions = {}
            for verb, resource, namespace in (("create", "jobs", "cwe"), ("get", "secrets", "cwe"),
                                               ("delete", "nodes", None)):
                command = ["kubectl", "--context", os.environ["CWE_EKS_CONTEXT"], "auth", "can-i", verb, resource]
                if namespace:
                    command += ["--namespace", os.environ.get("CWE_EKS_NAMESPACE", namespace)]
                response = subprocess.run(command, capture_output=True, text=True, timeout=60)
                answer = response.stdout.strip()
                assert answer in ("yes", "no"), "could not verify operator RBAC"
                permissions[f"{verb} {resource}"] = answer
            assert permissions == {"create jobs": "yes", "get secrets": "no", "delete nodes": "no"}
            stage("operator_rbac", {"principal": principal, **permissions})
        session = manager.create(tags={"example": "eks-demo"})
        result["session_id"] = session.info.session_id
        result["sandbox_session_id"] = session.info.sandbox_session_id
        stage("agentcore", {"ready": True})
        session.begin_run("seed Android sample")
        session.write_files(sample_files())
        session.end_run()
        profile = AndroidEmulatorProfile(
            boot_timeout=900, job_timeout_seconds=5400, package=PACKAGE,
            **({"image": args.image} if args.image else {}),
        )
        start = time.monotonic()
        session.start_android(profile)
        host = session._device_host
        result["jobs"] = list(host.jobs)
        stage("eks_boot", {"seconds": round(time.monotonic() - start, 2), "devices": session.device.health()})

        session.begin_run("build install UI tests")
        build = session.android_build(timeout=1800)
        stage("build", {k: build.get(k) for k in ("ok", "seconds", "apks", "log_tail")})
        assert build["ok"], "Android build failed"
        installs = session.android_install_built()
        assert installs and all(i.get("ok") for i in installs), "APK install failed"
        stage("install", {"installed": len(installs)})

        device = session.device
        # These calls deliberately omit or mismatch authentication.
        with httpx.Client(base_url=device.base_url, timeout=20) as client:
            unauthenticated = client.get("/health").status_code
            wrong_session = client.get("/health", headers={
                "authorization": f"Bearer {device.token}", "x-cwe-session": "sess_wrong",
            }).status_code
        assert unauthenticated == 401 and wrong_session == 403
        stage("device_auth", {"without_token": unauthenticated, "wrong_session": wrong_session})
        device.screenrecord_start(time_limit=180)
        session.device_action("screenrecord_start", {}, {"ok": True})
        device.shell(f"am force-stop {PACKAGE}")
        session.device_action("launch", {"package": PACKAGE}, device.launch(PACKAGE))
        nodes = device.ui()
        assert any(n["text"] == "Count: 0" for n in nodes), "initial UI counter is not zero"
        (output / "before.png").write_bytes(session.screenshot())
        button = next(n for n in nodes if n["id"].endswith("/increment"))
        for _ in range(3):
            x, y = button["center"]
            session.device_action("tap", {"x": x, "y": y}, device.tap(x, y))
        nodes = device.ui()
        assert any(n["text"] == "Count: 3" for n in nodes), "three taps did not produce Count: 3"
        (output / "after.png").write_bytes(session.screenshot())
        video = device.screenrecord_stop()
        assert len(video) > 1000, "empty screen recording"
        (output / "interaction.mp4").write_bytes(video)
        session.device_action("screenrecord_stop", {}, "ok", artifact=video, artifact_ext="mp4")
        stage("ui_and_recording", {"counter_before": 0, "counter_after": 3, "video_bytes": len(video)})

        # Exercise the authenticated browser viewer and actual streaming frame.
        view_url = device.view_url()
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            response = client.get(view_url)
            assert response.status_code == 200 and "cwe_view" in client.cookies, "viewer token exchange failed"
        frame = device.stream_frame()
        assert frame.startswith(b"\xff\xd8"), "MJPEG stream did not yield JPEG"
        (output / "live-frame.jpg").write_bytes(frame)
        stage("live_view", {"cookie_exchange": True, "jpeg_bytes": len(frame)})

        tests = session.run_instrumented_tests(PACKAGE + ".test", profile.test_runner)
        stage("instrumentation", tests)
        assert tests["passed"] >= 2 and tests["failed"] == 0, "Espresso tests failed"
        run = session.end_run()
        criteria = EvalCriteria(checks=[
            EvalCheck(type="instrumented_tests", value=1.0),
            EvalCheck(type="device_action_count", value=3),
            EvalCheck(type="no_errors"),
        ])
        evaluation = session.evaluate(criteria, run_id=run.run_id, use_llm=False)
        assert evaluation.passed, evaluation.summary
        stage("evaluation", evaluation.model_dump(mode="json"))
        result["baseline_run_id"] = run.run_id

        if args.agent:
            from cwe.agent import run_task

            # Give the agent a real implementation bug, then verify independently.
            path = "app/src/main/java/com/example/cwesample/MainActivity.kt"
            source = sample_files()[path].decode().replace("count += 1", "count += 2")
            session.begin_run("seed off-by-one bug")
            session.write_files({path: source})
            session.end_run()
            agent = run_task(
                session,
                "The Android counter implementation has a bug: pressing Increment must add exactly one. "
                "Read app/src/main/java/com/example/cwesample/MainActivity.kt, fix it without changing the tests, "
                "use android_build then android_install_built to deploy both APKs, and run android_run_tests "
                "with test_package=com.example.cwesample.test. Preserve the UI IDs and Count text format. "
                "Finish only after the instrumentation tests pass.",
                budget=RunBudget(max_executions=60, max_seconds=1800, max_cost_usd=8),
            )
            stage("agent", agent)
            assert agent["status"] == "succeeded", "agent run did not succeed"
            session.begin_run("independent agent verification")
            source = session.read_file(path)
            if isinstance(source, bytes):
                source = source.decode()
            assert "count += 1" in source, "agent did not fix the implementation"
            verification = session.run_instrumented_tests(PACKAGE + ".test", profile.test_runner)
            assert verification["passed"] >= 2 and verification["failed"] == 0, "agent result failed independent tests"
            session.end_run()
            stage("agent_verification", verification)

        snapshot = session.snapshot("verified Android source")
        stage("snapshot", {"snapshot_id": snapshot.snapshot_id, "size_bytes": snapshot.size_bytes})
        restored = manager.create(restore_from=snapshot, tags={"example": "eks-demo-restore"})
        try:
            path = "app/src/main/java/com/example/cwesample/MainActivity.kt"
            restored_source = restored.read_file(path)
            if isinstance(restored_source, bytes):
                restored_source = restored_source.decode()
            assert "count += 1" in restored_source, "restored source differs from the verified source"
            stage("snapshot_restore", {"source_matches": True})
        finally:
            manager.close(restored.info.session_id)
        result["artifacts"] = [artifact for run in session.info.runs for artifact in run.artifacts]
        result["passed"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        # Capture diagnostics before the session lifecycle removes failed Jobs.
        host = getattr(session, "_device_host", None) if session else None
        if host and hasattr(host, "_command"):
            for job in result.get("jobs", host.jobs):
                try:
                    response = subprocess.run(
                        host._command("logs", f"job/{job}", "--all-containers=true", "--tail=100"),
                        capture_output=True, text=True, timeout=30,
                    )
                    logs = re.sub(r"(vt=)[^&\s\"]+", r"\1[redacted]", response.stdout + response.stderr)
                    (output / f"{job}.log").write_text(logs)
                except Exception:
                    pass
        raise
    finally:
        if session:
            try:
                manager.close(session.info.session_id)
                stage("session_close", {"status": session.info.status})
                if result["passed"]:
                    recorded = manager.open_recorded(session.info.session_id)
                    report = recorded.evaluate(criteria, run_id=result["baseline_run_id"], use_llm=False)
                    assert report.passed, "post-hoc evaluation failed"
                    stage("post_hoc_evaluation", {"passed": report.passed, "score": report.overall_score})
                    # Download artifacts from the actual S3 store as a persistence check.
                    for uri in result.get("artifacts", []):
                        name = uri.rsplit("/", 1)[-1]
                        payload = manager.store.get(session.info.session_id, f"artifacts/{name}")
                        assert payload, f"missing S3 artifact {name}"
                    stage("s3_evidence", {"verified_objects": len(result.get("artifacts", []))})
            except Exception as exc:
                result["passed"] = False
                result["cleanup_or_persistence_error"] = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                result["seconds"] = round(time.monotonic() - started, 2)
                save()
        else:
            save()
    print(f"PASS: {output / 'report.json'}", flush=True)


if __name__ == "__main__":
    main()
