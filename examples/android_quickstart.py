"""Android emulator end-to-end: launch EKS Job -> wait for boot -> screenshot/UI dump/tap -> (optional) agent task -> evaluate -> tear down.

    set -a && source .env.eks && set +a   # deploy first: see GUIDE.md
    python examples/android_quickstart.py [--agent] [--apk URL --package com.example]
"""

from __future__ import annotations

import argparse

from cwe.android import AndroidEmulatorProfile
from cwe.models import EvalCheck, EvalCriteria
from cwe.session import SessionManager


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", action="store_true")
    ap.add_argument("--apk")
    ap.add_argument("--package")
    ap.add_argument("--count", type=int, default=1)
    a = ap.parse_args()

    profile = AndroidEmulatorProfile(apk_url=a.apk, package=a.package, count=a.count)
    mgr = SessionManager()
    sess = mgr.create(tags={"example": "android"})
    print("session:", sess.info.session_id)
    try:
        print("starting emulator host (first boot takes several minutes) ...")
        sess.start_android(profile)
        print("device:", sess.device.base_url, sess.device.health())

        task = "Open the Settings app, navigate to 'About emulated device' and report the Android version shown."
        if a.agent:
            from cwe.agent import run_task

            out = run_task(sess, task)
            print("agent:", out["response"][:600])
            run_id = out["run_id"]
        else:
            run = sess.begin_run("manual", metadata={"task": task})
            sess.screenshot()
            sess.device_action("launch", {"package": "com.android.settings"}, sess.device.launch("com.android.settings"))
            nodes = sess.device.ui()
            sess.device_action("ui", {}, {"ok": True, "nodes": len(nodes)})
            print("ui nodes:", [n["text"] for n in nodes if n["text"]][:12])
            sess.screenshot()
            r = sess.device.shell("getprop ro.build.version.release")
            sess.device_action("shell", {"cmd": "getprop ro.build.version.release"}, r)
            print("android version:", r["stdout"].strip())
            sess.end_run()
            run_id = run.run_id

        rep = sess.evaluate(EvalCriteria(checks=[
            EvalCheck(type="device_action_count", value=3),
            EvalCheck(type="no_errors"),
        ], rubric="Did the session open Settings and surface the Android version?", pass_threshold=0.7), task=task, run_id=run_id)
        print("EVAL:", rep.summary)
        for i in rep.items:
            print(f"  - [{i.source}] {i.name}: {i.score:.2f} {'PASS' if i.passed else 'FAIL'} - {i.explanation[:200]}")
        print("artifacts:", sess.info.runs[-1].artifacts if not a.agent else "see run", )
    finally:
        mgr.close(sess.info.session_id)


if __name__ == "__main__":
    main()
