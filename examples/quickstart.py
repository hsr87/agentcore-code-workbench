"""End-to-end example: environment emulation -> code execution/recording -> snapshot -> rule+LLM evaluation -> offline replay.

    python examples/quickstart.py            # uses the real AgentCore sandbox (needs AWS credentials)
    python examples/quickstart.py --agent    # also delegates the task to a Claude Agent SDK agent
"""

from __future__ import annotations

import json
import sys

from cwe.emulator import load_profile
from cwe.models import EvalCriteria
from cwe.sandbox import ReplaySandbox
from cwe.session import SessionManager

CLIENT = '''
import os, requests

BASE = os.environ["PAYMENT_API_URL"]

def charge(amount: int) -> dict:
    r = requests.post(f"{BASE}/charge", json={"amount": amount}, timeout=5)
    r.raise_for_status()
    return r.json()

def get_charge(charge_id: str) -> dict:
    r = requests.get(f"{BASE}/charge/{charge_id}", timeout=5)
    r.raise_for_status()
    return r.json()
'''

TESTS = '''
from payment_client import charge, get_charge

def test_charge():
    assert charge(1000)["status"] == "succeeded"

def test_lookup():
    assert get_charge("ch_123")["amount"] == 1000
'''


def main():
    use_agent = "--agent" in sys.argv
    profile = load_profile("examples/profiles/python-service.yaml")
    with open("examples/criteria/payment-task.json", encoding="utf-8") as f:
        criteria = EvalCriteria.model_validate(json.load(f))
    task = "Implement payment_client.py against the mock payment API and make the tests pass."

    mgr = SessionManager()
    sess = mgr.create(profile=profile, tags={"example": "quickstart"})
    print("session:", sess.info.session_id, "| sandbox:", sess.info.sandbox_session_id, "| ws:", sess.info.workspace_path)
    events_path = None
    try:
        if use_agent:
            from cwe.agent import run_task
            from cwe.models import RunBudget

            sess.begin_run("seed")
            sess.write_files({"test_payment.py": TESTS})
            sess.end_run()
            # Harness budget: complete within 40 executions, 15 minutes, $3 without human approval
            out = run_task(sess, task, budget=RunBudget(max_executions=40, max_seconds=900, max_cost_usd=3.0))
            print("agent:", out["status"], out["response"][:400])
            print("usage:", out["usage"], "| cost_usd_estimate:", out["cost_usd_estimate"])
            print("harness:", {k: v for k, v in out["harness"].items() if k != "verification"})
            run_id = out["run_id"]
        else:
            run = sess.begin_run("manual", metadata={"task": task})
            sess.write_files({"payment_client.py": CLIENT, "test_payment.py": TESTS})
            r = sess.run_command("curl -s $PAYMENT_API_URL/health")
            print("mock health:", r.output.strip())
            r = sess.run_pytest("-q")
            print("pytest:", r.output.strip().splitlines()[-1])
            sess.end_run()
            run_id = run.run_id

        print("mock payment received:", sess.mocks.requests_log("payment"))
        snap = sess.snapshot("after tests")
        print("snapshot:", snap.uri, snap.size_bytes, "bytes")

        report = sess.evaluate(criteria, task=task, run_id=run_id, manager=mgr)   # verify_mode=fresh restores the snapshot into a new session to verify
        v = next((r.harness.get("verification") for r in sess.info.runs if r.run_id == run_id), None)
        if v:
            print("harness verification:", v["mode"], "exit", v["exit_code"], v["pytest"])
        print("EVAL:", report.summary)
        for i in report.items:
            print(f"  - [{i.source}] {i.name}: {i.score:.2f} {'PASS' if i.passed else 'FAIL'} - {i.explanation[:200]}")
        events_path = mgr.events_path(sess.info.session_id)
    finally:
        mgr.close(sess.info.session_id)

    if events_path:
        print("\n--- offline replay from", events_path)
        rmgr = SessionManager(settings=mgr.settings, sandbox_factory=lambda p: ReplaySandbox.from_jsonl(events_path, strict=False))
        rs = rmgr.create(profile=profile)
        rs.begin_run("replay")
        r = rs.run_pytest("-q")
        print("replayed pytest:", r.output.strip().splitlines()[-1] if r.output.strip() else "(no recording)")
        rs.end_run()
        rmgr.close(rs.info.session_id)


if __name__ == "__main__":
    main()
