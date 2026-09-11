"""Example of attaching a session to an agent you already built with the Claude Agent SDK.

Keep your own ClaudeAgentOptions and ClaudeSDKClient loop as-is; just add two lines to
mcp_servers and hooks to get sandbox execution, recording, budget enforcement, harness
verification, evaluation, and post-hoc grading, all at once.

    set -a && source .env && set +a
    python examples/bring_your_own_agent.py
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile

from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, ClaudeSDKClient, ResultMessage, TextBlock

from cwe.agent import _UsageMeter, cwe_env, cwe_hooks, cwe_mcp_server, record_result, result_from
from cwe.emulator import load_profile
from cwe.models import EvalCriteria, RunBudget
from cwe.session import SessionManager

TESTS = '''
from payment_client import charge, get_charge

def test_charge():
    assert charge(1000)["status"] == "succeeded"

def test_lookup():
    assert get_charge("ch_123")["amount"] == 1000
'''
TASK = "Implement payment_client.py against the mock payment API and make the tests pass."
MODEL = "us.anthropic.claude-opus-5"


async def my_agent(session, task: str):
    """Caller-owned code. The prompt, model, and loop all belong to the caller."""
    meter = _UsageMeter(MODEL)                                     # collects per-turn usage so the hook can see the cost budget (optional)
    cfg_dir = tempfile.mkdtemp(prefix="cwe-claude-cfg-")           # the CLI writes conversation history here, so remove it once the run ends
    options = ClaudeAgentOptions(
        system_prompt="You are my team's coding agent. Use the cwe tools for every file and command; verify with run_tests before finishing.",
        model=MODEL,
        env=cwe_env(config_dir=cfg_dir),                           # Bedrock, isolated from this machine's Claude Code config, does not inherit unrelated secrets
        strict_mcp_config=True,
        tools=[],                                                  # disable local filesystem tools; all work happens in the sandbox
        permission_mode="dontAsk",                                 # anything outside allowed_tools is denied without asking (closed tool list)
        max_turns=40,
        # these two lines are the entirety of the session wiring
        mcp_servers={"cwe": cwe_mcp_server(session)},
        allowed_tools=["mcp__cwe"],
        hooks=cwe_hooks(session, meter),
    )
    texts, final = [], None
    try:
        async with ClaudeSDKClient(options) as client:
            await client.query(task)
            async for m in client.receive_response():
                if isinstance(m, AssistantMessage):
                    meter.add(getattr(m, "usage", None), getattr(m, "message_id", None))
                    for b in m.content:
                        if isinstance(b, TextBlock) and b.text.strip():
                            texts.append(b.text)
                            session.message(b.text, role="assistant")   # must be recorded in the transcript for the AI judge to see it
                elif isinstance(m, ResultMessage):
                    final = m
    finally:
        shutil.rmtree(cfg_dir, ignore_errors=True)
    return result_from(final, meter, MODEL, texts)


def main():
    mgr = SessionManager()
    sess = mgr.create(profile=load_profile("examples/profiles/python-service.yaml"), tags={"example": "byo-agent"})
    print("session:", sess.info.session_id)
    try:
        sess.begin_run("seed"); sess.write_files({"test_payment.py": TESTS}); sess.end_run()

        run = sess.begin_run(TASK[:80], actor="agent", metadata={"task": TASK, "model_id": MODEL}, budget=RunBudget(max_executions=40, max_cost_usd=3.0))
        sess.message(TASK, role="user")
        result = asyncio.run(my_agent(sess, TASK))
        status = record_result(sess, run, result, MODEL)
        sess.end_run(status)
        print("agent:", status, "| turns", result.num_turns, "| exec", run.exec_count, "| usage", run.usage, "| cost", run.cost_usd_estimate)

        with open("examples/criteria/payment-task.json", encoding="utf-8") as f:
            criteria = EvalCriteria.model_validate(json.load(f))
        report = sess.evaluate(criteria, task=TASK, run_id=run.run_id, manager=mgr)
        print("EVAL:", report.summary)
        for i in report.items:
            print(f"  - [{i.source}] {i.name}: {i.score:.2f} {'PASS' if i.passed else 'FAIL'} - {i.explanation[:160]}")
    finally:
        mgr.close(sess.info.session_id)


if __name__ == "__main__":
    main()
