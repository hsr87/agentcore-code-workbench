"""Three harness delegations: context (summary only), verification (harness re-runs), execution (budget)."""
import pytest

from cwe.agent import summarize_output
from cwe.models import BudgetExceeded, EvalCheck, EvalCriteria, RunBudget


def test_summarize_output_folds_middle_and_keeps_ends():
    text = "HEAD" + "x" * 5000 + "TAIL"
    s = summarize_output(text, limit=200)
    assert s.startswith("HEAD") and s.endswith("TAIL") and "chars omitted" in s and len(s) < 300
    assert summarize_output("short", limit=200) == "short"


def test_full_output_kept_outside_context(manager):
    sess = manager.create()
    sess.begin_run("ctx")
    sess.run_command("echo hello")
    ref = sess.last_exec_ref()
    assert sess.full_output(ref).strip() == "hello"
    assert sess.full_output("nope") is None


def test_budget_stops_run_by_executions(manager):
    sess = manager.create()
    run = sess.begin_run("b", budget=RunBudget(max_executions=2))
    sess.run_command("echo 1"); sess.run_command("echo 2")
    with pytest.raises(BudgetExceeded, match="max_executions"):
        sess.run_command("echo 3")
    assert run.harness["budget_exceeded"].startswith("max_executions") and run.harness["executions"] == 2


def test_budget_by_cost(manager):
    sess = manager.create()
    sess.begin_run("c", budget=RunBudget(max_cost_usd=0.5))
    sess.check_budget(cost_usd=0.4)
    with pytest.raises(BudgetExceeded, match="max_cost_usd"):
        sess.check_budget(cost_usd=0.6)


def test_harness_verification_overrides_agent_claim(manager):
    """Even if the agent prints '2 passed', only the result the harness runs itself counts."""
    sess = manager.create()
    sess.begin_run("v")
    sess.run_command("echo 2 passed in 0.1s")          # the agent's claim (FakeSandbox supports only echo)
    report = sess.verify("exit 1", mode="same")        # harness verification fails
    assert report["exit_code"] == 1 and report["mode"] == "same"
    rep = sess.evaluate(EvalCriteria(checks=[EvalCheck(type="harness_verification", weight=2)], verify_command="exit 1"), use_llm=False)
    assert not rep.passed and "harness ran 'exit 1'" in rep.items[0].explanation
    assert any(e["payload"].get("action") == "harness_verification" for e in sess.recorder.events())


def test_harness_verification_passes_when_command_succeeds(manager):
    sess = manager.create()
    sess.begin_run("v2")
    rep = sess.evaluate(EvalCriteria(checks=[EvalCheck(type="harness_verification")], verify_command="echo ok"), use_llm=False)
    assert rep.passed and rep.items[0].passed


def test_build_agent_constructs_without_aws(manager):
    """The agent and its tool set are constructed without a Bedrock call (regression guard)."""
    from cwe.agent import build_agent
    from cwe.config import Settings

    sess = manager.create()
    agent = build_agent(sess, Settings(region="us-east-1"))
    assert agent is not None
    assert {"run_shell", "write_and_run", "read_full_output", "run_tests"} <= set(agent.tool_names)


def test_verification_attaches_to_target_run_even_after_adhoc_run(manager):
    """Even if something like snapshot() creates a temporary run right before evaluation, verification still attaches to the target run (a regression caught on a real account)."""
    sess = manager.create()
    run = sess.begin_run("agent")
    sess.run_command("echo work")
    sess.end_run()
    sess.begin_run("adhoc-like"); sess.end_run()
    rep = sess.evaluate(EvalCriteria(checks=[EvalCheck(type="harness_verification")], verify_command="echo ok"), run_id=run.run_id, use_llm=False)
    assert rep.passed and run.harness["verification"]["exit_code"] == 0
