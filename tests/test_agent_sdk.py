"""Claude Agent SDK integration: session tools are exposed as MCP tools, the budget hook blocks calls, and the result is recorded onto the run (without AWS)."""
import asyncio
import json

import pytest

from cwe.agent import (AgentResult, SERVER_NAME, _UsageMeter, build_agent, build_options, cwe_hooks, cwe_tools, record_result,
                       result_from, run_sync)
from cwe.android import FakeAndroidDevice
from cwe.config import Settings
from cwe.models import RunBudget


def _tool(tools, name):
    return next(t for t in tools if t.name == name)


def _call(tools, name, args=None):
    return asyncio.run(_tool(tools, name).handler(args or {}))


def test_tools_execute_through_session_and_record(manager):
    sess = manager.create()
    sess.begin_run("t")
    tools = cwe_tools(sess)
    out = _call(tools, "run_shell", {"command": "echo hello"})
    body = json.loads(out["content"][0]["text"])
    assert body["exit_code"] == 0 and "hello" in body["output"] and body["ref"]
    assert sess.full_output(body["ref"]).strip() == "hello"
    out = _call(tools, "write_and_run", {"path": "a.py", "content": "print(1)", "command": "echo ran"})
    assert out["content"][0]["text"].startswith("wrote a.py (1 lines)")
    assert sess.info.runs[-1].exec_count == 3          # echo, write, run
    assert _call(tools, "read_full_output", {"ref": "nope"})["is_error"]


def test_tools_return_error_result_instead_of_raising(manager):
    sess = manager.create()
    sess.begin_run("e", budget=RunBudget(max_executions=1))
    tools = cwe_tools(sess)
    _call(tools, "run_shell", {"command": "echo 1"})
    out = _call(tools, "run_shell", {"command": "echo 2"})
    assert out["is_error"] and "harness budget" in out["content"][0]["text"]
    assert sess.info.runs[-1].harness["budget_exceeded"].startswith("max_executions")


def test_pre_tool_use_hook_denies_and_stops_when_budget_exceeded(manager):
    sess = manager.create()
    sess.begin_run("h", budget=RunBudget(max_executions=1, max_cost_usd=0.5))
    meter = _UsageMeter("us.anthropic.claude-opus-5")
    hook = cwe_hooks(sess, meter)["PreToolUse"][0].hooks[0]
    inp = {"hook_event_name": "PreToolUse", "tool_name": f"mcp__{SERVER_NAME}__run_shell", "tool_input": {}, "tool_use_id": "x"}
    assert asyncio.run(hook(inp, "x", {})) == {}                       # within budget
    meter.add({"input_tokens": 200_000, "output_tokens": 0}, "m1")      # a dollar's worth -> exceeds the cost budget
    meter.add({"input_tokens": 200_000, "output_tokens": 0}, "m1")      # the same message is not counted twice
    assert meter.as_usage()["inputTokens"] == 200_000
    out = asyncio.run(hook(inp, "x", {}))
    assert out["continue_"] is False and out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "max_cost_usd" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_build_options_targets_bedrock_and_only_sandbox_tools(manager):
    sess = manager.create()
    opts = build_options(sess, Settings(region="us-east-1"), budget=RunBudget(max_cost_usd=2.0), max_turns=5)
    assert opts.tools == [] and opts.allowed_tools == [f"mcp__{SERVER_NAME}"] and SERVER_NAME in opts.mcp_servers
    assert opts.env["CLAUDE_CODE_USE_BEDROCK"] == "1" and opts.model == "us.anthropic.claude-opus-5"
    assert opts.strict_mcp_config and opts.env["CLAUDE_CONFIG_DIR"] and "cwe-claude-cfg-" in opts.env["CLAUDE_CONFIG_DIR"]
    assert opts.max_budget_usd == 2.0 and opts.max_turns == 5 and "PreToolUse" in opts.hooks


def test_build_agent_exposes_android_tools_when_device_attached(manager):
    sess = manager.create()
    sess.begin_run("a"); sess.attach_android(FakeAndroidDevice()); sess.end_run()
    agent = build_agent(sess, Settings(region="us-east-1"))
    assert {"android_screenshot", "android_tap", "android_build", "android_install_built", "android_live_view_url"} <= set(agent.tool_names)
    sess.begin_run("shot")
    out = _call(cwe_tools(sess), "android_screenshot")
    assert out["content"][0]["type"] == "image" and out["content"][0]["mimeType"] == "image/png"


def test_record_result_marks_cancelled_on_budget(manager):
    sess = manager.create()
    run = sess.begin_run("r", budget=RunBudget(max_executions=1))
    sess.run_command("echo 1")
    with pytest.raises(Exception):
        sess.run_command("echo 2")
    res = AgentResult(text="partial", usage={"inputTokens": 10, "outputTokens": 1, "totalTokens": 11}, cost_usd=0.01, subtype="success")
    assert record_result(sess, run, res, "us.anthropic.claude-opus-5") == "cancelled"
    assert run.usage["totalTokens"] == 11 and run.cost_usd_estimate == 0.01 and run.harness["agent_sdk"] == "claude-agent-sdk"


def test_result_from_prefers_cli_cost_and_counts_cache_tokens():
    class Msg:
        usage = {"input_tokens": 6, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 50, "output_tokens": 20}; message_id = "m"
        total_cost_usd = 0.123456; result = "done"; num_turns = 3; subtype = "success"; is_error = False; terminal_reason = None
    r = result_from(Msg(), _UsageMeter("claude-opus-5"), "claude-opus-5")
    assert r.usage["inputTokens"] == 156 and r.usage["totalTokens"] == 176 and r.cost_usd == 0.1235 and r.text == "done"
    r2 = result_from(None, _UsageMeter("claude-opus-5"), "claude-opus-5", ["last text"])
    assert r2.is_error and r2.text == "last text"


def test_run_sync_works_inside_and_outside_event_loop():
    async def coro():
        return 7
    assert run_sync(coro()) == 7

    async def outer():
        return run_sync(coro())
    assert asyncio.run(outer()) == 7


def test_estimate_cost_discounts_cache_reads():
    from cwe.agent import estimate_cost_usd
    plain = estimate_cost_usd("claude-opus-5", {"inputTokens": 100_000, "outputTokens": 0})
    cached = estimate_cost_usd("claude-opus-5", {"inputTokens": 100_000, "outputTokens": 0, "cacheReadInputTokens": 100_000})
    assert plain == 0.5 and cached == 0.05


def test_build_agent_cleans_temp_dirs(manager):
    import os
    sess = manager.create()
    agent = build_agent(sess, Settings(region="us-east-1"))
    dirs = list(agent.tmp_dirs)
    assert len(dirs) == 2 and all(os.path.isdir(d) for d in dirs) and agent.options.env["CLAUDE_CONFIG_DIR"] in dirs and agent.options.cwd in dirs
    agent.cleanup()
    assert not any(os.path.exists(d) for d in dirs)
