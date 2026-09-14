from cwe.evaluator import RuleEvaluator, RunContext, _extract_json, aggregate, parse_pytest_output
from cwe.models import EvalCheck, ExecKind, ExecResult


def _r(out="", code=0, t=0.1):
    return ExecResult(kind=ExecKind.COMMAND, input="x", stdout=out, exit_code=code, is_error=code != 0, execution_time=t)


def test_parse_pytest_output():
    assert parse_pytest_output("....\n4 passed in 0.02s") == {"passed": 4, "failed": 0, "errors": 0}
    assert parse_pytest_output("F..\n1 failed, 2 passed, 1 error in 0.1s") == {"passed": 2, "failed": 1, "errors": 1}
    assert parse_pytest_output("no tests ran") == {"passed": 0, "failed": 0, "errors": 0}


def test_rule_checks():
    ctx = RunContext(results=[_r("3 passed in 0.1s"), _r("done", 0, 2.0)], files=["a.py", "out/report.json"])
    items = RuleEvaluator().evaluate([
        EvalCheck(type="pytest", value=1.0),
        EvalCheck(type="file_exists", value="out/report.json"),
        EvalCheck(type="stdout_regex", value=r"^\d+ passed"),
        EvalCheck(type="max_execution_time", value=1.0),
        EvalCheck(type="stdout_not_contains", value="Traceback"),
    ], ctx)
    passed = [i.passed for i in items]
    assert passed == [True, True, True, False, True]
    rep = aggregate("s", "r", items, threshold=0.7)
    assert not rep.passed  # FAIL if a single weight>=1 rule fails


def test_extract_json_tolerates_fences():
    assert _extract_json('```json\n{"score": 0.9, "passed": true, "explanation": "ok"}\n```')["score"] == 0.9
    assert _extract_json('Here: {"score": 0.1, "passed": false, "explanation": "x"} bye')["passed"] is False


def test_judge_client_falls_back_to_bedrock_runtime_without_a_mantle_endpoint(monkeypatch):
    import socket

    from anthropic import AnthropicBedrock, AnthropicBedrockMantle

    from cwe.evaluator import make_judge_client

    real = socket.getaddrinfo

    def only_bedrock_runtime(host, *a, **k):
        if host.startswith("bedrock-mantle."):
            raise socket.gaierror("no such host")
        return real(host, *a, **k) if False else []

    monkeypatch.setattr(socket, "getaddrinfo", only_bedrock_runtime)
    assert isinstance(make_judge_client("ap-northeast-2"), AnthropicBedrock)
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [])
    assert isinstance(make_judge_client("us-east-1"), AnthropicBedrockMantle)
