from cwe.models import ExecKind
from cwe.sandbox import normalize

# Fixtures copied verbatim from real AgentCore responses (verified 2026-09)
CODE_ERR = {"content": [{"type": "text", "text": "hi"}, {"type": "text", "text": "ZeroDivisionError: division by zero"}],
            "structuredContent": {"stdout": "hi", "stderr": "ZeroDivisionError: division by zero", "exitCode": 1, "executionTime": 0.117},
            "isError": True}
CMD_NONZERO = {"content": [{"type": "text", "text": "hello\r\n"}],
               "structuredContent": {"stdout": "", "stderr": "hello\r\n", "exitCode": 3, "executionTime": 0.09}, "isError": True}
BG_START = {"content": [{"type": "text", "text": "Successfully started a command execution task"}],
            "structuredContent": {"taskId": "6606f719", "taskStatus": "submitted", "stdout": "", "stderr": ""}, "isError": False}
WRITE = {"content": [{"type": "text", "text": "Successfully wrote all 1 files"}], "isError": False}


def test_code_error():
    r = normalize(ExecKind.CODE, "x=1/0", CODE_ERR, language="python")
    assert r.exit_code == 1 and r.is_error and not r.ok
    assert "ZeroDivisionError" in r.stderr and r.stdout == "hi"


def test_command_nonzero_output_is_in_stderr_but_visible_in_output():
    r = normalize(ExecKind.COMMAND, "echo hello; exit 3", CMD_NONZERO)
    assert r.exit_code == 3
    assert "hello" in r.output


def test_background_task():
    r = normalize(ExecKind.BACKGROUND, "sleep 2", BG_START)
    assert r.task_id == "6606f719" and r.task_status == "submitted" and r.ok


def test_write_without_structured_content_falls_back_to_text():
    r = normalize(ExecKind.FILE_WRITE, "a.txt", WRITE)
    assert r.ok and "Successfully wrote" in r.stdout
