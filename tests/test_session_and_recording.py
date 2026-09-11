from cwe.models import EvalCheck, EvalCriteria
from cwe.sandbox import ReplaySandbox
from cwe.session import SessionManager


def test_session_records_and_evaluates(manager):
    sess = manager.create()
    assert sess.info.status == "ready"
    sess.begin_run("t1")
    sess.write_files({"app.py": "print('hi')"})
    r = sess.run_command("echo hello")
    assert r.ok and "hello" in r.output
    bad = sess.run_command("exit 1")
    assert bad.is_error
    sess.end_run("succeeded")

    events = sess.recorder.events()
    kinds = [e["event_type"] for e in events]
    assert kinds.count("exec") >= 4  # provision(2) + write + echo + exit
    assert any(e["payload"].get("files") for e in events if e["event_type"] == "exec")

    report = sess.evaluate(EvalCriteria(checks=[
        EvalCheck(type="stdout_contains", value="hello"),
        EvalCheck(type="no_errors", weight=0.5),
        EvalCheck(type="exit_code", value=1, description="last exit is 1"),
    ], pass_threshold=0.6), use_llm=False)
    names = {i.name: i for i in report.items}
    assert names["stdout_contains"].passed
    assert not names["no_errors"].passed
    assert names["last exit is 1"].passed
    assert report.passed and 0.6 <= report.overall_score < 1.0

    transcript = sess.recorder.transcript()
    assert "echo hello" in transcript and "eval" in transcript
    manager.close(sess.info.session_id)
    assert sess.info.status == "closed"


def test_replay_reproduces_recorded_run(manager, tmp_path):
    sess = manager.create()
    sess.begin_run("record")
    sess.run_command("echo replay-me")
    sess.end_run()
    events_path = manager.events_path(sess.info.session_id)
    assert events_path
    manager.close(sess.info.session_id)

    # replays the recording without AWS
    replay_mgr = SessionManager(settings=manager.settings, sandbox_factory=lambda p: ReplaySandbox.from_jsonl(events_path))
    rs = replay_mgr.create()
    rs.begin_run("replay")
    r = rs.run_command("echo replay-me")
    assert r.output.strip() == "replay-me"
    rep = rs.evaluate(EvalCriteria(checks=[EvalCheck(type="stdout_contains", value="replay-me")]), use_llm=False)
    assert rep.passed


def test_session_json_persisted(manager):
    sess = manager.create(tags={"owner": "dev1"})
    info = manager.load_session_info(sess.info.session_id)
    assert info.tags == {"owner": "dev1"} and info.status == "ready"


def test_transcript_includes_written_files_and_strips_ansi(manager):
    sess = manager.create()
    sess.begin_run("files")
    sess.write_files({"app.py": "print('\x1b[32mgreen\x1b[0m')"})
    sess.end_run()
    t = sess.recorder.transcript()
    assert "--- wrote app.py ---" in t and "print('green')" in t and "\x1b[" not in t


def test_store_rejects_path_traversal(tmp_path):
    import pytest
    from cwe.recorder import _LocalStore, validate_key

    st = _LocalStore(str(tmp_path / "store"))
    for bad in ("../x", "..", "/etc", "a/b", "sess x"):
        with pytest.raises(ValueError):
            st.path(bad, "session.json")
    with pytest.raises(ValueError):
        st.path("sess_ok", "../../evil")
    validate_key("sess_ok", "artifacts/run_1_0001.png")
