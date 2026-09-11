import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def builder(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "device_agent/builder.py"
    spec = importlib.util.spec_from_file_location("cwe_test_builder", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "ROOT", tmp_path / "builds")
    work = mod.ROOT / "b1"
    work.mkdir(parents=True)
    return mod, work


def test_builder_executes_argv_without_inheriting_credentials(builder, monkeypatch):
    mod, work = builder
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-build")
    (work / "gradlew").write_text('printf "%s\\n" "$@"\nprintf "credential=%s\\n" "${AWS_SECRET_ACCESS_KEY-unset}"\n')
    result = mod.run_build("b1", ["assembleDebug", ":app:test"], 5)
    assert result["exit_code"] == 0
    assert ":app:test" in result["log_tail"] and "credential=unset" in result["log_tail"]


def test_builder_rejects_paths_flags_and_symlink_escape(builder, tmp_path):
    mod, work = builder
    (work / "gradlew").write_text("exit 0\n")
    for bid, tasks in (("../../x", ["test"]), ("b1", ["test;id"]), ("b1", ["--init-script"])):
        with pytest.raises(ValueError):
            mod.run_build(bid, tasks, 5)
    (work / "gradlew").unlink()
    outside = tmp_path / "outside"
    outside.write_text("exit 0\n")
    (work / "gradlew").symlink_to(outside)
    with pytest.raises(ValueError, match="inside"):
        mod.run_build("b1", ["test"], 5)


def test_builder_times_out_process_group(builder):
    mod, work = builder
    (work / "gradlew").write_text("sleep 30 &\necho $!\nwait\n")
    result = mod.run_build("b1", ["test"], 1)
    assert result["exit_code"] == 124
    assert result["log_tail"].strip().isdigit()
