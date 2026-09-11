from cwe.android import AndroidEmulatorProfile, FakeAndroidDevice
from cwe.models import EvalCheck, EvalCriteria


def test_android_session_records_actions_and_artifacts(manager):
    sess = manager.create()
    dev = FakeAndroidDevice()
    sess.begin_run("android")
    sess.attach_android(dev)
    sess.device_action("launch", {"package": "com.example"}, dev.launch("com.example"))
    png = sess.screenshot()
    assert png.startswith(b"\x89PNG")
    nodes = dev.ui()
    x, y = nodes[0]["center"]
    sess.device_action("tap", {"x": x, "y": y}, dev.tap(x, y))
    assert dev.screen == "login"
    rep = sess.run_instrumented_tests("com.example.test", "androidx.test.runner.AndroidJUnitRunner")
    assert rep["passed"] == 3
    sess.end_run()

    run = sess.info.runs[-1]
    assert len(run.artifacts) == 1 and run.artifacts[0].endswith(".png")
    report = sess.evaluate(EvalCriteria(checks=[
        EvalCheck(type="instrumented_tests", value=1.0, weight=2),
        EvalCheck(type="device_action_count", value=3),
        EvalCheck(type="no_errors"),
    ]), use_llm=False)
    assert report.passed, report.summary
    t = sess.recorder.transcript()
    assert "tap" in t and "artifact:" in t


def test_profile_defaults():
    p = AndroidEmulatorProfile()
    assert p.api_level == 30 and "30-google-x64" in p.image


def test_ec2_host_from_env_requires_config(monkeypatch):
    import pytest as _pytest

    from cwe.android import EC2EmulatorHost
    from cwe.config import Settings

    with _pytest.raises(RuntimeError, match="CWE_ANDROID_SUBNET_ID"):
        EC2EmulatorHost.from_env(settings=Settings(android_subnet_id=None, android_security_group_id=None, android_device_agent_image=None))
    host = EC2EmulatorHost.from_env(settings=Settings(android_subnet_id="subnet-1", android_security_group_id="sg-1",
                                                      android_device_agent_image="123.dkr.ecr.us-east-1.amazonaws.com/x:latest", android_instance_type="c8i.2xlarge"))
    assert host.instance_type == "c8i.2xlarge" and host.token and host.instance_profile == "cwe-android-instance-profile"


def test_ec2_host_access_modes():
    import pytest as _pytest

    from cwe.android import EC2EmulatorHost
    from cwe.config import Settings

    st = Settings(android_subnet_id="subnet-1", android_security_group_id="sg-1", android_device_agent_image="r/x:latest", android_access="ssm")
    assert EC2EmulatorHost.from_env(settings=st).access == "ssm"
    with _pytest.raises(ValueError):
        EC2EmulatorHost.from_env(settings=st, access="vpn")


def test_ec2_user_data_renders_agent_and_emulators(monkeypatch):
    """User data template regression guard: includes the agent container, session token, bind address, and N emulators."""
    from cwe.android import AndroidEmulatorProfile, EC2EmulatorHost

    monkeypatch.setattr(EC2EmulatorHost, "__init__", lambda self, **kw: None)
    host = EC2EmulatorHost()
    host.region, host.access, host.token = "us-east-1", "ssm", "literal-9f8e7d6c"
    host.agent_image, host.build_image = "123.dkr.ecr.us-east-1.amazonaws.com/cwe-device-agent:latest", "thyrlian/android-sdk:latest"
    host.token_param = "/cwe/hosts/abc/token"
    ud = host.render_user_data(AndroidEmulatorProfile(count=2, images=["img30", "img34"], emulator_params="-gpu swiftshader_indirect -memory 3072; rm -rf /"), "sess_x")
    assert "literal-9f8e7d6c" not in ud and "/cwe/hosts/abc/token" in ud and "--with-decryption" in ud   # the token comes only from an SSM SecureString
    assert ud.startswith("#!/bin/bash\nset -euo pipefail") and "modprobe kvm" in ud and "docker login" in ud and 'no host token' in ud
    assert 'DEVICE_AGENT_TOKEN="$CWE_TOKEN"' in ud and "DEVICE_AGENT_SESSION=sess_x" in ud and "DEVICE_AGENT_HOST=127.0.0.1" in ud
    assert ud.count("--device /dev/kvm") == 2 and "android-emulator-0" in ud and "android-emulator-1" in ud and "img34" in ud
    assert "-v /opt/cwe:/opt/cwe" in ud and "BUILD_IMAGE=thyrlian/android-sdk:latest" in ud
    assert "EMULATOR_PARAMS='-gpu swiftshader_indirect -memory 3072; rm -rf /'" in ud   # the profile value is a single shell word only (shlex.quote)
    assert "shutdown -h +245" in ud   # 4h job_timeout + 5 minutes of slack: shuts itself down even if the reaper dies
    assert "{" not in ud.replace("{{", "").replace("}}", "") or "{i}" not in ud
