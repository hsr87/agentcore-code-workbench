"""Session registry and reattach: the same runtimeSessionId finds its sandbox and Pods after a microVM is replaced."""
import json
import re
import time
from types import SimpleNamespace

import pytest

from cwe.config import Settings
from cwe.recorder import make_store
from cwe.registry import DynamoRegistry, Sealer, StoreRegistry, make_registry, record_key, validate_runtime_session_id
from cwe.sandbox import FakeSandbox
from cwe.session import SessionManager


def test_store_registry_roundtrip_and_expiry(tmp_path):
    reg = StoreRegistry(make_store(str(tmp_path), "us-east-1"))
    rid = "my-runtime-session-0123456789abcdef0123456789abcdef"
    assert reg.get(rid) is None
    reg.put(rid, {"session_id": "sess_1", "hosts": [{"kind": "workload", "token": "t"}]}, ttl_seconds=3600)
    rec = reg.get(rid)
    assert rec["session_id"] == "sess_1" and rec["runtime_session_id"] == rid and rec["expires_at"] > time.time()
    assert (tmp_path / "_registry" / f"{record_key(rid)}.json").exists()      # digest, never the caller's id, in the path
    reg.put(rid, {"session_id": "sess_1"}, ttl_seconds=-1)
    assert reg.get(rid) is None                                                # expired records are ignored
    reg.put(rid, {"session_id": "sess_1"})
    reg.delete(rid)
    assert reg.get(rid) is None
    for bad in ("", "../x", "a/b", "x" * 300):
        with pytest.raises(ValueError):
            validate_runtime_session_id(bad)


class FakeKMS:
    def encrypt(self, KeyId, Plaintext, EncryptionContext):
        return {"CiphertextBlob": json.dumps({"p": Plaintext.decode(), "ctx": EncryptionContext}).encode()}

    def decrypt(self, CiphertextBlob, EncryptionContext):
        blob = json.loads(CiphertextBlob)
        if blob["ctx"] != EncryptionContext:
            raise RuntimeError("InvalidCiphertextException")
        return {"Plaintext": blob["p"].encode()}


def test_sealer_seals_the_whole_record_and_binds_it_to_the_runtime_session(tmp_path):
    sealer = Sealer("alias/test")
    sealer._kms = FakeKMS()
    reg = StoreRegistry(make_store(str(tmp_path), "us-east-1"), sealer)
    record = {"session_id": "sess_1", "sandbox_session_id": "ci-9", "hosts": [{"kind": "workload", "job": "j1", "token": "secret-token"}]}
    reg.put("rid-1", record)
    raw = json.loads((tmp_path / "_registry" / f"{record_key('rid-1')}.json").read_text())
    assert "secret-token" not in json.dumps(raw) and "ci-9" not in json.dumps(raw) and raw["sealed"].startswith("kms:")
    assert set(raw) == {"runtime_session_id", "session_id", "updated_at", "expires_at", "sealed"}
    opened = reg.get("rid-1")
    assert opened["hosts"] == record["hosts"] and opened["sandbox_session_id"] == "ci-9"
    # A record copied under another runtime session id does not open.
    (tmp_path / "_registry" / f"{record_key('rid-2')}.json").write_text(json.dumps(raw))
    with pytest.raises(RuntimeError):
        reg.get("rid-2")
    # A forged clear-text record (someone with write access to the store but not to the key) is refused.
    forged = {**raw, "hosts": [{"kind": "workload", "job": "victim", "token": "x"}]}
    forged.pop("sealed")
    (tmp_path / "_registry" / f"{record_key('rid-1')}.json").write_text(json.dumps(forged))
    with pytest.raises(RuntimeError, match="not sealed"):
        reg.get("rid-1")


def test_registry_refuses_records_written_for_another_runtime_session(tmp_path):
    reg = StoreRegistry(make_store(str(tmp_path), "us-east-1"))
    reg.put("rid-a", {"session_id": "sess_1", "hosts": []})
    raw = (tmp_path / "_registry" / f"{record_key('rid-a')}.json").read_text()
    (tmp_path / "_registry" / f"{record_key('rid-b')}.json").write_text(raw)     # copied under another id
    with pytest.raises(RuntimeError, match="another runtime session"):
        reg.get("rid-b")
    assert reg.get("rid-a")["session_id"] == "sess_1"


def test_make_registry_refuses_an_unsealed_s3_store(tmp_path):
    store = make_store(str(tmp_path), "us-east-1")
    with pytest.raises(ValueError, match="CWE_REGISTRY_KMS_KEY_ID"):
        make_registry(Settings(storage_uri="s3://bucket/prefix"), store)
    assert isinstance(make_registry(Settings(storage_uri=str(tmp_path)), store), StoreRegistry)    # local dev store


def test_manager_attach_rejects_malformed_session_ids(manager):
    for bad in ("../etc", "sess_zz", "", None, "sess_0123456789ab/../x"):
        with pytest.raises(ValueError, match="invalid session id"):
            manager.attach({"session_id": bad, "sandbox_session_id": "x", "hosts": []})


class FakeDynamo:
    """Enough of the DynamoDB client for the registry: items, conditional update_item, delete_item, get_item."""

    class exceptions:  # noqa: N801  mirrors botocore's client.exceptions namespace
        class ConditionalCheckFailedException(Exception):
            pass

    def __init__(self):
        self.items: dict[str, dict] = {}
        self.calls: list[str] = []

    @staticmethod
    def _num(v):
        return float(v["N"])

    def _condition_holds(self, item, expr, values):
        if not expr:
            return True
        if expr == "attribute_not_exists(lease_owner) OR lease_until < :now":
            return "lease_owner" not in item or self._num(item["lease_until"]) < self._num(values[":now"])
        if expr == "lease_owner = :owner":
            return item.get("lease_owner") == values[":owner"]
        raise NotImplementedError(expr)

    RESERVED = {"record", "name", "status", "value", "count", "size", "type", "key", "data"}   # a few of DynamoDB's reserved words

    def update_item(self, TableName, Key, UpdateExpression, ExpressionAttributeValues=None, ConditionExpression=None, ReturnValues=None,
                    ExpressionAttributeNames=None):
        self.calls.append(UpdateExpression)
        # Like the service: a bare reserved word in an expression is a ValidationException; #aliases must be declared.
        for token in re.findall(r"[A-Za-z_#][A-Za-z0-9_]*", re.sub(r":[A-Za-z_][A-Za-z0-9_]*", "", UpdateExpression)):
            if token.startswith("#"):
                if token not in (ExpressionAttributeNames or {}):
                    raise ValueError(f"undeclared attribute name {token}")
            elif token.lower() in self.RESERVED:
                raise ValueError(f"Invalid UpdateExpression: Attribute name is a reserved keyword; reserved keyword: {token}")
        for alias, attr in (ExpressionAttributeNames or {}).items():
            UpdateExpression = UpdateExpression.replace(alias, attr)
        rid = Key["runtime_session_id"]["S"]
        item = self.items.get(rid, {"runtime_session_id": Key["runtime_session_id"]})
        values = ExpressionAttributeValues or {}
        if not self._condition_holds(item, ConditionExpression, values):
            raise self.exceptions.ConditionalCheckFailedException(ConditionExpression)
        for clause in UpdateExpression.replace("\n", " ").split(" REMOVE "):
            pass
        expr = UpdateExpression
        set_part, remove_part = "", ""
        if expr.startswith("SET "):
            set_part = expr[4:]
            if " REMOVE " in set_part:
                set_part, remove_part = set_part.split(" REMOVE ", 1)
        elif expr.startswith("REMOVE "):
            remove_part = expr[7:]
        for assignment in filter(None, (a.strip() for a in re.split(r",(?![^()]*\))", set_part))):   # commas outside if_not_exists(...)
            name, _, value = assignment.partition("=")
            name, value = name.strip(), value.strip()
            if value.startswith("if_not_exists("):
                attr, default = value[len("if_not_exists("):-1].split(",")
                item[name] = item.get(attr.strip(), values[default.strip()])
            else:
                item[name] = values[value]
        for name in filter(None, (n.strip() for n in remove_part.split(","))):
            item.pop(name, None)
        self.items[rid] = item
        return {"Attributes": dict(item)} if ReturnValues == "ALL_NEW" else {}

    def put_item(self, TableName, Item):
        self.items[Item["runtime_session_id"]["S"]] = Item

    def get_item(self, TableName, Key, ConsistentRead=False):
        item = self.items.get(Key["runtime_session_id"]["S"])
        return {"Item": item} if item else {}

    def delete_item(self, TableName, Key):
        self.items.pop(Key["runtime_session_id"]["S"], None)


def test_dynamo_registry_item_shape():
    table = FakeDynamo()
    reg = DynamoRegistry("cwe-sessions", client=table)
    reg.put("rid", {"session_id": "sess_9", "hosts": []}, ttl_seconds=60)
    item = table.items["rid"]
    assert set(item) == {"runtime_session_id", "record", "session_id", "updated_at", "expires_at"}
    assert item["session_id"]["S"] == "sess_9" and int(item["expires_at"]["N"]) > time.time()
    assert reg.get("rid")["session_id"] == "sess_9"
    reg.delete("rid")
    assert reg.get("rid") is None


def test_dynamo_lease_excludes_a_second_process_and_hands_over_the_record(monkeypatch):
    import cwe.registry as registry_module

    monkeypatch.setattr(registry_module, "LEASE_RENEW_SECONDS", 0.05)
    table = FakeDynamo()
    first = DynamoRegistry("cwe-sessions", client=table)
    second = DynamoRegistry("cwe-sessions", client=table)     # another microVM
    with first.lease("rid-1") as lease:
        assert lease.authoritative and lease.record is None
        first.put("rid-1", {"session_id": "sess_a", "hosts": [{"kind": "workload", "job": "j1", "token": "t"}]})
        assert table.items["rid-1"]["lease_owner"]["S"] == lease.owner
        other = registry_module.DynamoLease(table, "cwe-sessions", "rid-1", registry_module.Sealer(None))
        with pytest.raises(RuntimeError, match="busy"):
            other.acquire(wait_seconds=0)                      # the lease is held: no second environment
        time.sleep(0.2)
        lease.check()                                          # renewals kept it alive
        assert "SET lease_until = :until" in table.calls
    assert "lease_owner" not in table.items["rid-1"]           # released
    with second.lease("rid-1") as lease2:
        assert lease2.record["session_id"] == "sess_a" and lease2.record["hosts"][0]["job"] == "j1"
        second.delete("rid-1")                                 # close under the lease keeps the item, drops the state
        assert "record" not in table.items["rid-1"] and table.items["rid-1"]["lease_owner"]["S"] == lease2.owner
        assert second.get("rid-1") is None
    assert first.get("rid-1") is None


def test_dynamo_registry_write_is_refused_once_the_lease_is_lost():
    table = FakeDynamo()
    reg = DynamoRegistry("cwe-sessions", client=table)
    with reg.lease("rid-2") as lease:
        reg.put("rid-2", {"session_id": "sess_b", "hosts": []})
        table.items["rid-2"]["lease_owner"] = {"S": "someone-else"}   # a stale process no longer owns the item
        with pytest.raises(RuntimeError, match="lease lost"):
            reg.put("rid-2", {"session_id": "sess_b", "hosts": []})
        with pytest.raises(RuntimeError, match="lease lost"):
            reg.delete("rid-2")
    assert lease._lost.is_set()                                 # release saw the takeover


def test_make_registry_prefers_dynamo_when_table_is_set(tmp_path, monkeypatch):
    store = make_store(str(tmp_path), "us-east-1")
    assert isinstance(make_registry(Settings(storage_uri=str(tmp_path)), store), StoreRegistry)
    import cwe.registry as registry_module

    monkeypatch.setattr(registry_module, "DynamoRegistry", lambda table, region, sealer: ("dynamo", table))
    assert make_registry(Settings(storage_uri=str(tmp_path), session_table="cwe-sessions"), store) == ("dynamo", "cwe-sessions")


class AttachableSandbox(FakeSandbox):
    """FakeSandbox that remembers which session id it adopted."""
    attached = []

    def attach(self, session_id):
        AttachableSandbox.attached.append(session_id)
        return super().attach(session_id)


def test_manager_attach_rebuilds_session_and_hosts(tmp_path, monkeypatch):
    settings = Settings(storage_uri=str(tmp_path / "store"), enable_llm_judge=False)
    first = SessionManager(settings=settings, sandbox_factory=lambda p: AttachableSandbox())
    sess = first.create()
    sess.begin_run("work")
    sess.run_command("echo hello")
    sess.end_run()
    fake_client = SimpleNamespace(health=lambda: {"ok": True, "cpus": 8}, close=lambda: None, base_url="http://10.0.0.1:8080", token="tok")
    host = SimpleNamespace(start=lambda p, s: fake_client, stop=lambda: None, detach=lambda: None,
                           describe=lambda: {"kind": "workload", "session_id": sess.info.session_id, "job": "cwe-job", "token": "tok",
                                             "profile": {"image": "repo/build:v1", "memory": "24Gi"}})
    from cwe.workload import WorkloadProfile
    sess.start_workload(WorkloadProfile(image="repo/build:v1", memory="24Gi"), host=host)
    record = sess.registry_record("rt-1")
    assert record["sandbox_session_id"] == "replay" and record["hosts"][0]["job"] == "cwe-job"
    first.detach_all()                               # process exit: nothing is stopped
    assert first.list() == []

    # A new process (microVM) adopts the sandbox and reconnects to the Pod.
    attached = {}

    class FakeWorkloadHost:
        def __init__(self, *a, **kw):
            pass

        @classmethod
        def from_env(cls, settings):
            return cls()

        def attach(self, rec, timeout=60):
            attached.update(rec)
            return fake_client

        def describe(self):
            return {"kind": "workload", "session_id": attached["session_id"], "job": attached["job"], "token": attached["token"], "profile": attached["profile"]}

        def detach(self):
            pass

        def stop(self):
            attached["stopped"] = True

    monkeypatch.setattr("cwe.workload.EKSWorkloadHost", FakeWorkloadHost)
    second = SessionManager(settings=settings, sandbox_factory=lambda p: AttachableSandbox())
    again = second.attach(record)
    assert again.info.session_id == sess.info.session_id and again.info.status == "ready"
    assert AttachableSandbox.attached[-1] == "replay"
    assert attached["job"] == "cwe-job" and attached["token"] == "tok"
    assert again.workload is fake_client and again._workload_profile.memory == "24Gi"
    assert [r.title for r in again.info.runs][-1] == "reattach"
    assert len(again.info.runs) == 4                    # provision, work, workload-provision, reattach
    assert second.attach(record) is again              # idempotent within a process
    again.begin_run("after")
    assert again.run_command("echo again").output.strip() == "again"
    again.end_run()
    assert again.registry_record("rt-1")["hosts"][0]["job"] == "cwe-job"
    second.close(again.info.session_id)
    assert attached["stopped"]


def test_manager_attach_fails_when_pod_is_gone(tmp_path, monkeypatch):
    settings = Settings(storage_uri=str(tmp_path / "store"), enable_llm_judge=False)
    mgr = SessionManager(settings=settings, sandbox_factory=lambda p: AttachableSandbox())
    sess = mgr.create()
    record = {**sess.registry_record("rt"), "hosts": [{"kind": "workload", "session_id": sess.info.session_id, "job": "gone", "token": "t"}]}
    mgr.detach_all()

    class Gone:
        @classmethod
        def from_env(cls, settings):
            return cls()

        def attach(self, rec, timeout=60):
            raise RuntimeError("workload Job gone is no longer running")

        def detach(self):
            pass

    monkeypatch.setattr("cwe.workload.EKSWorkloadHost", Gone)
    with pytest.raises(RuntimeError, match="no longer running"):
        mgr.attach(record)
    assert mgr.list() == []
    with pytest.raises(RuntimeError, match="no sandbox"):
        mgr.attach({**record, "hosts": [], "sandbox_session_id": None})


def test_runtime_app_reattaches_by_runtime_session_id(tmp_path, monkeypatch):
    """runtime_app: same runtimeSessionId in a new process -> registry -> manager.attach; close deletes the record."""
    monkeypatch.setenv("CWE_STORAGE_URI", str(tmp_path / "store"))
    monkeypatch.setenv("CWE_ENABLE_LLM_JUDGE", "0")
    import importlib

    import cwe.config as config
    import cwe.runtime_app as runtime_app

    config.get_settings.cache_clear()
    monkeypatch.setattr(SessionManager, "_default_sandbox", lambda self, profile: AttachableSandbox())
    runtime_app = importlib.reload(runtime_app)
    ctx = SimpleNamespace(session_id="runtime-session-abc")
    out = runtime_app.invoke({"action": "exec", "type": "command", "input": "echo one"}, ctx)
    sid = out["session_id"]
    assert runtime_app.registry.get("runtime-session-abc")["session_id"] == sid
    assert runtime_app.invoke({"action": "status"}, ctx)["workload"] is None

    # The microVM goes away: detach and forget the in-memory map, then a new process comes up.
    runtime_app.manager.detach_all()
    runtime_app._by_runtime_session.clear()
    out2 = runtime_app.invoke({"action": "exec", "type": "command", "input": "echo two"}, ctx)
    assert out2["session_id"] == sid and out2["result"]["stdout"].strip() == "two"
    assert AttachableSandbox.attached[-1] == "replay"

    # Another runtimeSessionId never reaches this session.
    other = runtime_app.invoke({"action": "status"}, SimpleNamespace(session_id="runtime-session-xyz"))
    assert other["session_id"] != sid
    closed = runtime_app.invoke({"action": "close"}, ctx)
    assert closed["closed"] == sid and runtime_app.registry.get("runtime-session-abc") is None
    fresh = runtime_app.invoke({"action": "status"}, ctx)
    assert fresh["session_id"] != sid
    runtime_app.manager.close_all()
    config.get_settings.cache_clear()


def test_runtime_app_under_a_dynamo_lease_trusts_the_registry_over_its_cache(tmp_path, monkeypatch):
    """A record removed by another process invalidates this process's cache; the old session is detached, never reused."""
    monkeypatch.setenv("CWE_STORAGE_URI", str(tmp_path / "store"))
    monkeypatch.setenv("CWE_ENABLE_LLM_JUDGE", "0")
    import importlib

    import cwe.config as config
    import cwe.runtime_app as runtime_app

    config.get_settings.cache_clear()
    monkeypatch.setattr(SessionManager, "_default_sandbox", lambda self, profile: AttachableSandbox())
    runtime_app = importlib.reload(runtime_app)
    table = FakeDynamo()
    runtime_app.registry = DynamoRegistry("cwe-sessions", client=table)
    ctx = SimpleNamespace(session_id="runtime-lease-1")

    assert runtime_app.invoke({"action": "close"}, ctx) == {"closed": None}          # nothing created just to close it
    assert runtime_app.manager.list() == []
    first = runtime_app.invoke({"action": "exec", "type": "command", "input": "echo one"}, ctx)["session_id"]
    assert table.items["runtime-lease-1"]["session_id"]["S"] == first
    assert "lease_owner" not in table.items["runtime-lease-1"]                        # released between calls
    assert runtime_app.invoke({"action": "status"}, ctx)["session_id"] == first       # cache agrees with the record

    # Another process closed the session and deleted the record while this process still has it cached.
    runtime_app.registry.delete("runtime-lease-1")
    second = runtime_app.invoke({"action": "status"}, ctx)["session_id"]
    assert second != first
    assert first not in {s.session_id for s in runtime_app.manager.list()}            # detached, not closed, not reused
    assert table.items["runtime-lease-1"]["session_id"]["S"] == second

    # Another process replaced the record with a different session: this process attaches to that one.
    other = runtime_app.manager.create(tags={"runtime_session_id": "runtime-lease-1"})
    runtime_app.manager.detach_all()
    runtime_app.registry.put("runtime-lease-1", other.registry_record("runtime-lease-1"))
    assert runtime_app.invoke({"action": "status"}, ctx)["session_id"] == other.info.session_id
    runtime_app.invoke({"action": "close"}, ctx)
    assert "record" not in table.items["runtime-lease-1"]
    runtime_app.manager.close_all()
    config.get_settings.cache_clear()


def test_runtime_app_refuses_to_continue_without_a_durable_record(tmp_path, monkeypatch):
    monkeypatch.setenv("CWE_STORAGE_URI", str(tmp_path / "store"))
    monkeypatch.setenv("CWE_ENABLE_LLM_JUDGE", "0")
    import importlib

    import cwe.config as config
    import cwe.runtime_app as runtime_app

    config.get_settings.cache_clear()
    monkeypatch.setattr(SessionManager, "_default_sandbox", lambda self, profile: AttachableSandbox())
    runtime_app = importlib.reload(runtime_app)
    table = FakeDynamo()
    reg = DynamoRegistry("cwe-sessions", client=table)
    runtime_app.registry = reg
    original = reg.put

    def failing_put(rid, record, ttl_seconds=0):
        raise RuntimeError("dynamodb unavailable")

    monkeypatch.setattr(reg, "put", failing_put)
    ctx = SimpleNamespace(session_id="runtime-lease-2")
    with pytest.raises(RuntimeError, match="durable record"):
        runtime_app.invoke({"action": "exec", "type": "command", "input": "echo x"}, ctx)
    assert runtime_app.manager.list() == []                 # the freshly created session was closed, not orphaned
    monkeypatch.setattr(reg, "put", original)
    assert runtime_app.invoke({"action": "status"}, ctx)["status"] == "ready"
    runtime_app.manager.close_all()
    config.get_settings.cache_clear()
