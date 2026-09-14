"""Session registry: what an AgentCore Runtime session needs to find its resources again.

A runtimeSessionId is pinned to one microVM, but that microVM is replaced after the idle timeout
or the maximum lifetime. Everything that lives outside it (the Code Interpreter session, the EKS
Pod, the Pod's token) must be recorded somewhere durable, or the next invocation with the same
runtimeSessionId would start from nothing while the old Pod keeps running until its deadline.

Two backends:
- StoreRegistry: rides on the recordings store (local directory or S3) under the reserved
  `_registry` namespace. No extra infrastructure; fine for one Runtime.
- DynamoRegistry: a DynamoDB table with a TTL attribute, created by infra/terraform/runtime.

Records hold Pod tokens. With CWE_REGISTRY_KMS_KEY_ID set they are sealed with KMS and an
encryption context bound to the runtime session id, so a record copied to another session id
cannot be opened. Without it the store's own encryption at rest applies.

Leases. Two cold Runtime processes can receive the first two invocations for the same
runtimeSessionId within the same second (a client retry after a timeout, or the Runtime replacing a
microVM mid-request). Without coordination each would create its own sandbox and Pod. The
DynamoDB backend therefore hands out a conditional lease per runtime session: one process holds it
while it serves a request, renews it in the background, and every registry write is conditioned on
still owning it. A lost lease turns further execution into an error rather than a second
environment. The store backend has no atomic conditional write, so its lease is a no-op and it is
only suitable for a single Runtime process or local use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Protocol

log = logging.getLogger(__name__)
NAMESPACE = "_registry"
DEFAULT_TTL_SECONDS = 24 * 3600
LEASE_SECONDS = 120
LEASE_RENEW_SECONDS = 20
LEASE_WAIT_SECONDS = 90
_RID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,255}")
_SECRET_FIELDS = ("token",)


def validate_runtime_session_id(rid: str) -> str:
    if not isinstance(rid, str) or not _RID_RE.fullmatch(rid):
        raise ValueError("invalid runtime session id")
    return rid


def record_key(rid: str) -> str:
    """Store object name: a digest, so the (caller-chosen) runtime session id never becomes a path."""
    return hashlib.sha256(validate_runtime_session_id(rid).encode()).hexdigest()


class Sealer:
    """Optional KMS envelope for a whole record.

    The entire record is encrypted with an encryption context bound to the runtime session id. That gives
    confidentiality for the Pod tokens and integrity for everything else: a record copied under another
    runtime session id does not decrypt, and a principal without kms:Encrypt on the key cannot forge one.
    Only the stamp fields (`runtime_session_id`, `session_id`, `updated_at`, `expires_at`) stay in clear so the
    store and the TTL can work with them.
    """

    CLEAR_FIELDS = ("runtime_session_id", "session_id", "updated_at", "expires_at")

    def __init__(self, key_id: str | None, region: str | None = None):
        self.key_id = key_id
        self._kms = None
        if key_id:
            import boto3

            self._kms = boto3.client("kms", region_name=region)

    @property
    def enabled(self) -> bool:
        return self._kms is not None

    def seal(self, rid: str, record: dict[str, Any]) -> dict[str, Any]:
        if not self._kms:
            return record
        blob = self._kms.encrypt(KeyId=self.key_id, Plaintext=json.dumps(record).encode(),
                                 EncryptionContext={"runtime_session_id": rid})["CiphertextBlob"]
        out = {k: record[k] for k in self.CLEAR_FIELDS if k in record}
        out["sealed"] = "kms:" + base64.b64encode(blob).decode()
        return out

    def open(self, rid: str, record: dict[str, Any]) -> dict[str, Any]:
        if not self._kms:
            return record
        sealed = record.get("sealed")
        if not isinstance(sealed, str) or not sealed.startswith("kms:"):
            raise RuntimeError("registry record is not sealed; refusing to trust it")
        plain = self._kms.decrypt(CiphertextBlob=base64.b64decode(sealed[4:]),
                                  EncryptionContext={"runtime_session_id": rid})["Plaintext"]
        return json.loads(plain.decode())


def check_record(rid: str, record: dict[str, Any]) -> dict[str, Any]:
    """A record is only usable for the runtime session it was written for."""
    if record.get("runtime_session_id") != rid:
        raise RuntimeError("registry record belongs to another runtime session")
    return record


class Lease:
    """What a process holds while it serves one runtime session.

    `authoritative` says whether `record` is the current registry state read under the lease (DynamoDB)
    or unknown (store backend: callers fall back to a plain read). `check()` raises once the lease is lost.
    """

    authoritative = False

    def __init__(self, rid: str):
        self.rid = rid
        self.record: dict[str, Any] | None = None

    def check(self) -> None:
        return None

    def release(self) -> None:
        return None


class DynamoLease(Lease):
    """Conditional lease on the session item: `lease_owner` / `lease_until` attributes, renewed in the background."""

    authoritative = True

    def __init__(self, client, table: str, rid: str, sealer: "Sealer"):
        super().__init__(rid)
        self.client, self.table, self.sealer = client, table, sealer
        self.key = {"runtime_session_id": {"S": validate_runtime_session_id(rid)}}
        self.owner = uuid.uuid4().hex
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._expires = 0.0
        self._thread: threading.Thread | None = None

    def acquire(self, wait_seconds: int = LEASE_WAIT_SECONDS) -> None:
        deadline = time.monotonic() + wait_seconds
        while True:
            now = int(time.time())
            try:
                response = self.client.update_item(
                    TableName=self.table, Key=self.key,
                    UpdateExpression="SET lease_owner = :owner, lease_until = :until, expires_at = if_not_exists(expires_at, :ttl)",
                    ConditionExpression="attribute_not_exists(lease_owner) OR lease_until < :now",
                    ExpressionAttributeValues={":owner": {"S": self.owner}, ":until": {"N": str(now + LEASE_SECONDS)},
                                               ":now": {"N": str(now)}, ":ttl": {"N": str(now + DEFAULT_TTL_SECONDS)}},
                    ReturnValues="ALL_NEW",
                )
                break
            except self.client.exceptions.ConditionalCheckFailedException:
                if time.monotonic() >= deadline:
                    raise RuntimeError("development session is busy in another process; retry the request")
                time.sleep(0.5)
        self._expires = now + LEASE_SECONDS
        item = response.get("Attributes", {})
        self.record = None
        raw = item.get("record", {}).get("S")
        if raw and int(item.get("expires_at", {}).get("N", "0")) >= time.time():
            self.record = check_record(self.rid, self.sealer.open(self.rid, json.loads(raw)))
        self._thread = threading.Thread(target=self._renew, name=f"lease-{self.rid[:12]}", daemon=True)
        self._thread.start()

    def check(self) -> None:
        if self._lost.is_set() or time.time() >= self._expires - 10:
            raise RuntimeError("session lease lost; refusing further execution in this process")

    def condition(self) -> tuple[str, dict[str, Any]]:
        """ConditionExpression and values a registry write must carry while this lease is held."""
        return "lease_owner = :owner", {":owner": {"S": self.owner}}

    def _renew(self) -> None:
        while not self._stop.wait(LEASE_RENEW_SECONDS):
            try:
                until = int(time.time()) + LEASE_SECONDS
                self.client.update_item(
                    TableName=self.table, Key=self.key, UpdateExpression="SET lease_until = :until",
                    ConditionExpression="lease_owner = :owner",
                    ExpressionAttributeValues={":owner": {"S": self.owner}, ":until": {"N": str(until)}},
                )
                self._expires = until
            except Exception:  # noqa: BLE001  any failure to renew means we can no longer prove ownership
                self._lost.set()
                return

    def release(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=LEASE_RENEW_SECONDS + 5)
        try:
            self.client.update_item(
                TableName=self.table, Key=self.key, UpdateExpression="REMOVE lease_owner, lease_until",
                ConditionExpression="lease_owner = :owner",
                ExpressionAttributeValues={":owner": {"S": self.owner}},
            )
        except self.client.exceptions.ConditionalCheckFailedException:
            self._lost.set()
        except Exception as e:  # noqa: BLE001  the lease expires on its own after LEASE_SECONDS
            log.warning("lease release for %s failed: %s", self.rid, e)


class SessionRegistry(Protocol):
    def get(self, rid: str) -> dict[str, Any] | None: ...
    def put(self, rid: str, record: dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None: ...
    def delete(self, rid: str) -> None: ...
    def lease(self, rid: str) -> Iterator[Lease]: ...


def _stamp(rid: str, record: dict[str, Any], ttl_seconds: int) -> dict[str, Any]:
    now = int(time.time())
    return {**record, "runtime_session_id": rid, "updated_at": now, "expires_at": now + int(ttl_seconds)}


class StoreRegistry:
    """Records as JSON objects in the recordings store, under the reserved `_registry` session namespace."""

    def __init__(self, store, sealer: Sealer | None = None):
        self.store = store
        self.sealer = sealer or Sealer(None)

    def get(self, rid: str) -> dict[str, Any] | None:
        try:
            raw = self.store.get(NAMESPACE, f"{record_key(rid)}.json")
        except Exception:  # noqa: BLE001  missing object: local FileNotFoundError or S3 NoSuchKey
            return None
        record = json.loads(raw.decode("utf-8"))
        if record.get("expires_at", 0) < time.time():
            return None
        return check_record(rid, self.sealer.open(rid, record))

    def put(self, rid: str, record: dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        data = self.sealer.seal(rid, _stamp(rid, record, ttl_seconds))
        self.store.put(NAMESPACE, f"{record_key(rid)}.json", json.dumps(data).encode("utf-8"))

    def delete(self, rid: str) -> None:
        name = f"{record_key(rid)}.json"
        if hasattr(self.store, "delete"):
            self.store.delete(NAMESPACE, name)
        else:   # stores without delete: overwrite with an already-expired record
            self.store.put(NAMESPACE, name, json.dumps({"runtime_session_id": rid, "expires_at": 0}).encode("utf-8"))

    @contextmanager
    def lease(self, rid: str) -> Iterator[Lease]:
        """No cross-process lease: object stores have no conditional write. One Runtime process at a time."""
        yield Lease(validate_runtime_session_id(rid))


class DynamoRegistry:
    """One item per runtime session. `expires_at` is the table's TTL attribute; `lease_owner`/`lease_until` coordinate processes."""

    def __init__(self, table_name: str, region: str | None = None, sealer: Sealer | None = None, client=None):
        import boto3
        from botocore.config import Config

        self.table = table_name
        self.client = client or boto3.client("dynamodb", region_name=region,
                                             config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 2}))
        self.sealer = sealer or Sealer(None)
        self._leases: dict[str, DynamoLease] = {}
        self._lock = threading.Lock()

    def _condition(self, rid: str) -> dict[str, Any]:
        with self._lock:
            lease = self._leases.get(rid)
        if lease is None:
            return {}
        expr, values = lease.condition()
        return {"ConditionExpression": expr, "values": values}

    def get(self, rid: str) -> dict[str, Any] | None:
        item = self.client.get_item(TableName=self.table, Key={"runtime_session_id": {"S": validate_runtime_session_id(rid)}},
                                    ConsistentRead=True).get("Item")
        if not item or "record" not in item:
            return None
        record = json.loads(item["record"]["S"])
        if int(item.get("expires_at", {}).get("N", "0")) < time.time():
            return None
        return check_record(rid, self.sealer.open(rid, record))

    def put(self, rid: str, record: dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        data = self.sealer.seal(rid, _stamp(rid, record, ttl_seconds))
        cond = self._condition(rid)
        values = {":record": {"S": json.dumps(data)}, ":session_id": {"S": str(data.get("session_id", ""))},
                  ":updated_at": {"N": str(data["updated_at"])}, ":expires_at": {"N": str(data["expires_at"])}, **cond.get("values", {})}
        kwargs: dict[str, Any] = {"TableName": self.table, "Key": {"runtime_session_id": {"S": validate_runtime_session_id(rid)}},
                                  "UpdateExpression": "SET record = :record, session_id = :session_id, updated_at = :updated_at, expires_at = :expires_at",
                                  "ExpressionAttributeValues": values}
        if cond:
            kwargs["ConditionExpression"] = cond["ConditionExpression"]
        try:
            self.client.update_item(**kwargs)
        except self.client.exceptions.ConditionalCheckFailedException as e:
            raise RuntimeError("session lease lost; registry write refused") from e

    def delete(self, rid: str) -> None:
        key = {"runtime_session_id": {"S": validate_runtime_session_id(rid)}}
        cond = self._condition(rid)
        if not cond:
            self.client.delete_item(TableName=self.table, Key=key)
            return
        # Under a lease keep the item (and its lease attributes) but drop the session state; TTL removes the rest.
        try:
            self.client.update_item(TableName=self.table, Key=key, UpdateExpression="REMOVE record, session_id",
                                    ConditionExpression=cond["ConditionExpression"], ExpressionAttributeValues=cond["values"])
        except self.client.exceptions.ConditionalCheckFailedException as e:
            raise RuntimeError("session lease lost; registry delete refused") from e

    @contextmanager
    def lease(self, rid: str) -> Iterator[DynamoLease]:
        lease = DynamoLease(self.client, self.table, rid, self.sealer)
        lease.acquire()
        with self._lock:
            self._leases[rid] = lease
        try:
            yield lease
        finally:
            with self._lock:
                self._leases.pop(rid, None)
            lease.release()


def make_registry(settings, store) -> SessionRegistry:
    """DynamoDB when CWE_SESSION_TABLE is set, otherwise the recordings store.

    An S3 recordings store is also reachable by the Code Interpreter execution role when the optional
    sandbox S3 access is enabled, and code inside the sandbox is written by the model. A registry there
    must be sealed, otherwise sandbox code could read Pod tokens or forge a record that points a runtime
    session at another session's sandbox. Local directory stores are for development only.
    """
    sealer = Sealer(settings.registry_kms_key_id, settings.region)
    if settings.session_table:
        return DynamoRegistry(settings.session_table, settings.region, sealer)
    if str(settings.storage_uri).startswith("s3://") and not sealer.enabled:
        raise ValueError("an S3-backed session registry requires CWE_REGISTRY_KMS_KEY_ID (or use CWE_SESSION_TABLE)")
    return StoreRegistry(store, sealer)
