"""Workspace snapshot, so a session's files can be restored into a fresh sandbox later.

Inside the sandbox we build a tar.gz and pull it out with readFiles(blob) into the recordings
store (S3/local). Restore writes it back into a new session's sandbox with writeFiles(blob) and
unpacks it with tar.
"""

from __future__ import annotations

import shlex

from cwe.models import SnapshotInfo
from cwe.sandbox import Sandbox

_ARCHIVE = ".cwe/snapshot.tar.gz"
MAX_INLINE_BYTES = 90 * 1024 * 1024   # stay under the Code Interpreter inline file transfer limit (100 MB)


def take_snapshot(sandbox: Sandbox, store, session_id: str, workspace_path: str, description: str = "") -> SnapshotInfo:
    ws = shlex.quote(workspace_path)
    r = sandbox.execute_command(
        f"mkdir -p .cwe && tar -czf {_ARCHIVE} --exclude=node_modules --exclude=.venv --exclude=__pycache__ --exclude=./.cwe -C {ws} . && ls -l {_ARCHIVE}"
    )
    if not r.ok:
        raise RuntimeError(f"snapshot tar failed: {r.output}")
    blob = sandbox.read_files([_ARCHIVE]).get(_ARCHIVE)
    if blob is None:
        raise RuntimeError("snapshot archive not found in sandbox")
    if isinstance(blob, str):
        blob = blob.encode("latin-1")
    if len(blob) > MAX_INLINE_BYTES:
        raise RuntimeError(f"snapshot is {len(blob)/1e6:.0f} MB; inline restore is limited to 100 MB. "
                           "Exclude build outputs or mount EFS/S3 Files (VPC mode) for large workspaces.")
    info = SnapshotInfo(session_id=session_id, uri="", size_bytes=len(blob), description=description)
    info.uri = store.put(session_id, f"{info.snapshot_id}.tar.gz", blob)
    return info


def restore_snapshot(sandbox: Sandbox, store, snapshot: SnapshotInfo, workspace_path: str) -> None:
    blob = store.get(snapshot.session_id, f"{snapshot.snapshot_id}.tar.gz")
    sandbox.write_files({_ARCHIVE: blob})
    ws = shlex.quote(workspace_path)
    r = sandbox.execute_command(f"mkdir -p {ws} && tar -xzf {_ARCHIVE} -C {ws} && ls -la {ws}")
    if not r.ok:
        raise RuntimeError(f"snapshot restore failed: {r.output}")
