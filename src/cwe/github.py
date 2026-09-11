"""PR attachment: post session evidence (screenshots, recordings, harness verification results) as a GitHub PR comment.

The token comes from the GITHUB_TOKEN environment variable or from the AgentCore Identity token vault (API key provider).
"""

from __future__ import annotations

import re
from typing import Any

import httpx

_REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _valid_repo(repo: str) -> bool:
    """owner/name only: a '.' or '..' segment would rewrite the request path while still carrying the token."""
    return bool(_REPO_RE.fullmatch(repo)) and all(part not in (".", "..") for part in repo.split("/"))

from cwe.models import RunRecord


def presign(store, session_id: str, name: str, region: str, expires: int = 3600) -> str | None:
    """For an S3 store: a presigned GET URL (default 1 hour: the link left in the PR comment can be opened by anyone until it expires). For a local store: None (never expose a host path)."""
    if hasattr(store, "s3"):
        return store.s3.generate_presigned_url("get_object", Params={"Bucket": store.bucket, "Key": store.key(session_id, name)}, ExpiresIn=expires)
    return None


def build_comment(run: RunRecord, artifact_urls: list[tuple[str, str]], eval_summary: str | None = None) -> str:
    v = run.harness.get("verification") or {}
    lines = [f"### Verification evidence for run `{run.run_id}`", ""]
    if eval_summary:
        lines.append(f"**Evaluation**: {eval_summary}")
    if v:
        lines.append(f"**Harness verification** (`{v.get('command')}`, {v.get('mode')}): exit {v.get('exit_code')}, pytest {v.get('pytest')}")
    lines.append(f"**Executions**: {run.exec_count}, **human approvals**: {run.harness.get('human_approvals', 0)}, "
                 f"**tokens**: {run.usage.get('totalTokens', 0)}, **est. cost**: ${run.cost_usd_estimate or 0}")
    if artifact_urls:
        lines += ["", "**Artifacts**"]
        for name, url in artifact_urls:
            lines.append(f"- [{name}]({url})" if not name.endswith(".png") else f"- {name}\n  ![{name}]({url})")
    lines += ["", "_Posted by code-workflow-emulator_"]
    return "\n".join(lines)


def post_pr_comment(repo: str, pr_number: int, body: str, token: str, api_base: str = "https://api.github.com", client: httpx.Client | None = None) -> dict[str, Any]:
    if not _valid_repo(repo) or int(pr_number) <= 0:   # goes straight into the URL path
        raise ValueError(f"invalid repo or pr number: {repo!r} #{pr_number}")
    c = client or httpx.Client(timeout=30)
    r = c.post(f"{api_base}/repos/{repo}/issues/{int(pr_number)}/comments", json={"body": body}, timeout=30,
               headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    r.raise_for_status()
    return r.json()


def attach_evidence(session, run_id: str, repo: str, pr_number: int, token: str, region: str, eval_summary: str | None = None,
                    client: httpx.Client | None = None) -> dict[str, Any]:
    run = next(r for r in session.info.runs if r.run_id == run_id)
    urls = []
    for a in run.artifacts:
        name = a.rsplit("/", 1)[-1]
        url = presign(session.store, session.info.session_id, f"artifacts/{name}", region)
        if url:
            urls.append((name, url))
    body = build_comment(run, urls, eval_summary)
    resp = post_pr_comment(repo, pr_number, body, token, client=client)
    session.recorder.record(run_id, "note", {"action": "pr_comment", "repo": repo, "pr": pr_number, "url": resp.get("html_url")})
    return {"url": resp.get("html_url"), "body": body}
