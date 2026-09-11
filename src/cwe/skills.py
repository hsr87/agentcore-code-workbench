"""Skills: read a long, rarely-needed procedure only when it is relevant, and distill new skills from successful runs
so the project accumulates reusable know-how over time.

Storage location: `_skills/<name>/SKILL.md` in the recording store (local directory or S3). frontmatter tracks status (draft|approved).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

SKILL_TEMPLATE = """---
name: {name}
description: {description}
status: {status}
source_session: {session_id}
source_run: {run_id}
---

{body}
"""


_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


class SkillStore:
    def __init__(self, store, prefix: str = "_skills"):
        self.store, self.prefix = store, prefix

    def _path(self, name: str) -> tuple[str, str]:
        if not _NAME_RE.fullmatch(name or ""):   # so a name supplied by the agent/API can't escape the storage key
            raise ValueError(f"invalid skill name: {name!r}")
        return self.prefix, f"{name}/SKILL.md"

    def save(self, name: str, description: str, body: str, status: str = "draft", session_id: str = "", run_id: str = "") -> str:
        sid, fname = self._path(name)
        text = SKILL_TEMPLATE.format(name=name, description=description, status=status, session_id=session_id, run_id=run_id, body=body.strip())
        return self.store.put(sid, fname, text.encode("utf-8"))

    def load(self, name: str) -> dict[str, Any] | None:
        sid, fname = self._path(name)
        try:
            text = self.store.get(sid, fname).decode("utf-8")
        except Exception:
            return None
        return parse_skill(text)

    def approve(self, name: str) -> bool:
        sk = self.load(name)
        if not sk:
            return False
        self.save(name, sk["description"], sk["body"], status="approved", session_id=sk.get("source_session", ""), run_id=sk.get("source_run", ""))
        return True

    def list(self, approved_only: bool = False) -> list[dict[str, Any]]:
        names = self._list_names()
        out = []
        for n in names:
            sk = self.load(n)
            if sk and (not approved_only or sk["status"] == "approved"):
                out.append({"name": n, "description": sk["description"], "status": sk["status"]})
        return out

    def _list_names(self) -> list[str]:
        if hasattr(self.store, "root"):
            import os

            base = os.path.join(self.store.root, self.prefix)
            return sorted(d for d in os.listdir(base)) if os.path.isdir(base) else []
        # S3
        prefix = "/".join(p for p in (self.store.prefix, self.prefix) if p) + "/"
        names: set[str] = set()
        for page in self.store.s3.get_paginator("list_objects_v2").paginate(Bucket=self.store.bucket, Prefix=prefix):
            names |= {k["Key"].split("/")[-2] for k in page.get("Contents", []) if k["Key"].endswith("/SKILL.md")}
        return sorted(names)


def parse_skill(text: str) -> dict[str, Any]:
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    meta: dict[str, Any] = {}
    body = text
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        body = m.group(2)
    return {"name": meta.get("name", ""), "description": meta.get("description", ""), "status": meta.get("status", "draft"),
            "source_session": meta.get("source_session", ""), "source_run": meta.get("source_run", ""), "body": body.strip()}


DISTILL_SYSTEM = """You turn a successful developer session transcript into a reusable SKILL document for future agents working on the same project.
Write in the transcript's language. Output JSON only: {"name": "<kebab-case>", "description": "<one line>", "body": "<markdown>"}.
The body must contain: when to use, exact commands that worked (in order), environment assumptions, pitfalls seen in the transcript, and how to verify success.
Keep it under 400 words. Never include secrets, tokens, or account IDs."""


def distill_skill(transcript: str, task: str, region: str, model: str = "anthropic.claude-opus-5") -> dict[str, str]:
    """Build a skill draft from a successful run's transcript (Claude on Bedrock)."""
    from anthropic import AnthropicBedrockMantle

    client = AnthropicBedrockMantle(aws_region=region)
    with client.messages.stream(model=model, max_tokens=3000, system=DISTILL_SYSTEM,
                                messages=[{"role": "user", "content": f"## Task\n{task}\n\n## Transcript\n```\n{transcript[-16000:]}\n```"}]) as st:
        msg = st.get_final_message()
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.S)
    data = json.loads(text[text.find("{"): text.rfind("}") + 1])
    name = re.sub(r"[^a-z0-9-]+", "-", str(data.get("name", "skill")).lower()).strip("-") or "skill"
    return {"name": name, "description": str(data.get("description", "")), "body": str(data.get("body", ""))}
