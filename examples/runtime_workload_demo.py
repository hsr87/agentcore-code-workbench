"""AgentCore Runtime + EKS workload Pod, driven through InvokeAgentRuntime.

    python examples/runtime_workload_demo.py --agent-runtime-arn "$(terraform -chdir=infra/terraform/runtime output -raw agent_runtime_arn)"

What it shows, in order:
  1. the sandbox on Code Interpreter runs a command;
  2. a workload Pod is started for the same runtime session, with more memory and disk than the microVM;
  3. the sandbox workspace is synced into the Pod and a Gradle build runs there (or any command via --build-cmd);
  4. `status` shows the same Pod after a pause long enough to let the microVM go idle (--idle-wait), proving reattach;
  5. `close` releases the sandbox, the Pod and the registry record.

This script needs a deployed runtime root. Nothing here is mocked; it costs Runtime, Code Interpreter,
Bedrock and EKS time. Its output from the 2026-09-14 run is docs/evidence/workload/runtime-demo.log and the
report around it is docs/verification-workload.md.
"""
from __future__ import annotations

import argparse
import json
import secrets
import time

import boto3
from botocore.config import Config

# Actions such as `workload` and long `remote` builds run for minutes inside one invocation, and none of them is
# idempotent: give the call time and never let botocore replay it.
CLIENT_CONFIG = Config(read_timeout=900, connect_timeout=10, retries={"max_attempts": 1})


def invoke(client, arn: str, session_id: str, payload: dict) -> dict:
    response = client.invoke_agent_runtime(agentRuntimeArn=arn, runtimeSessionId=session_id, contentType="application/json",
                                           accept="application/json", payload=json.dumps(payload).encode())
    body = response["response"].read() if hasattr(response.get("response"), "read") else response.get("response")
    return json.loads(body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--agent-runtime-arn", required=True)
    parser.add_argument("--region")
    parser.add_argument("--memory", default="16Gi")
    parser.add_argument("--disk", default="50Gi")
    parser.add_argument("--build-cmd", default="./gradlew --no-daemon -q assemble || ls -la",
                        help="command run on the Pod after the sync (default: a Gradle assemble)")
    parser.add_argument("--idle-wait", type=int, default=0,
                        help="seconds to sleep before the reattach check; set above the Runtime idle timeout to force a microVM swap")
    args = parser.parse_args()
    client = boto3.client("bedrock-agentcore", region_name=args.region, config=CLIENT_CONFIG)
    rid = f"demo-{secrets.token_hex(16)}"
    print("runtime session", rid)

    print(json.dumps(invoke(client, args.agent_runtime_arn, rid, {"action": "exec", "type": "command", "input": "nproc && free -g && df -h ."})["result"]["stdout"]))
    invoke(client, args.agent_runtime_arn, rid, {"action": "files", "files": {"README.md": "# demo\n"}})
    wl = invoke(client, args.agent_runtime_arn, rid, {"action": "workload", "profile": {"memory": args.memory, "ephemeral_storage": args.disk}})
    print("workload", json.dumps(wl["workload"]), "health", json.dumps(wl["health"]))
    before = invoke(client, args.agent_runtime_arn, rid, {"action": "status"})
    print("sync", json.dumps(invoke(client, args.agent_runtime_arn, rid, {"action": "remote", "type": "sync"})["result"]))
    build = invoke(client, args.agent_runtime_arn, rid, {"action": "remote", "type": "exec", "input": args.build_cmd, "timeout": 3600})["result"]
    print("build exit", build["exit_code"], build["stdout"][-2000:])
    if args.idle_wait:
        print(f"sleeping {args.idle_wait}s so the microVM can be released ...")
        time.sleep(args.idle_wait)
    status = invoke(client, args.agent_runtime_arn, rid, {"action": "status"})
    same = status["workload"]["job"] == wl["workload"]["job"]
    swapped = status["process"]["id"] != before["process"]["id"]
    print("after wait: same session", status["session_id"] == wl["session_id"], "same Pod", same,
          "new microVM process", swapped, json.dumps({"before": before["process"], "after": status["process"]}))
    check = invoke(client, args.agent_runtime_arn, rid, {"action": "remote", "type": "exec", "input": "cat README.md && ls"})["result"]
    print("workspace still there after wait:", check["exit_code"] == 0 and "demo" in check["stdout"])
    print(json.dumps(invoke(client, args.agent_runtime_arn, rid, {"action": "close"})))


if __name__ == "__main__":
    main()
