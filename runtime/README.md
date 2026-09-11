# AgentCore Runtime deployment

Use one of two methods.

## A. agentcore CLI (recommended)

```bash
npm install -g @aws/agentcore
agentcore create --name CodeWorkflowEmulator --defaults   # then, after scaffolding is generated,
# point codeLocation in agentcore/agentcore.json at this repo's src, and entrypoint at cwe/runtime_app.py
agentcore deploy
agentcore invoke --session-id my-dev-session-0123456789abcdef0123456789 \
  '{"action":"exec","type":"command","input":"python --version"}'
```

## B. Direct container deployment

```bash
aws ecr create-repository --repository-name cwe-runtime
finch build --platform linux/arm64 -f runtime/Dockerfile -t <acct>.dkr.ecr.<region>.amazonaws.com/cwe-runtime:latest . && finch push <acct>.dkr.ecr.<region>.amazonaws.com/cwe-runtime:latest
aws bedrock-agentcore-control create-agent-runtime \
  --agent-runtime-name cwe_runtime \
  --agent-runtime-artifact '{"containerConfiguration":{"containerUri":"<acct>.dkr.ecr.<region>.amazonaws.com/cwe-runtime:latest"}}' \
  --network-configuration '{"networkMode":"PUBLIC"}' \
  --role-arn arn:aws:iam::<acct>:role/CweRuntimeRole
```

The execution role (CweRuntimeRole) must trust `bedrock-agentcore.amazonaws.com` and hold the stack's `cwe-operator` managed policy (the `operator_policy_arn` output of `infra/terraform/foundation`) plus ECR/CloudWatch Logs/X-Ray permissions. The Runtime endpoint authenticates via IAM or JWT (AgentCore Identity), and session isolation is per runtimeSessionId.

## Runtime payload

| action | description |
|---|---|
| `exec` | run `{"type":"command"\|"code"\|"pytest","input":"..."}` and record it |
| `files` | write files to the workspace via `{"files":{"path":"content"}}` |
| `task` | delegate the task to the Claude Agent SDK agent via `{"text":"..."}` |
| `evaluate` | rule-based + LLM judging via `{"criteria":{...},"task":"..."}` |
| `snapshot` | store a workspace snapshot in the storage backend |
| `events` | read the recording (JSONL) |
| `close` | close the sandbox |

Calls sharing the same `runtimeSessionId` keep using the same DevSession (sandbox).

## Invoking EKS Android

The default Runtime image is for code execution and does not include kubectl/AWS CLI. For EKS Android, verify first locally/in CI with `.env.eks` and a kubeconfig. To manage the Job from the Runtime, you must separately set up kubectl, authentication, and network access to the EKS API. `CWE_EKS_ACCESS=pod` is for an allowed orchestrator running inside the cluster; it does not auto-configure Pod IP access for an external Runtime.
