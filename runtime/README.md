# AgentCore Runtime deployment

The Runtime hosts the orchestrator: the agent loop, the Code Interpreter session and the EKS
Jobs are all driven from here. Deploy it with Terraform (`infra/terraform/runtime`), which puts
the Runtime in **VPC mode** so it can reach session Pods directly, gives its execution role the
operator policy plus an EKS access entry, and creates the session registry (DynamoDB + KMS).

```bash
./scripts/deploy.sh --stage images --tag v1 --workload --runtime   # pushes cwe-eks-runtime:v1 and cwe-eks-workload-agent:v1
cp infra/terraform/runtime/terraform.tfvars.example infra/terraform/runtime/terraform.tfvars   # fill from foundation outputs and .env.eks
./scripts/deploy.sh --stage runtime --apply
# admit the Runtime subnets in the lab network policy:
terraform -chdir=infra/terraform/runtime output runtime_subnet_cidrs   # -> orchestrator_cidrs in platform/terraform.tfvars
./scripts/deploy.sh --stage platform --apply
```

`private_access` decides how the Runtime reaches AWS from its private subnets: `nat` (a NAT gateway, needs an Elastic IP) or
`endpoints` (PrivateLink for Bedrock, AgentCore, STS, KMS, Logs, X-Ray, ECR and EKS plus S3 and DynamoDB gateway endpoints;
no internet path at all). The image is pulled through the customer ENI in VPC mode, so the ECR endpoints are not optional.

Clients must give long actions time: `workload` and `remote exec` run for minutes inside one invocation. A retried
`workload` waits for the first Pod rather than creating a second one, and a retried `remote exec` joins the running
command through its `request_id`, but the retry still blocks for the remaining build time. Use
`Config(read_timeout=900, retries={"max_attempts": 1})` as `examples/runtime_workload_demo.py` does, and run anything
longer than a few minutes with `remote start` + `remote logs`.

The image (`runtime/Dockerfile`, linux/arm64) carries kubectl pinned by checksum. It needs no AWS
CLI: `cwe eks-token` is the kubectl exec plugin and derives the EKS token from the execution
role's credentials, and `cwe.kube.ensure_kubeconfig` writes the kubeconfig from
`CWE_EKS_CLUSTER_NAME` on first use.

For a quick manual deployment without Terraform, `agentcore create` / `agentcore deploy` or
`aws bedrock-agentcore-control create-agent-runtime` still work; set the same `CWE_*` environment
variables that `infra/terraform/runtime/main.tf` sets, and use `--network-configuration
'{"networkMode":"VPC", ...}'` if the Runtime has to reach Pods.

## Runtime payload

| action | description |
|---|---|
| `exec` | run `{"type":"command"\|"code"\|"pytest","input":"..."}` in the sandbox and record it |
| `files` | write files to the sandbox workspace via `{"files":{"path":"content"}}` |
| `task` | delegate the task to the Claude Agent SDK agent via `{"text":"..."}`; `remote_*` tools appear once a workload is attached |
| `workload` | start the session's EKS build/run Pod: `{"profile":{"memory":"24Gi","ephemeral_storage":"100Gi","image":"..."}}` (fields of `WorkloadProfile`, all optional) |
| `remote` | on that Pod: `{"type":"exec","input":"./gradlew build","timeout":1800}`, `{"type":"sync"}`, `{"type":"start","name":"svc","input":"java -jar app.jar"}`, `{"type":"logs","name":"svc"}`, `{"type":"probe","port":8081,"path":"/health"}`, `{"type":"stop","name":"svc"}` |
| `evaluate` | rule-based + LLM judging via `{"criteria":{...},"task":"..."}` |
| `snapshot` | store a workspace snapshot in the storage backend |
| `events` | read the recording (JSONL) |
| `status` | session, sandbox and Pod identifiers for this runtime session (tokens excluded) |
| `close` | stop the sandbox and the Pods, delete the registry record |

## Sticky sessions

Calls sharing the same `runtimeSessionId` keep using the same DevSession. The Runtime pins a
`runtimeSessionId` to one microVM, but that microVM is released after `idle_runtime_session_timeout`
and replaced after `max_lifetime`. Before exit the Runtime **detaches** (nothing is stopped), and
the session registry keeps `runtimeSessionId → {Code Interpreter session, Job, Pod token}`. The
next invocation with the same id, on a fresh microVM, adopts the sandbox and reconnects to the Pod,
so a Gradle daemon-less build that takes an hour survives a microVM swap and the workspace on the
Pod is not rebuilt. Pod tokens are sealed with the registry KMS key using the runtime session id
as encryption context.

With the DynamoDB registry each invocation holds a lease on its runtime session item for as long as
it runs (renewed every 20 s). A second process that receives the same `runtimeSessionId` while the
lease is held waits up to 90 s and then fails with "development session is busy", so a client retry
that lands on a fresh microVM cannot create a second sandbox and Pod. Registry writes are refused
once a process has lost its lease, and a new session whose record cannot be written is closed again
instead of being left without a durable pointer. `remote exec` carries a `request_id`; the client
retries a dropped connection once with the same id and the workload agent returns the running or
stored result instead of running the command again.

What to keep aligned:

- `CWE_SESSION_TIMEOUT_SECONDS` (Code Interpreter idle timeout) ≥ `idle_runtime_session_timeout`, otherwise the sandbox is gone before the microVM.
- `WorkloadProfile.job_timeout_seconds` (default 8 h) ≥ `max_lifetime`, otherwise the Pod is reclaimed under a live session.
- Sessions nobody comes back for are reclaimed by the Code Interpreter timeout, the Job deadline and `cwe reap`; the registry item expires after `CWE_SESSION_REGISTRY_TTL_SECONDS`.
