# Verification: workload Pods, AgentCore Runtime and sticky sessions

What was run on real AWS on 2026-09-14 for the workload Pod backend, the AgentCore Runtime in VPC mode and the session
registry. Account identifiers and tokens are excluded; raw logs are in [evidence/workload/](evidence/workload/).

## Deployment under test

- `cwe-eks-eks` (EKS 1.35, us-east-1) with the `foundation` changes applied: a `build` node group (`r7i.2xlarge`, 300 GiB root
  volume) and ECR repositories for the workload and Runtime images. `platform` applied with the network policy covering
  `cwe-workload` Pods and the Runtime subnet CIDRs.
- `runtime` applied with `private_access = "endpoints"`: two new private subnets in the cluster's default VPC, PrivateLink
  endpoints for Bedrock, AgentCore, STS, KMS, Logs, X-Ray, ECR and EKS plus S3 and DynamoDB gateway endpoints, the Runtime
  execution role with the operator policy and an EKS access entry, the DynamoDB registry table and its KMS key, and the
  AgentCore Runtime itself (idle timeout 300 s for the reattach test). The account had no spare Elastic IP, so the NAT variant
  was not used; both variants are in `infra/terraform/runtime/network.tf`.
- Workload image `device_agent/Dockerfile.workload` on the default JDK 17 base; Runtime image `runtime/Dockerfile`.

## Laptop path (kubectl port-forward, `examples/workload_demo.py`)

| Step | Result |
|---|---|
| Java sample written to the sandbox, workload Pod started on the build node | ~33 s to a healthy agent; 8 CPUs, 61.8 GiB memory, 293 GiB free disk seen from the Pod |
| `sync_workspace_to_workload` (snapshot → S3 → presigned fetch) | 23 files |
| `./gradlew --no-daemon -q test installDist` on the Pod | exit 0 in 19 s (wrapper download included) |
| Service started with `remote_start`, probed from inside the Pod | `/health` 200 `{"status":"ok"}`, `/orders/1001` 200 |
| `--agent`: a bug seeded in `/health`, the Claude agent fixes it with `remote_sync_workspace`, `remote_shell`, `remote_start`, `remote_probe` | succeeded: 6 executions, 12 turns, $0.09 |
| Harness re-verification (tests, rebuild, restart, probe, all by the harness) | tests exit 0, `/health` 200 with `"ok"` |

## Runtime path (`examples/runtime_workload_demo.py`, InvokeAgentRuntime)

| Step | Result |
|---|---|
| `exec` in the Code Interpreter through the Runtime (PrivateLink) | 2 vCPU, 7 GiB, 9.7 GiB disk reported by the microVM |
| `workload`: the Runtime writes its kubeconfig from `CWE_EKS_CLUSTER_NAME`, authenticates with `cwe eks-token`, creates the Job and reaches the Pod IP directly | Pod healthy; 8 CPUs, 66 GiB, 315 GiB free seen from the Pod |
| `remote` sync and exec (`java -version` on the Pod) | OpenJDK 17.0.20 |
| 420 s idle (idle timeout 300 s), then `status` and `remote exec` with the same `runtimeSessionId` | **served by a different process** (`status.process.id` changed), same session id, same Job, workspace file still present |
| `task`: the Claude agent on the Runtime, tools on the Pod (`remote_write_file`, `remote_shell` with `javac`/`java`, `remote_status`) | succeeded; program output `hello from 17.0.20 4` |
| `close` | Job deleted, sandbox stopped, registry item removed; nothing left running |

## Earlier check on the unchanged cluster

Before the Terraform changes were applied, the same code path was run on the Android node with the agent mounted from the
Job's Secret (`inject_agent=True`) into the public `python:3.12-slim` image; see
[evidence/workload/verification.json](evidence/workload/verification.json). Reattach across two local processes was proven
there first (same sandbox, same Job, files intact); `sync_workspace_to_workload` failed as expected because the network
policy did not yet admit `cwe-workload` Pods.

## Findings fixed during verification

- **Client retries duplicate Pods.** botocore's default retry replayed a `workload` invocation that outlived the 60 s read
  timeout, and each replay created a Job. Fixed on both sides: `start_workload` is serialized per session and refuses a second
  Pod, and the demo client uses a 900 s read timeout with retries disabled. Callers of long actions must do the same.
- **Close during start.** A `close` that raced a still-starting workload left a Pod behind; `start_workload` now stops the
  Pod when the session was closed meanwhile, and the Runtime does not re-register a closed session.
- **Endpoints mode needs ECR and EKS endpoints.** In VPC mode the image is pulled through the customer ENI, and
  `ensure_kubeconfig` calls `eks:DescribeCluster`; without those endpoints the first invocation failed after the 120 s
  initialization limit and kubeconfig discovery hung in botocore's retry ladder. Both are in the endpoint list now and
  `ensure_kubeconfig` fails within seconds when the control plane is unreachable.
- **Security group rule descriptions** may not contain `>`.

## What was exercised (offline and pre-apply)

| Step | Result |
|---|---|
| Code Interpreter session created, file written in the sandbox | ok |
| Workload Job + owned Secret created, Pod Ready, agent healthy | 26.7 s from `start_workload` to a healthy agent; Pod saw 8 CPUs, 31 GiB memory, 89 GiB free disk |
| `remote_shell` (`nproc`, `df`, `python3 --version`, `id`) | exit 0; runs as uid 1000 |
| `remote_write_file`, `remote_start` of an HTTP server, `remote_probe` from inside the Pod, `remote_logs`, `remote_stop`, `remote_read_file` | probe returned 200 with the served body; log showed the request |
| `sync_workspace_to_workload` | **failed as expected**: the Pod has no DNS or egress until the platform stage admits the `cwe-workload` label (`url host does not resolve`) |
| Registry record written to and read back from the S3 recordings store | ok |
| Process 1 `detach_all`: Job still running, sandbox still READY | ok |
| Process 2 `SessionManager.attach(record)`: adopts the Code Interpreter session (`get_code_interpreter_session` READY check), reconnects to the Pod | 12.7 s; same session id, same sandbox session, same Job; `cat hello.txt` in the sandbox and `cat app/index.html` on the Pod both returned the files written before the detach |
| `close`: Job deleted, sandbox stopped, registry record removed | no Jobs left, no READY sandbox sessions left |

Local regression tests: **116 passed**. `terraform validate` passed for `storage`, `foundation`, `platform` and `runtime`.
`terraform plan` against the live state: `storage` no changes; `foundation` 4 to add (two ECR repositories, the `build` launch
template and node group), 0 to change, 0 to destroy; `platform` 2 to change (network policy selector, quota), 0 to destroy.

The Runtime image (`runtime/Dockerfile`, linux/arm64) and the workload image (`device_agent/Dockerfile.workload`, linux/amd64)
were built locally. In the Runtime image `kubectl` passed its checksum and runs, `cwe.runtime_app` imports, and `cwe.kube token`
reaches the credential lookup, as the user `app` (uid 10001).

## Not covered

- A real Gradle build through the Runtime path: the `files` action carries text only, so the Java sample (with its wrapper jar)
  was built through the laptop path. Through the Runtime, use `remote exec` with `git clone`, or add a binary-capable upload.
- Invocations longer than the InvokeAgentRuntime request limit: run long builds with `remote start` and poll `remote logs`
  rather than one `remote exec`.
- The NAT variant of the runtime network (`private_access = "nat"`) was planned but not applied in this account.
