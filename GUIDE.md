# End-to-end guide

Everything needed to take this repository from a clean checkout to a working deployment, run sessions on it, host the agent on AgentCore Runtime, operate it, and tear it down. [README.md](README.md) is the summary; [docs/architecture.md](docs/architecture.md) explains the design; the two verification reports ([Android](docs/verification-eks.md), [workload and Runtime](docs/verification-workload.md)) show what was actually run.

Contents

0. How the pieces fit
1. Prerequisites and local setup
2. Reaching the EKS API
3. Deploy: storage, foundation, platform, images, verification, Runtime
4. Run: examples, Python API, REST API, Runtime payloads, agent tools
5. Operate: capacity, monitoring, reaping, troubleshooting
6. Security model and trust boundary
7. Repository layout
8. Limits and known gaps
9. Clean up
10. Sharing the repository

A first deployment takes about an hour, most of it waiting for EKS.

| Stage | What happens | Typical wait |
|---|---|---|
| Local setup and offline tests | Install the package, run the regression suite | 5 min |
| `storage` | Recording bucket | 1 min |
| `foundation` | Code Interpreter, IAM, ECR, EKS cluster and three node groups (system, Android, build) | 15 to 25 min |
| `platform` | Namespace, RBAC, KVM plugin, network policies | 2 min |
| `images` | Build and push the sidecar, workload and Runtime images | 5 to 15 min |
| `runtime` (optional) | Private subnets and NAT or PrivateLink endpoints, AgentCore Runtime in VPC mode, execution role, session registry | 5 to 10 min |
| First Android session | Emulator image pull and boot, SDK download and Gradle build | 3 to 5 min |
| First workload session | Toolchain image pull, agent ready | 1 to 2 min |

The EKS control plane and any ready nodes are billed while idle. Tear down with section 9 when you are done.

## 0. How the pieces fit

Letting an agent write and run code raises questions that a plain sandbox does not answer. Each part of this platform exists to answer one of them.

- **Where does the code run, and what can it reach?** Environments are declared once as YAML profiles (`examples/profiles/`), provisioned into a fresh AgentCore Code Interpreter session, and external dependencies are replaced by mock HTTP services inside the sandbox. The agent edits and runs small things here.
- **What if the build does not fit?** A Code Interpreter microVM has 2 vCPU, 8 GB of memory and 10 GB of disk, and a Runtime microVM 2 vCPU, 8 GB and 1 GB of session storage; none of it can be raised. A session can attach a **workload Pod** on EKS sized by a `WorkloadProfile` (image, CPU, memory, ephemeral storage, environment). The agent gets tools to sync code to it, run builds and tests, start the service and probe it over HTTP. The Pod is where heavy things happen.
- **Does the app work on a device?** Code Interpreter has no KVM. A device lab on EKS provides one Android emulator per Job with screenshots, UI dumps, input, installs, instrumented tests, screen recording and a live view.
- **What did the agent actually do?** Every execution, message, written file, screenshot and remote command is written as JSONL and artifacts to S3 or a local directory. A closed session replays offline and can be re-scored later without the sandbox.
- **Did it succeed, by whose account?** Scoring combines deterministic rules, an LLM judge that sees the transcript, and an optional AgentCore Evaluations pass. The harness runs the verification command itself, on the sandbox or on the Pod, and ignores what the agent claims.
- **What happens when the microVM goes away?** AgentCore Runtime pins a `runtimeSessionId` to a microVM but replaces it after the idle timeout or maximum lifetime. A **session registry** records the Code Interpreter session and the Pods, and the next microVM reattaches to them. With the DynamoDB registry each invocation also holds a lease on its runtime session, so two cold processes cannot each create an environment.

Everything passes through `DevSession` (`src/cwe/session.py`), so every command, file write, device action and remote command is recorded the same way whether a person, a CI job, the REST API, the Runtime or the agent issued it. Each EKS Job has a lifetime deadline and a TTL after completion; its token lives in a Kubernetes Secret owned by the Job and is garbage collected with it.

The EKS side exists because Code Interpreter has no KVM, no custom images, no adjustable size and no managed session storage.

## 1. Prerequisites and local setup

| Requirement | Notes |
|---|---|
| Python 3.12 | Package metadata allows 3.11+, but development, tests and containers target 3.12. |
| `uv` (optional) | The commands below use `uv`; `python -m venv .venv` and `pip install -e '.[dev]'` are equivalent. |
| Terraform 1.5+ | The AWS provider is pinned to 6.x (6.64 or later); lock files are committed. |
| AWS CLI, kubectl | `kubectl` must be able to reach the EKS API from wherever you run it (section 2). |
| Finch or Docker | Builds the sidecar and workload images for `linux/amd64` and the Runtime image for `linux/arm64`. Set `CWE_CONTAINER_CLI=docker` to use Docker. |
| AWS permissions | Create EKS, IAM, VPC resources, ECR, S3, KMS, DynamoDB and AgentCore Code Interpreter and Runtime. The first VPC-mode Runtime in an account also needs `iam:CreateServiceLinkedRole`. |
| Quotas | vCPUs for the node groups; one Elastic IP if the runtime stage creates a NAT gateway (`private_access = "nat"`). Accounts at the EIP limit use `private_access = "endpoints"`. |
| Bedrock model access | `us.anthropic.claude-opus-5` (agent) and `anthropic.claude-opus-5` (judge) must be usable in the region. Outside the US regions set `CWE_AGENT_MODEL` and `CWE_JUDGE_MODEL` to a cross-region inference profile the region offers (`global.anthropic.claude-opus-5` in Seoul) and add it to `bedrock_model_ids`. Check Bedrock model access in the console if a first invocation returns `AccessDeniedException`. |
| An existing VPC | Two or more subnets in different Availability Zones for the nodes. Private subnets need NAT; public subnets need `MapPublicIpOnLaunch` for node egress. The `runtime` stage can add two private subnets for the Runtime; nothing else creates a VPC, NAT, endpoints or a VPN. |

Nodes need outbound HTTPS to ECR, S3, STS and to the public image, Gradle and Android SDK repositories.

Install the package and confirm the offline suite passes. Nothing here touches AWS.

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e '.[dev]'
python -m pytest -q          # expect: 126 passed
```

The suite covers the session and recording model, the agent harness and budget hooks, the workload agent (paths, downloads, archives, exec dedup), the Job manifests, the registry and lease logic, EKS token generation and the security guards. It uses fakes for AWS and Kubernetes and real local processes for the in-Pod agent.

## 2. Reaching the EKS API

The cluster endpoint is private-only by default, so Terraform for the `platform` stage and every `kubectl` call must run somewhere with VPC connectivity. To work from a laptop without a VPN, set `endpoint_public_access = true` and list your own fixed egress CIDR in `endpoint_public_access_cidrs`. `0.0.0.0/0` is rejected. Find your egress address with `curl https://checkip.amazonaws.com`.

This setting controls access to the Kubernetes API only; it never exposes the in-Pod agents. If your address changes later, `kubectl` fails with `Unable to connect to the server: ... i/o timeout`; update the CIDR list and re-apply the foundation stage.

## 3. Deploy

Terraform is split into four roots with separate state. Copy each `terraform.tfvars.example` to `terraform.tfvars`, fill in real values, and apply in order: `storage`, `foundation`, `platform`, then optionally `runtime` followed by a second `platform` apply that admits the Runtime subnets. `scripts/deploy.sh` runs `init` and `plan` for a stage and applies only with `--apply`.

| Root | Creates |
|---|---|
| `infra/terraform/storage` | Recording S3 bucket: versioning, encryption, public access block, TLS-only policy, lifecycle, `prevent_destroy`. |
| `infra/terraform/foundation` | AgentCore Code Interpreter, IAM roles and policies, ECR repositories, KMS key, EKS cluster, system, Android and build node groups, VPC CNI with network policy support. |
| `infra/terraform/platform` | Namespace, service account, RBAC, resource quota, KVM device plugin, network policies (plus Runtime subnet CIDRs). |
| `infra/terraform/runtime` | Optional. Private subnets with a NAT gateway or PrivateLink endpoints, the AgentCore Runtime (VPC mode), its security group and the cluster security group rules, execution role, EKS access entry, session registry (DynamoDB + KMS). |

### 3.1 Storage

```bash
cp infra/terraform/storage/terraform.tfvars.example infra/terraform/storage/terraform.tfvars
./scripts/deploy.sh --stage storage            # plan only
./scripts/deploy.sh --stage storage --apply
```

Keep `region`, `project_name` and `recordings_bucket_name` consistent between `storage` and `foundation`. `recordings_prefix` in the foundation stage confines the operator role to one key prefix of the bucket; it must match the prefix in `CWE_STORAGE_URI`. The sandbox execution role has no S3 access unless `sandbox_recordings_access = true`, which nothing in this repository needs.

### 3.2 Foundation

```bash
cp infra/terraform/foundation/terraform.tfvars.example infra/terraform/foundation/terraform.tfvars
```

Values to fill in:

- `vpc_id`, `subnet_ids`: an existing VPC and at least two subnets in different AZs.
- `cluster_version`: a Kubernetes version EKS currently supports in your region, for example `1.35`. `aws eks describe-cluster-versions --query 'clusterVersions[].clusterVersion'` lists them.
- `cluster_admin_role_arn`: the IAM role you will use for the platform stage and for `kubectl`. It must be a role ARN, not the STS session ARN that `aws sts get-caller-identity` prints. Convert `arn:aws:sts::123456789012:assumed-role/MyRole/session` to `arn:aws:iam::123456789012:role/MyRole`. For IAM Identity Center roles the path matters: `arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/<region>/AWSReservedSSO_<PermissionSet>_<id>`.
- `operator_role_arns`: optional extra roles allowed to run sessions. Terraform always creates its own `<project>-session-operator` role as well.
- `endpoint_public_access`, `endpoint_public_access_cidrs`: see section 2.
- `android_desired_size`: the number of concurrent devices you want ready; one node serves one emulator. Set to 0 if you only need workload Pods.
- `build_instance_type`, `build_volume_size`, `build_desired_size`: the node group for build/run workload Pods. No KVM is needed there, so any family works; size memory for your largest build and the volume for image layers plus every Pod's workspace. The verified deployment used `r7i.2xlarge` with a 300 GiB volume. For a backend-only deployment set `android_desired_size = 0`; this node group is the one that matters.
- `network_policy_enforcing_mode`: leave `standard` for the first apply. In `strict` mode every new Pod is default-deny until a policy selects it, and the CoreDNS policy only exists after the platform stage, so a fresh cluster created in strict mode never gets a healthy CoreDNS and the `coredns` addon times out. You switch to `strict` in 3.3.
- `sandbox_recordings_access`: leave `false`.

```bash
./scripts/deploy.sh --stage foundation
./scripts/deploy.sh --stage foundation --apply
```

Applying this stage creates a KMS key for envelope encryption of Kubernetes Secrets, which is where per-Pod tokens live. Terraform also creates the `<project>-session-operator` role for running sessions, attaches the matching IAM policy, and maps it to the `cwe-operators` Kubernetes group. Only `cluster_admin_role_arn` may assume it.

Then point kubectl at the cluster:

```bash
terraform -chdir=infra/terraform/foundation output cluster_name
aws eks update-kubeconfig --region <region> --name <cluster-name> --role-arn <cluster-admin-role-arn>
kubectl config current-context
kubectl get nodes                         # system, android and build nodes, all Ready
```

The default context name is the cluster ARN. If you pass `--alias`, use that alias for the platform `kube_context` and for `CWE_EKS_CONTEXT`. If you wrote the kubeconfig somewhere other than `~/.kube/config`, note the path; both the platform stage and `.env.eks` need it.

### 3.3 Platform

```bash
cp infra/terraform/platform/terraform.tfvars.example infra/terraform/platform/terraform.tfvars
```

Values to fill in:

- `kube_context`: the context name from 3.2.
- `kubeconfig_path`: only if your kubeconfig is not `~/.kube/config`.
- `kvm_plugin_image`: the KVM device plugin, pinned by digest. This DaemonSet is the one privileged workload in the cluster, so review the image and pin exactly what you reviewed. A mutable tag such as `:latest` is rejected. To get the digest of the current upstream release:

```bash
finch pull squat/generic-device-plugin:latest          # or: docker pull
finch image inspect squat/generic-device-plugin:latest --format '{{index .RepoDigests 0}}'
```

The verified deployment used `squat/generic-device-plugin@sha256:dc192e164c69b03f156765793a1be62ca437709ae477b27ca7d8f3dcf5021576`.

- `orchestrator_cidrs`: leave empty for now; filled in after the runtime stage (3.6).

```bash
./scripts/deploy.sh --stage platform
./scripts/deploy.sh --stage platform --apply
kubectl -n kube-system rollout status daemonset/cwe-kvm
kubectl get nodes -l cwe/workload=android \
  -o 'custom-columns=NAME:.metadata.name,KVM:.status.allocatable.devic\.es/kvm'
```

The last command must show `1` in the KVM column for every Android node. If it shows `<none>`, check `kubectl -n kube-system logs daemonset/cwe-kvm` and `/dev/kvm` on the node, and confirm nested virtualization is set on the current launch template version.

Now that the namespace policies and the CoreDNS policy exist, turn on strict enforcement so that every new Pod starts default-deny instead of open until its policy is reconciled:

```bash
sed -i '' 's/^network_policy_enforcing_mode.*/network_policy_enforcing_mode = "strict"/' infra/terraform/foundation/terraform.tfvars
./scripts/deploy.sh --stage foundation --apply        # updates the vpc-cni addon only
kubectl -n kube-system rollout status daemonset/aws-node --timeout=300s
kubectl -n kube-system get pods -l k8s-app=kube-dns    # both Running and Ready
```

### 3.4 Images and environment file

```bash
./scripts/deploy.sh --stage images --tag v1 --workload --runtime
set -a; source .env.eks; set +a
```

This builds `device_agent/Dockerfile` and `device_agent/Dockerfile.builder` for `linux/amd64`, pushes both to ECR, and writes `.env.eks` with the interpreter id, bucket, cluster context and image references. ECR tags are immutable, so use a new tag for every change.

`--workload` builds `device_agent/Dockerfile.workload` from the repository root: your toolchain plus the workload agent (`src/cwe/workload_agent.py`). The default base is a JDK 17 image; pass `--workload-base eclipse-temurin:21-jdk` (or your own image, pinned by digest) for another toolchain. The result is written as `CWE_WORKLOAD_IMAGE`. Any image that already has `python3` can be used without this build by setting `WorkloadProfile(inject_agent=True)`, which mounts the agent from the Job's Secret.

`--runtime` builds `runtime/Dockerfile` for `linux/arm64` and writes `CWE_RUNTIME_IMAGE`; it is only needed for 3.6.

Values that are not generated and may need to be added by hand to `.env.eks` (the script preserves extra keys on later runs):

- `KUBECONFIG=<path>` if your kubeconfig is not `~/.kube/config`.
- `CWE_EKS_NAMESPACE=<name>` if you changed the namespace in the platform stage.
- `CWE_API_KEY=<random>` if you plan to run the REST API.

The Android Dockerfiles pin their base image by digest and every downloaded tool by URL and SHA-256: the device agent takes `adb` from Google's platform-tools release on Amazon Linux 2023 minimal (pulled from ECR Public, which may need `aws ecr-public get-login-password | finch login` first), and the builder installs the Android command-line tools on `eclipse-temurin:17-jdk`. The builder pre-installs the SDK components the sample app needs (`SDK_PACKAGES` in `Dockerfile.builder`); add your own versions there to make repeat builds faster.

After the push the script waits for the ECR scan and refuses to write `.env.eks` if an image has a CRITICAL finding (`--allow-critical` overrides). Base images accumulate published CVEs over time, so rebuild with a new tag on a schedule and refresh the digests when you do.

Mirror the emulator image as well, so nodes pull it from ECR under an immutable tag instead of from Google's registry by a mutable `latest` tag:

```bash
./scripts/deploy.sh --stage images --mirror-emulator      # pulls linux/amd64, pushes <repo>:30-google-x64-<date>
set -a; source .env.eks; set +a                           # now also contains CWE_ANDROID_EMULATOR_IMAGE
```

Images for other API levels are built by your own pipeline and pushed to the same repository, then selected with `AndroidEmulatorProfile.image` or `images`.

### 3.5 Confirm the deployment

Run these before handing the environment to anyone. Each one should complete without an error.

```bash
python examples/quickstart.py                                   # sandbox loop, about a minute; ends with EVAL: ... PASS
python examples/workload_demo.py                                # Java service built and probed on a workload Pod; ends with PASSED
python examples/android_quickstart.py                           # boots a device, prints the Android version, deletes the Job
python infra/verify_eks_security.py --env-file .env.eks         # all checks true; run while a session Pod exists for the Pod checks
terraform -chdir=infra/terraform/foundation plan                # No changes
```

`verify_eks_security.py` asserts the security model against the live account: endpoint exposure, secret encryption, audit logging, IMDSv2, nested virtualization, node security groups, bucket settings, network policies, and for every session Pod it finds (Android device Pod, workload Pod) the security context, the read-only root filesystem of the workload container, the token source, and instance metadata reachability from inside the Pod. The report's `pods_checked` lists which Pod kinds were present.

To exercise the full Android loop under the restricted session role, including a real Gradle build, instrumented tests, an agent fix and post-hoc scoring:

```bash
python examples/eks_demo.py --env-file .env.eks --agent \
  --operator-role-arn "$(terraform -chdir=infra/terraform/foundation output -raw operator_role_arn)"
```

Temporary AssumeRole credentials are passed to the demo process only and never written to a file. Reports and media land in `.cwe_data/eks-demo/`. Running this under the operator role rather than your administrator credentials is what proves the operator IAM policy and namespace RBAC are sufficient.

### 3.6 AgentCore Runtime (optional)

Host the orchestrator on AgentCore Runtime instead of a laptop or CI job. The Runtime runs in VPC mode so it reaches session Pods directly, and the session registry makes sessions sticky across microVM replacement (details in [runtime/README.md](runtime/README.md)).

```bash
cp infra/terraform/runtime/terraform.tfvars.example infra/terraform/runtime/terraform.tfvars
terraform -chdir=infra/terraform/foundation output      # cluster_name, code_interpreter_id, recordings_bucket, operator_policy_arn, vpc_id
grep -E 'CWE_RUNTIME_IMAGE|CWE_WORKLOAD_IMAGE' .env.eks   # runtime_image, workload_image
./scripts/deploy.sh --stage runtime
./scripts/deploy.sh --stage runtime --apply
terraform -chdir=infra/terraform/runtime output runtime_subnet_cidrs
```

Values to decide:

- `subnet_ids` or `private_subnets`: the Runtime's ENIs never get a public IP, so give it private subnets dedicated to it, either existing ones or two that the root creates. Do not reuse the EKS node subnets; `orchestrator_cidrs` would then admit every Pod in the cluster to the agent port.
- `private_access`: `nat` (a NAT gateway, needs one Elastic IP) or `endpoints` (PrivateLink for Bedrock, AgentCore, STS, KMS, Logs, X-Ray, ECR and EKS plus S3 and DynamoDB gateway endpoints, no internet path). The image is pulled through the Runtime's ENI, so the ECR endpoints are not optional.
- `idle_runtime_session_timeout`: seconds before an idle microVM is released. Keep it at or below `CWE_SESSION_TIMEOUT_SECONDS` so the sandbox outlives the microVM. 1800 is a reasonable default; the verification used 300 to force a swap quickly.

Put the printed CIDRs into `orchestrator_cidrs` of `infra/terraform/platform/terraform.tfvars` and re-apply the platform stage; until then the network policy does not admit the Runtime. The first VPC-mode Runtime in an account creates the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role, so the applying principal needs `iam:CreateServiceLinkedRole`.

Then try it end to end:

```bash
python examples/runtime_workload_demo.py --agent-runtime-arn "$(terraform -chdir=infra/terraform/runtime output -raw agent_runtime_arn)" \
  --memory 16Gi --disk 50Gi --idle-wait 420        # longer than idle_runtime_session_timeout: proves reattach to the same Pod
```

The demo runs a command in the sandbox, starts a workload Pod, syncs the workspace, runs a Gradle build on the Pod, waits past the idle timeout, and prints `same session True same Pod True new microVM process True` when the invocation after the wait was served by a different process that adopted the same sandbox and Pod through the registry. Its output from the verified run is in [docs/evidence/workload/runtime-demo.log](docs/evidence/workload/runtime-demo.log).

What to keep aligned between the Runtime, the sandbox and the Pods:

- `CWE_SESSION_TIMEOUT_SECONDS` (Code Interpreter idle timeout) at or above `idle_runtime_session_timeout`, otherwise the sandbox is gone before the microVM.
- `WorkloadProfile.job_timeout_seconds` (default 8 h) at or above the Runtime's maximum lifetime, otherwise the Pod is reclaimed under a live session.
- `CWE_SESSION_REGISTRY_TTL_SECONDS` (default 24 h) above the longest session you expect.

## 4. Run

### 4.1 Examples

```bash
python examples/quickstart.py               # sandbox only: provision, run, snapshot, evaluate, replay
python examples/quickstart.py --agent       # same task delegated to the agent
python examples/workload_demo.py            # Java service: sync, gradle build, run, probe on a workload Pod
python examples/workload_demo.py --agent    # plus: the agent fixes a seeded bug on the Pod and the harness re-verifies
python examples/android_quickstart.py       # EKS device: boot, screenshot, UI dump, evaluate
python examples/android_quickstart.py --agent
python examples/bring_your_own_agent.py     # wire the session tools into your own ClaudeAgentOptions
cwe android-setup examples/android-sample   # propose an emulator profile from a Gradle project
```

What to expect: the sandbox quickstart finishes in about a minute and prints the rule and judge scores. The agent variants take a few minutes and a few cents of Bedrock usage; their output includes token usage and the cost estimate recorded on the run. The workload demo prints the Pod's CPU, memory and disk, the Gradle exit code and the HTTP probes, and writes a report to `.cwe_data/workload-demo/`. The Android quickstart prints the device agent URL, the Settings UI nodes and the Android version, then deletes the Job. Recordings land under `CWE_STORAGE_URI/<session_id>/`.

### 4.2 Python API

A backend service that does not fit the microVM: build and run it on a workload Pod and verify it over HTTP from inside the Pod.

```python
from cwe.session import SessionManager
from cwe.workload import WorkloadProfile

manager = SessionManager()
session = manager.create()
try:
    session.start_workload(WorkloadProfile(memory="24Gi", ephemeral_storage="100Gi"))   # image from CWE_WORKLOAD_IMAGE
    session.begin_run("build-and-run")
    session.workload_exec("git clone --depth 1 https://github.com/example/service.git .", timeout=600)
    build = session.workload_exec("./gradlew --no-daemon -q bootJar", timeout=1800)
    session.workload_start("svc", "java -jar build/libs/*.jar --server.port=8081")
    print(session.workload_probe(8081, "/actuator/health"))
    session.end_run()
finally:
    manager.close(session.info.session_id)
```

`WorkloadProfile` fields:

| Field | Default | Meaning |
|---|---|---|
| `image` | `CWE_WORKLOAD_IMAGE` | Toolchain image carrying the workload agent, or any image with `python3` when `inject_agent=True` |
| `cpu`, `cpu_limit` | `4`, same as `cpu` | Kubernetes quantities |
| `memory` | `16Gi` | Requests equal limits, so the scheduler places the whole build |
| `ephemeral_storage` | `50Gi` | Size of the workspace `emptyDir`, also requested as ephemeral storage |
| `tmp_size` | `4Gi` | Size of the `/tmp` `emptyDir` (`java.io.tmpdir`, `HOME`) |
| `env` | `{}` | Non-secret environment for the toolchain (`GRADLE_OPTS`, `JAVA_TOOL_OPTIONS`) |
| `boot_timeout` | 600 s | Wait for the Pod and the agent to become ready |
| `job_timeout_seconds` | 8 h | Job deadline; the Pod is reclaimed after it |
| `node_selector`, `toleration_key` | `cwe/workload=build`, `cwe/build` | Placement on the build node group |
| `arch` | `amd64` | Node architecture |
| `inject_agent` | `false` | Mount the agent from the Job's Secret instead of expecting it in the image |
| `read_only_root` | `true` | Read-only root filesystem; workspace, cache, logs and `/tmp` stay writable |

Sync the sandbox workspace to the Pod with `session.sync_workspace_to_workload()` (snapshot to S3, presigned GET, extraction inside the Pod; needs an S3 store). Run something longer than a few minutes with `workload_start` and poll `workload_logs`.

Android:

```python
from cwe.android import AndroidEmulatorProfile

session = manager.create()
try:
    session.start_android(AndroidEmulatorProfile())
    session.begin_run("inspect")
    session.screenshot()
    session.end_run()
finally:
    manager.close(session.info.session_id)
```

### 4.3 Agent tools

`cwe.agent.run_task(session, text, settings)` runs the Claude Agent SDK on Bedrock with an in-process MCP server that exposes the session. The tool list is closed and every run carries a budget (executions, wall clock, cost, turns; defaults from `CWE_DEFAULT_MAX_*`).

| Group | Tools |
|---|---|
| Sandbox | `run_shell`, `run_python`, `write_file`, `write_and_run`, `read_file`, `list_files`, `run_tests`, `read_full_output`, `list_skills`, `load_skill` |
| Workload Pod (when attached) | `remote_shell`, `remote_start`, `remote_stop`, `remote_logs`, `remote_probe`, `remote_read_file`, `remote_write_file`, `remote_sync_workspace`, `remote_status` |
| Android (when attached) | `android_screenshot`, `android_ui`, `android_tap`, `android_swipe`, `android_type`, `android_key`, `android_shell`, `android_install`, `android_launch`, `android_logcat`, `android_build`, `android_install_built`, `android_run_tests`, `android_live_view_url` |

Tool output is summarized into the model's context; the full output stays in the recording and is retrievable with `read_full_output`. `examples/bring_your_own_agent.py` shows how an existing `ClaudeAgentOptions` picks up the same tools and hooks by adding two fields.

### 4.4 REST API

```bash
CWE_API_KEY=<random> cwe serve              # 127.0.0.1:8000; every request needs x-api-key
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/sessions`, `GET /v1/sessions`, `GET|DELETE /v1/sessions/{sid}` | Create, list, inspect, close |
| `POST /v1/sessions/{sid}/runs`, `POST .../runs/{run_id}/finish` | Run boundaries |
| `POST /v1/sessions/{sid}/exec`, `POST .../files`, `GET .../files/{path}` | Sandbox execution and files |
| `POST /v1/sessions/{sid}/message` | Record a message from the developer to the agent |
| `POST /v1/sessions/{sid}/workload`, `POST .../remote` | Start the workload Pod; exec, start, stop, logs, probe, sync on it |
| `POST /v1/sessions/{sid}/snapshots`, `POST .../evaluate`, `POST /v1/recorded/{sid}/evaluate` | Snapshot, score a live session, re-score a closed one |
| `GET /v1/sessions/{sid}/events`, `GET .../transcript` | The recording |

The API binds `127.0.0.1` unless `CWE_API_KEY` is set, caps request bodies, accepts only server-generated ids, and never returns Pod tokens. It is one shared key: a trusted operator boundary, not per-user authorization.

### 4.5 Runtime payloads

With the Runtime deployed, a client calls `invoke_agent_runtime` with a `runtimeSessionId` it chooses (33 or more characters) and a JSON payload. The same id keeps reaching the same session, across microVM swaps.

```python
import json, secrets
import boto3
from botocore.config import Config

client = boto3.client("bedrock-agentcore", region_name="us-east-1",
                      config=Config(read_timeout=900, connect_timeout=10, retries={"max_attempts": 1}))
rid = f"dev-{secrets.token_hex(16)}"

def invoke(payload):
    r = client.invoke_agent_runtime(agentRuntimeArn=ARN, runtimeSessionId=rid, contentType="application/json",
                                    accept="application/json", payload=json.dumps(payload).encode())
    return json.loads(r["response"].read())

invoke({"action": "files", "files": {"README.md": "# demo\n"}})
invoke({"action": "workload", "profile": {"memory": "24Gi", "ephemeral_storage": "100Gi"}})
invoke({"action": "remote", "type": "sync"})
build = invoke({"action": "remote", "type": "exec", "input": "./gradlew --no-daemon -q assemble", "timeout": 3600})
invoke({"action": "task", "text": "Make the failing test in MainTest pass"})
invoke({"action": "status"})     # session, sandbox, Pod and a per-process marker; tokens excluded
invoke({"action": "close"})
```

| action | description |
|---|---|
| `exec` | run `{"type":"command"\|"code"\|"pytest","input":"..."}` in the sandbox |
| `files` | write files to the sandbox workspace |
| `task` | delegate to the agent; `remote_*` tools appear once a workload is attached |
| `workload` | start the session's Pod from `WorkloadProfile` fields (all optional) |
| `remote` | `exec`, `sync`, `start`, `stop`, `logs`, `probe` on the Pod |
| `evaluate` | rules plus LLM judge |
| `snapshot`, `events`, `status`, `close` | snapshot, read the recording, inspect, tear down and delete the registry record |

Give long actions time and do not let botocore retry them. A retried `workload` waits for the first Pod rather than creating a second one, and a retried `remote exec` joins the running command through its `request_id`, but the retry still blocks for the remaining build time. Run anything longer than a few minutes with `remote start` and `remote logs`.

## 5. Operate

```bash
kubectl -n "$CWE_EKS_NAMESPACE" get jobs,pods -l app.kubernetes.io/name=cwe-workload
kubectl -n "$CWE_EKS_NAMESPACE" get jobs,pods -l app.kubernetes.io/name=cwe-android
kubectl -n "$CWE_EKS_NAMESPACE" logs <pod-name> -c workload            # or -c emulator, -c device-agent, -c builder
cwe reap                                                                # list expired Jobs and stale sandbox sessions
cwe reap --apply                                                        # reclaim them
python infra/verify_eks_security.py --env-file .env.eks                 # re-run the deployment security checks
```

`cwe reap` reads its settings from the environment, so source `.env.eks`. Without the Android images it reaps workload Jobs and reports that Android Jobs were skipped. Run it periodically (cron or EventBridge); Job deadlines and TTLs reclaim Pods on their own, reaping only shortens the wait.

With the Runtime deployed:

```bash
aws logs tail /aws/bedrock-agentcore/runtimes/<runtime-id>-DEFAULT --since 30m --format short   # Runtime container log
aws dynamodb scan --table-name "$(terraform -chdir=infra/terraform/runtime output -raw session_table)" \
  --query 'Items[].{rid:runtime_session_id.S,sid:session_id.S,expires:expires_at.N,lease:lease_owner.S}'
```

A `lease_owner` on an item means a process is serving that runtime session right now; the lease expires 120 s after the last renewal if the process dies. Records are sealed, so the scan shows identifiers only.

Capacity: one KVM slot per Android node, so two concurrent devices need `android_desired_size = 2`. A build node takes as many workload Pods as its memory allows (`WorkloadProfile.memory` against the node's allocatable memory); the namespace quota caps the total (16 Pods, 320 GiB memory, 1600 GiB ephemeral storage by default). Raising `*_max_size` alone does not add nodes; no autoscaler is installed. The EKS control plane, ready nodes, a NAT gateway and PrivateLink endpoints cost money while idle; the Runtime bills only during active sessions.

| Symptom | Check |
|---|---|
| `Unable to connect to the server: ... i/o timeout` | Your current egress IP is not in `endpoint_public_access_cidrs`, or you are outside the VPC with a private-only endpoint (section 2) |
| `kubectl ... failed` | `CWE_EKS_CONTEXT`, `KUBECONFIG`, AWS role, EKS access entry, namespace RBAC, API reachability |
| Workload Pod `Pending` | `build_desired_size`, node memory versus `WorkloadProfile.memory`, `ephemeral_storage` versus `build_volume_size`, namespace quota |
| Android Pod `Pending` | `devic.es/kvm` capacity, node count, taints and tolerations |
| CoreDNS `CrashLoopBackOff` on a fresh cluster, `coredns` addon stuck in `CREATING` | `network_policy_enforcing_mode = "strict"` before the platform stage created the `cwe-coredns` policy; apply the platform stage (CoreDNS recovers within a minute) and re-run the foundation apply, or create the cluster in `standard` mode first |
| `ImagePullBackOff` | ECR image tag, node pull role, NAT or registry reachability |
| Agent 401 / 403 | Token or `x-cwe-session` mismatch, or a stale tunnel from a previous session |
| Emulator boot timeout | Emulator logs, `/dev/kvm`, whether the image serves ADB on 5555 |
| Gradle failure | JDK in the image, HTTPS reachability of package repositories, `gradlew` present in the source |
| Toolchain writes fail with read-only filesystem | The image writes outside the workspace, cache or `/tmp`; set `read_only_root=False` or fix the image's `HOME`, `GRADLE_USER_HOME`, `MAVEN_OPTS` |
| Private repository unreachable | The network policy allows only DNS and public HTTPS; add the approved private CIDR and port explicitly |
| `DeadlineExceeded` | `job_timeout_seconds` reached; the Pod is terminated and the Job and Secret are reclaimed by TTL |
| `AccessDeniedException` from Bedrock | Model access not enabled in the region, or the operator policy's model list does not include the model id in use |
| Runtime cannot reach the Pod (timeouts on 8080) | `orchestrator_cidrs` in the platform stage, the cluster SG rule from the runtime stage, `CWE_EKS_ACCESS=pod` |
| Runtime `kubectl ... failed` | EKS access entry for the runtime role, `CWE_EKS_CLUSTER_NAME`, private endpoint reachable from the Runtime subnets |
| `Runtime initialization time exceeded` or 502 on the first call | Image pull through the VPC failed: with `endpoints`, the `ecr.api`/`ecr.dkr` endpoints and their security group; with `nat`, the route table |
| `development session is busy` | Another process holds the lease for this runtime session (a retry landed on a new microVM while the first call still runs); wait and retry |
| `session registry write failed; refusing to continue` | DynamoDB unreachable or the execution role lacks `dynamodb:UpdateItem`; the new session was closed, nothing is orphaned |
| Session restarted from scratch after a pause | Sandbox timed out (`CWE_SESSION_TIMEOUT_SECONDS` below the Runtime idle timeout) or the Job hit its deadline; see the Runtime log line "reattach ... failed" |

Expired AWS credentials surface as `401 Unauthorized` or `The security token included in the request is expired`. Refresh the profile or session credentials and confirm with `aws sts get-caller-identity`. Environment variables take precedence over profiles, and a running process does not pick up new ones. If Terraform stopped mid-apply, query the real state and reconcile before the next plan.

## 6. Security model and trust boundary

- **Cluster**: the EKS API is private by default; a public endpoint requires an explicit fixed CIDR and `0.0.0.0/0` is rejected. Kubernetes Secrets are envelope-encrypted with a customer-managed KMS key, so revoking the key revokes the session tokens. All control-plane log types are on. Nodes require IMDSv2 with hop limit 1, encrypted root volumes and no world-open ingress.
- **Pods**: the namespace enforces the `baseline` Pod Security Standard and audits `restricted`. Session containers drop all capabilities, disable privilege escalation, use the default seccomp profile, mount no host path, run as uid 1000 with `runAsNonRoot`, and have service account token automounting off. The workload container's root filesystem is read-only; only the workspace, cache, logs and `/tmp` `emptyDir` volumes are writable. `/dev/kvm` is granted through the device plugin resource, not privileged mode; the plugin DaemonSet is the one privileged workload and is pinned by digest.
- **Network**: the namespace denies all traffic by default. Session Pods are allowed DNS plus public HTTPS only, excluding private, carrier-grade NAT and link-local ranges, so a build reaches neither instance metadata nor other cluster services nor the Kubernetes API. Ingress to port 8080 is allowed only from labelled in-cluster orchestrator Pods and from the Runtime subnets in `orchestrator_cidrs`. Nothing is published through a Service, Ingress or load balancer.
- **Runtime network**: the Runtime's ENIs sit in private subnets. With `private_access = "endpoints"` it reaches AWS through PrivateLink and gateway endpoints and has no route to the internet. Its security group may send only HTTPS and port 8080 inside the VPC; the cluster security group admits it on 443 and 8080.
- **In-Pod agents**: both refuse to start without a token, compare it in constant time, require it on every endpoint except `/healthz`, and bind to one session id. Tokens live only in Job-owned Secrets (the operator role can create Secrets but not read them) and, for reattach, in the registry. Downloads are HTTPS-only and re-checked against private, loopback and link-local addresses after every redirect; archives are extracted with a filter that rejects path escapes and links pointing outside the destination. The Android live view exchanges a single-use viewer token for an `HttpOnly` cookie.
- **Registry**: the whole record is sealed with KMS using the runtime session id as encryption context, so it cannot be read, copied to another session or forged by anyone without the key, and every read checks the record was written for the requesting session. An S3-backed registry without the key is refused. Under DynamoDB every write is conditioned on holding the session lease.
- **Sandbox**: the Code Interpreter execution role has no S3 access unless `sandbox_recordings_access` is set; snapshots and syncs go through the orchestrator. Profile environment values are written to a file inside the sandbox and never appear in commands, recordings, transcripts, judge prompts or session metadata.
- **Agent and API**: agent runs always carry a budget, the tool allowlist is closed (`dontAsk`, and `bypassPermissions` is refused), credential-shaped variables are blanked before the agent process starts, and the judge treats the transcript as untrusted data. The REST API binds `127.0.0.1` unless `CWE_API_KEY` is set, caps request bodies, and accepts only server-generated ids.
- **Storage**: the recordings bucket blocks public access, keeps versions, is encrypted, and refuses any request not made over TLS. The operator role is confined to one key prefix.
- **Trust boundary**: an operator, and the Runtime execution role, can create Jobs in the namespace, which is equivalent to mounting any Secret in that namespace. Operators are trusted. For multi-user isolation, give each user or team their own namespace and role, mapped from AgentCore Identity claims. The workload Pod runs the customer's own build scripts as uid 1000; it is one trust domain per session, isolated from the cluster and from other sessions, not from the code it builds. The emulator container runs as root inside its own container, which `baseline` permits. The sandbox and the Pods can reach any public HTTPS host, so an agent misled by repository content could send workspace contents outward; the system prompt forbids it, and an egress allowlist is the hardening step for production.

`infra/verify_eks_security.py` checks the cluster, node, bucket, network policy and Pod parts of this list against the live account (3.5).

## 7. Repository layout

- `src/cwe/`: `session.py` (DevSession, SessionManager), `sandbox.py` (Code Interpreter, replay, fake), `agent.py` (Claude Agent SDK harness, MCP tools, budget hook), `evaluator.py`, `recorder.py`, `snapshots.py`, `emulator.py` (profiles and mock services), `api.py` (REST), `cli.py`, `eks.py` (EKS Job base and Android host), `workload.py` and `workload_agent.py` (build/run Pod and its in-Pod agent), `registry.py` (session registry, sealer, lease), `kube.py` (EKS token and kubeconfig without the AWS CLI), `runtime_app.py` (AgentCore Runtime entry point), `android.py`, `android_setup.py`, `skills.py`, `github.py`, `models.py`, `config.py`.
- `device_agent/`: the ADB HTTP service (`app.py`), the Gradle builder sidecar (`builder.py`), and the Dockerfiles for the device agent, the builder and the workload image.
- `runtime/`: the Runtime container image and its payload reference.
- `infra/terraform/`: `storage`, `foundation`, `platform`, `runtime`. `infra/build_images.py` builds and scans the images and writes `.env.eks`. `infra/verify_eks_security.py` audits a live deployment.
- `examples/`: `quickstart.py` (sandbox and mock payment API), `workload_demo.py` and `java-service-sample/`, `runtime_workload_demo.py`, `android_quickstart.py`, `eks_demo.py` and `android-sample/`, `bring_your_own_agent.py`, `profiles/`, `criteria/`.
- `tests/`: 126 regression tests that run without AWS.
- `docs/`: architecture, the two verification reports with evidence, and `legacy/` for the earlier EC2 and CloudFormation path (with `scripts/legacy/` and `infra/cfn/`).

## 8. Limits and known gaps

Measured behaviour:

- Runtime invocation, Pod start and build times in the reports are single-run measurements, not guarantees.
- Verified in us-east-1 only. The Seoul (ap-northeast-2) prerequisites were checked against the AWS documentation and the account on 2026-09-14:

| Prerequisite | Seoul | How checked |
|---|---|---|
| AgentCore Runtime (microVM), Code Interpreter | Available | Supported Regions table; control plane answers in the region |
| AgentCore Runtime Instances | Not available (nine regions, Seoul not among them) | Supported Regions table, GA announcement |
| PrivateLink `com.amazonaws.ap-northeast-2.bedrock-agentcore` plus the ten other endpoints the runtime root creates | Available | `aws ec2 describe-vpc-endpoint-services` |
| `m8i.2xlarge` (nested virtualization), `r7i.2xlarge`, `m6i.large` | Offered | `aws ec2 describe-instance-type-offerings` |
| EKS 1.35 | Supported | `aws eks describe-cluster-versions` |
| Claude Opus 5 and Sonnet 5 | Only through the `global.` cross-region inference profile; there is no `apac.` profile for Claude 5 | `aws bedrock list-inference-profiles` |

  To deploy in Seoul set `region = "ap-northeast-2"` in every root, set `CWE_AGENT_MODEL` and `CWE_JUDGE_MODEL` to `global.anthropic.claude-opus-5`, and add `global.anthropic.claude-opus-5*` to `bedrock_model_ids` in the foundation root so the operator policy allows it. A `global.` profile routes inference to any commercial region, so confirm that is acceptable for the code being sent to the model. Nothing else in the stack is region specific; the end-to-end run itself has not been repeated there.
- The read-only root filesystem default was added after the 2026-09-14 run and has unit coverage but no live run yet; the first workload session on a new toolchain image is where it would show.

What a production platform would add:

- **Tenancy**: one namespace and one operator role. Per-user or per-team isolation needs a namespace and role per tenant, mapped from AgentCore Identity claims.
- **Persistence**: a workload Pod's workspace and Gradle or Maven caches live in `emptyDir` and disappear with the Pod. Reattach keeps them; `close`, the Job deadline and `cwe reap` discard them. Persistent volumes, a remote build cache or a pre-warmed image would make repeat builds fast.
- **Repository access**: there is no built-in path for handing a Git credential to the Pod. Code arrives by `sync_workspace_to_workload` from the sandbox or by `git clone` with a token the caller injects.
- **Private dependencies**: Pod egress is public HTTPS only. An internal Nexus or Artifactory needs an explicit network policy rule.
- **Scale**: no autoscaler. `build_desired_size` and `android_desired_size` fix the capacity.
- **Long invocations**: one Runtime invocation has a request limit; run long builds with `remote start` and poll `remote logs`.
- **Agent choice**: the built-in loop is the Claude Agent SDK on Bedrock. The tool layer is an MCP server and can serve another agent; an adapter for a different CLI or framework is not included.
- **Emulator image**: `deploy.sh --stage images --mirror-emulator` copies Google's public emulator image into ECR under an immutable tag; without `CWE_ANDROID_EMULATOR_IMAGE` the code falls back to the public image's mutable `latest` tag.
- **Legacy path**: warm AMI baking and pre-booted emulator pools from the EC2 path were not ported; `cwe android-pool`, `infra/bake_ami.py` and `scripts/build_emulator_image.sh` belong to that path.

## 9. Clean up

```bash
cwe reap --apply --max-age-hours 0
./scripts/cleanup.sh          # plan
./scripts/cleanup.sh --apply  # destroy runtime (if configured), then platform, then foundation
```

A VPC-mode Runtime leaves service-managed network interfaces behind for a while after deletion; if destroying its security group stalls, wait for the interfaces to disappear and re-run.

Deleting the platform namespace removes Jobs, Pods and Secrets; destroying the foundation removes the cluster, nodes, IAM, KMS key (after its deletion window), ECR and the Code Interpreter. ECR images are deleted with their repositories. The recording bucket and the storage state are kept by a separate state and `prevent_destroy`; remove them only deliberately, after checking versioning and retention requirements. Existing CloudFormation stacks from the legacy path are not touched.

## 10. Sharing the repository

A working tree carries live deployment detail: Terraform state and plan files hold your account id, resource ids and every variable value in cleartext, and `.env` files hold your environment. `.gitignore` excludes all of them, so a Git-based handoff is safe, but a `tar`, `zip` or `rsync` of the directory is not. Package from Git:

```bash
git ls-files            # confirm no tfstate, tfplan, tfvars, .env, .cwe_data or issues/
git archive --format=tar.gz -o /tmp/platform.tar.gz HEAD
```
