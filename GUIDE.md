# Deployment and operations guide

End-to-end instructions for deploying the platform on your own AWS account, running a session, operating it, and tearing it down. See [README.md](README.md) for what the platform is and why each part exists, and [docs/architecture.md](docs/architecture.md) for the design.

A first deployment takes about an hour, most of it waiting for EKS. Plan for these stages:

| Stage | What happens | Typical wait |
|---|---|---|
| Local setup and offline tests | Install the package, run the regression suite | 5 min |
| `storage` | Recording bucket | 1 min |
| `foundation` | Code Interpreter, IAM, ECR, EKS cluster and two node groups | 15–25 min |
| `platform` | Namespace, RBAC, KVM plugin, network policies | 2 min |
| `images` | Build and push two sidecar images | 5–10 min |
| First Android session | Emulator image pull and boot, SDK download and Gradle build | 3–5 min |

The EKS control plane and any ready nodes are billed while idle. Tear down with §6 when you are done.

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.12 | Package metadata allows 3.11+, but development, tests and containers target 3.12. |
| `uv` (optional) | The commands below use `uv`; `python -m venv .venv` and `pip install -e '.[dev]'` are equivalent. |
| Terraform 1.5+ | The AWS provider is pinned to 6.x (6.64 or later); lock files are committed. |
| AWS CLI, kubectl | `kubectl` must be able to reach the EKS API from wherever you run it (see §2). |
| Finch or Docker | Builds the two sidecar images for `linux/amd64`. Set `CWE_CONTAINER_CLI=docker` to use Docker. |
| AWS permissions | Create EKS, IAM, VPC resources, ECR, S3, KMS and AgentCore Code Interpreter. |
| Bedrock model access | `us.anthropic.claude-opus-5` (agent) and `anthropic.claude-opus-5` (judge) must be usable in the region. Check **Bedrock → Model access** in the console if a first invocation returns `AccessDeniedException`. |
| An existing VPC | Two or more subnets in different Availability Zones. Private subnets need NAT; public subnets need `MapPublicIpOnLaunch` for node egress. This Terraform does not create a VPC, NAT, VPC endpoints or a VPN. Private subnets are the better choice for anything beyond a lab. |

Nodes need outbound HTTPS to ECR, S3, STS and to the public image, Gradle and Android SDK repositories.

Install the Python package first and confirm the offline test suite passes. Nothing here touches AWS:

```bash
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install -e '.[dev]'
python -m pytest -q          # expect: 90 passed
```

## 2. EKS API access

The cluster endpoint is private-only by default, so Terraform for the `platform` stage and every `kubectl` call must run somewhere with VPC connectivity. To work from a laptop without a VPN, set `endpoint_public_access = true` and list your own fixed egress CIDR in `endpoint_public_access_cidrs`. `0.0.0.0/0` is rejected. Find your egress address with `curl https://checkip.amazonaws.com`.

This setting controls access to the Kubernetes API only; it never exposes the device agent. If your address changes later, `kubectl` fails with `Unable to connect to the server: ... i/o timeout`; update the CIDR list and re-apply the foundation stage.

## 3. Deploy

Terraform is split into three roots with separate state. Copy each `terraform.tfvars.example` to `terraform.tfvars`, fill in real values, and apply in order. `scripts/deploy.sh` runs `init` and `plan` for a stage and applies only with `--apply`.

| Root | Creates |
|---|---|
| `infra/terraform/storage` | Recording S3 bucket: versioning, encryption, public access block, TLS-only policy, lifecycle, `prevent_destroy`. |
| `infra/terraform/foundation` | AgentCore Code Interpreter, IAM roles and policies, ECR repositories, KMS key, EKS cluster, system and Android node groups, VPC CNI with network policy support. |
| `infra/terraform/platform` | Namespace, service account, RBAC, resource quota, KVM device plugin, network policies. |

### 3.1 Storage

```bash
cp infra/terraform/storage/terraform.tfvars.example infra/terraform/storage/terraform.tfvars
./scripts/deploy.sh --stage storage            # plan only
./scripts/deploy.sh --stage storage --apply
```

Keep `region`, `project_name` and `recordings_bucket_name` consistent between `storage` and `foundation`. `recordings_prefix` in the foundation stage confines both the sandbox execution role and the operator role to one key prefix of the bucket; it must match the prefix in `CWE_STORAGE_URI`.

### 3.2 Foundation

```bash
cp infra/terraform/foundation/terraform.tfvars.example infra/terraform/foundation/terraform.tfvars
```

Values to fill in:

- `vpc_id`, `subnet_ids`: an existing VPC and at least two subnets in different AZs.
- `cluster_version`: a Kubernetes version EKS currently supports in your region, for example `1.35`. `aws eks describe-cluster-versions --query 'clusterVersions[].clusterVersion'` lists them.
- `cluster_admin_role_arn`: the IAM **role** you will use for the platform stage and for `kubectl`. It must be a role ARN, not the STS session ARN that `aws sts get-caller-identity` prints. Convert `arn:aws:sts::123456789012:assumed-role/MyRole/session` to `arn:aws:iam::123456789012:role/MyRole`. For IAM Identity Center roles the path matters: `arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/<region>/AWSReservedSSO_<PermissionSet>_<id>`.
- `operator_role_arns`: optional extra roles allowed to run sessions. Terraform always creates its own `<project>-session-operator` role as well.
- `endpoint_public_access`, `endpoint_public_access_cidrs`: see §2.
- `android_desired_size`: the number of concurrent devices you want ready; one node serves one emulator.

```bash
./scripts/deploy.sh --stage foundation
./scripts/deploy.sh --stage foundation --apply
```

Applying this stage creates a KMS key for envelope encryption of Kubernetes Secrets, which is where per-device tokens live. Terraform also creates the `operator_role_arn` for running sessions, attaches the matching IAM policy, and maps it to the `cwe-operators` Kubernetes group. Only `cluster_admin_role_arn` may assume it.

Then point kubectl at the cluster:

```bash
terraform -chdir=infra/terraform/foundation output cluster_name
aws eks update-kubeconfig --region <region> --name <cluster-name> --role-arn <cluster-admin-role-arn>
kubectl config current-context
kubectl get nodes                         # two nodes, both Ready
```

The default context name is the cluster ARN. If you pass `--alias`, use that alias for the platform `kube_context` and for `CWE_EKS_CONTEXT`. If you wrote the kubeconfig somewhere other than `~/.kube/config`, note the path; both the platform stage and `.env.eks` need it.

### 3.3 Platform

```bash
cp infra/terraform/platform/terraform.tfvars.example infra/terraform/platform/terraform.tfvars
```

Values to fill in:

- `kube_context`: the context name from §3.2.
- `kubeconfig_path`: only if your kubeconfig is not `~/.kube/config`.
- `kvm_plugin_image`: the KVM device plugin, pinned by digest. This DaemonSet is the one privileged workload in the cluster, so review the image and pin exactly what you reviewed. A mutable tag such as `:latest` is rejected. To get the digest of the current upstream release:

```bash
finch pull squat/generic-device-plugin:latest          # or: docker pull
finch image inspect squat/generic-device-plugin:latest --format '{{index .RepoDigests 0}}'
```

The verified deployment used `squat/generic-device-plugin@sha256:dc192e164c69b03f156765793a1be62ca437709ae477b27ca7d8f3dcf5021576`.

```bash
./scripts/deploy.sh --stage platform
./scripts/deploy.sh --stage platform --apply
kubectl -n kube-system rollout status daemonset/cwe-kvm
kubectl get nodes -l cwe/workload=android \
  -o 'custom-columns=NAME:.metadata.name,KVM:.status.allocatable.devic\.es/kvm'
```

The last command must show `1` in the KVM column for every Android node. If it shows `<none>`, check `kubectl -n kube-system logs daemonset/cwe-kvm` and `/dev/kvm` on the node, and confirm nested virtualization is set on the current launch template version.

### 3.4 Sidecar images and environment

```bash
./scripts/deploy.sh --stage images --tag v1
set -a; source .env.eks; set +a
```

This builds `device_agent/Dockerfile` and `device_agent/Dockerfile.builder` for `linux/amd64`, pushes both to ECR, and writes `.env.eks` with the interpreter id, bucket, cluster context and image references. ECR tags are immutable, so use a new tag for every change.

Two values are not generated and may need to be added by hand to `.env.eks`; the script preserves any extra keys on later runs:

- `KUBECONFIG=<path>` if your kubeconfig is not `~/.kube/config`.
- `CWE_EKS_NAMESPACE=<name>` if you changed the namespace in the platform stage.
- `CWE_API_KEY=<random>` if you plan to run the REST API.

Both Dockerfiles pin their base image by digest and every downloaded tool by URL and SHA-256: the device agent takes `adb` from Google's platform-tools release on Amazon Linux 2023 minimal (pulled from ECR Public, which may need `aws ecr-public get-login-password | finch login` first), and the builder installs the Android command-line tools on `eclipse-temurin:17-jdk`. The builder pre-installs the SDK components the sample app needs (`SDK_PACKAGES` in `Dockerfile.builder`); anything else a project needs is downloaded during its first Gradle build, so add your own versions there to make repeat builds faster. The Gradle cache lives in the Pod and is not shared between Pods.

After the push the script waits for the ECR scan and refuses to write `.env.eks` if either sidecar has a CRITICAL finding (`--allow-critical` overrides). Base images accumulate published CVEs over time, so rebuild with a new tag on a schedule and refresh the digests in the Dockerfiles when you do.

Mirror the emulator image as well, so nodes pull it from ECR with the node role under an immutable tag instead of from Google's registry by a mutable `latest` tag:

```bash
./scripts/deploy.sh --stage images --mirror-emulator      # pulls linux/amd64, pushes <repo>:30-google-x64-<date>
set -a; source .env.eks; set +a                           # now also contains CWE_ANDROID_EMULATOR_IMAGE
```

The two flags can be combined in one run. Images for other API levels are built by your own pipeline and pushed to the same repository, then selected with `AndroidEmulatorProfile.image` or `images`.

### 3.5 Confirm the deployment

Run these before handing the environment to anyone. Each one should complete without an error.

```bash
python examples/quickstart.py                                   # sandbox loop, about a minute; ends with EVAL: ... PASS
python examples/android_quickstart.py                           # boots a device, prints the Android version, deletes the Job
python infra/verify_eks_security.py --env-file .env.eks         # all checks true; run while a session Pod exists for the Pod checks
terraform -chdir=infra/terraform/foundation plan                # No changes
```

`verify_eks_security.py` asserts the security model in README against the live account: endpoint exposure, secret encryption, audit logging, IMDSv2, nested virtualization, node security groups, bucket settings, Pod security context, network policies and instance metadata reachability from the builder.

## 4. Run

```bash
python examples/quickstart.py               # sandbox only: provision, run, snapshot, evaluate, replay
python examples/quickstart.py --agent       # same task delegated to the agent
python examples/android_quickstart.py       # EKS device: boot, screenshot, UI dump, evaluate
python examples/android_quickstart.py --agent
cwe android-setup examples/android-sample   # propose an emulator profile from a Gradle project
CWE_API_KEY=<random> cwe serve              # REST API on 127.0.0.1:8000
```

What to expect: the sandbox quickstart finishes in about a minute and prints the rule and judge scores. The agent variant takes several minutes and a few cents of Bedrock usage; its output includes token usage and the cost estimate recorded on the run. The Android quickstart prints the device agent URL, the Settings UI nodes and the Android version, then deletes the Job. Recordings land under `CWE_STORAGE_URI/<session_id>/`.

From Python:

```python
from cwe.android import AndroidEmulatorProfile
from cwe.session import SessionManager

manager = SessionManager()
session = manager.create()
try:
    session.start_android(AndroidEmulatorProfile())
    session.begin_run("inspect")
    session.screenshot()
    session.end_run()
finally:
    manager.close(session.info.session_id)
```

To exercise the full loop with the restricted session role, including a real Gradle build, instrumented tests, an agent fix and post-hoc scoring:

```bash
python examples/eks_demo.py --env-file .env.eks --agent \
  --operator-role-arn "$(terraform -chdir=infra/terraform/foundation output -raw operator_role_arn)"
```

Temporary AssumeRole credentials are passed to the demo process only and never written to a file. Reports and media land in `.cwe_data/eks-demo/`. Running this under the operator role, rather than your administrator credentials, is what proves the operator IAM policy and namespace RBAC are sufficient.

## 5. Operate

```bash
kubectl -n "$CWE_EKS_NAMESPACE" get jobs,pods -l app.kubernetes.io/name=cwe-android
kubectl -n "$CWE_EKS_NAMESPACE" logs <pod-name> -c emulator      # or -c device-agent, -c builder
cwe reap                                                          # list expired Jobs and stale sandbox sessions
cwe reap --apply                                                  # reclaim them
python infra/verify_eks_security.py --env-file .env.eks           # re-run the deployment security checks
```

`cwe reap` resolves the device backend from the environment, so source the whole `.env.eks`: a partial environment fails with "EKS requires device-agent and builder images".

Capacity: one KVM slot per node. Two concurrent devices need `android_desired_size = 2` in the foundation stage; raising `android_max_size` alone does not add nodes, and no autoscaler is installed. The EKS control plane and any ready nodes cost money while idle.

| Symptom | Check |
|---|---|
| `Unable to connect to the server: ... i/o timeout` | Your current egress IP is not in `endpoint_public_access_cidrs`, or you are outside the VPC with a private-only endpoint (§2) |
| `kubectl ... failed` | `CWE_EKS_CONTEXT`, `KUBECONFIG`, AWS role, EKS access entry, namespace RBAC, API reachability |
| Pod `Pending` | `devic.es/kvm` capacity, node count, requests versus node memory, taints and tolerations |
| `ImagePullBackOff` | ECR image tag, node pull role, NAT or registry reachability |
| Device agent 401 / 403 | Token or `x-cwe-session` mismatch, or a stale tunnel from a previous session |
| Boot timeout | Emulator logs, `/dev/kvm`, whether the image serves ADB on 5555 |
| Gradle failure | SDK and JDK in the builder image, HTTPS reachability of package repositories, `gradlew` present in the source |
| Private repository unreachable | The device network policy allows only DNS and public HTTPS; add the approved private CIDR and port explicitly |
| `DeadlineExceeded` | `job_timeout_seconds` reached; the Pod is terminated and the Job and Secret are reclaimed by TTL |
| `AccessDeniedException` from Bedrock | Model access not enabled in the region, or the operator policy's model list does not include the model id in use |

Expired AWS credentials surface as `401 Unauthorized` or `The security token included in the request is expired`. Refresh the profile or session credentials and confirm with `aws sts get-caller-identity`. Environment variables take precedence over profiles, and a running process does not pick up new ones. If Terraform stopped mid-apply, query the real state and reconcile before the next plan.

## 6. Clean up

```bash
cwe reap --apply --max-age-hours 0
./scripts/cleanup.sh          # plan
./scripts/cleanup.sh --apply  # destroy platform, then foundation
```

Deleting the platform namespace removes Jobs, Pods and Secrets; destroying the foundation removes the cluster, nodes, IAM, KMS key (after its deletion window), ECR and the Code Interpreter. ECR images are deleted with their repositories. **The recording bucket and the storage state are kept** by a separate state and `prevent_destroy`; remove them only deliberately, after checking versioning and retention requirements.

## 7. Sharing this repository

A working tree carries live deployment detail: Terraform state and plan files hold your account id, resource ids and every variable value in cleartext, and `.env` files hold your environment. `.gitignore` excludes all of them, so a Git-based handoff is safe, but a `tar`, `zip` or `rsync` of the directory is not. Package from Git:

```bash
git init && git add . && git commit -m "initial"
git ls-files            # confirm no tfstate, tfplan, tfvars, .env or .cwe_data
git archive --format=tar.gz -o /tmp/platform.tar.gz HEAD
```
