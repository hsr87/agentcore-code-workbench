# Architecture

## Execution layer

`SessionManager → DevSession → Sandbox` is the centre of code execution. Profile provisioning, run creation, command, code and file execution, recording, evaluation and shutdown all pass through it. Lightweight code execution uses AgentCore Code Interpreter; EKS runs what the microVM cannot hold: the Android device lab and the build/run workload Pods.

`ExecResult` normalizes SDK results. `Recorder` stores events and written files. `RunRecord` keeps execution counts, tokens, an estimated cost, a trace id and verification results. The harness path is unchanged: tool output is summarized, `RunBudget` gates execution, and `verify_command` is run by the harness itself.

An evaluation score is a weighted average. A run passes when the score clears the threshold and every rule item with weight 1 or higher passes. `open_recorded` re-scores a closed session from stored events and session metadata alone.

## EKS device lab

`DevSession.start_android(profile)` selects a backend from `CWE_ANDROID_BACKEND`. The default is `EKSEmulatorHost`; `ec2` selects the legacy `EC2EmulatorHost`. Both expose `start(profile, session_id) → AndroidDevice` and `stop()`.

```text
SessionManager / DevSession
  └─ EKSEmulatorHost (explicit kube context or in-cluster credentials)
       ├─ Job (device 0) + Job-owned Secret
       │    └─ Pod: emulator + device agent + SDK builder + emptyDir
       ├─ Job (device 1) + Job-owned Secret
       │    └─ Pod: emulator + device agent + SDK builder + emptyDir
       └─ ... up to count
```

- Jobs use `restartPolicy=Never`, `backoffLimit=0`, `activeDeadlineSeconds=job_timeout_seconds` and `ttlSecondsAfterFinished=300`. A failed emulator is never restarted underneath a session that is already connected to it.
- The authentication token is generated per device, stored only in a Kubernetes Secret, and injected into that one device agent. The Secret is owned by the Job and is garbage collected with it. If any device fails during startup, every Job created so far is cleaned up.
- One emulator per Pod means ADB ports never collide; the agent talks to `127.0.0.1:5555`. `DeviceGroup.for_device(i)` returns the client for that Pod, and default operations use device zero.
- For a build, the device agent extracts the source into the shared `emptyDir` and passes only a build id, Gradle task names and a timeout to the builder on `127.0.0.1:9090`. The builder receives no token, no cluster credentials, no Docker socket and no KVM device.
- Build outputs and APK paths are per Pod. Other devices either build separately or install a shared APK URL. The Gradle cache is reused within the same Pod only.

## Workload Pods

`DevSession.start_workload(profile)` creates one Job from a `WorkloadProfile` through `EKSWorkloadHost` (`cwe/workload.py`). The container runs as uid 1000 with all capabilities dropped and, by default, a read-only root filesystem: the workspace, the Gradle/Maven cache, the logs and `/tmp` are `emptyDir` volumes (`read_only_root=False` relaxes this for toolchains that write elsewhere in the image). `EKSJobHost` in `cwe/eks.py` is the shared base for the Android and workload hosts: kubectl plumbing, Job plus owned Secret, waiting for a Ready Pod, port-forward, teardown, reaping, and `describe`/`attach` for the registry.

```text
DevSession
  └─ EKSWorkloadHost
       └─ Job (one per session) + Job-owned Secret (agent token)
            └─ Pod: your toolchain image + workload_agent.py on :8080
                 /opt/cwe/work  (emptyDir sized by ephemeral_storage)
                 /opt/cwe/cache (Gradle / Maven caches, per Pod)
```

- The Pod is unprivileged, non-root, no service account token, no host path. It is scheduled on the `build` node group (`cwe/workload=build`, taint `cwe/build`), which needs no KVM and so any instance family, including in regions without nested-virtualization instance types.
- The agent inside the Pod exposes `exec` (synchronous, with timeout and output cap), `start`/`stop`/`logs`/`procs` (background processes such as the service under test), `files`/`file`, `fetch` (HTTPS-only download and safe extraction of the workspace archive) and `probe` (an HTTP request to `127.0.0.1:<port>` inside the Pod, because the network policy only admits port 8080 from outside).
- Every call is recorded as an `ExecKind.REMOTE` event, so builds and service checks on the Pod appear in the same transcript, replay and evaluation as sandbox commands.
- Code moves sandbox → Pod through `sync_workspace_to_workload` (snapshot to S3, presigned fetch). For a large repository, clone it in the Pod with `remote_shell` and sync only what the agent changed.

## AgentCore Runtime and sticky sessions

`cwe/runtime_app.py` maps `runtimeSessionId` to a `DevSession`. The Runtime keeps a `runtimeSessionId` on one microVM, but releases it after the idle timeout and replaces it after the maximum lifetime, and it offers no shutdown callback that could stop the sandbox or Pods cleanly. The session registry (`cwe/registry.py`) is the durable half of the mapping:

1. On create, and after a workload starts, the Runtime writes `{runtimeSessionId → session_id, sandbox_session_id, hosts[...]}`. Host records carry the Job name and the agent token; with `CWE_REGISTRY_KMS_KEY_ID` the whole record is KMS-encrypted with the runtime session id as encryption context, so a record copied under another id does not open and a principal without the key cannot forge one. Every read also checks that the record was written for the requesting runtime session, and `attach` validates the session id before touching the store. The recordings-store registry on S3 requires the key, because sandbox code could otherwise reach the same prefix if `sandbox_recordings_access` is enabled.
2. On exit the Runtime **detaches**: HTTP clients and port-forwards are closed, nothing is stopped.
3. A new microVM receiving the same `runtimeSessionId` reads the record, adopts the Code Interpreter session (`AgentCoreSandbox.attach`, after checking it is `READY`), and reconnects to every Job that still has a Running Pod (`EKSWorkloadHost.attach`, `EKSEmulatorHost.attach`). If the sandbox is gone the record is dropped and a fresh session starts; Job deadlines reclaim the orphaned Pods.
4. `close` stops everything and deletes the record. Records expire after `CWE_SESSION_REGISTRY_TTL_SECONDS`.
5. With the DynamoDB registry every invocation holds a **lease** on the runtime session item (`lease_owner`, `lease_until`, renewed every 20 s for 120 s). A second process asking for the same `runtimeSessionId` waits, then fails with "busy" rather than creating its own sandbox and Pod. Registry writes are conditioned on still owning the lease, and a lost lease turns further execution into an error. The record read under the lease is authoritative: a process whose cached session no longer matches it detaches that session and follows the record. If the record cannot be written for a newly created session, that session is closed and the call fails, so a Pod is never left running without a durable pointer to it. The recordings-store registry has no conditional write and therefore no lease; it is for a single Runtime process or local use.

The Runtime is deployed in VPC mode (`infra/terraform/runtime`) so it reaches Pod IPs directly (`CWE_EKS_ACCESS=pod`): its security group may send to port 8080 in the VPC, the cluster security group admits it on that port and on 443 for the private Kubernetes API endpoint, and the platform network policy adds the Runtime subnet CIDRs as `ipBlock` sources. The Runtime's ENIs live in private subnets; `private_access` picks a NAT gateway or PrivateLink endpoints (Bedrock, AgentCore, STS, KMS, Logs, X-Ray, ECR, EKS, plus S3 and DynamoDB gateway endpoints). In VPC mode the container image is pulled through those ENIs, which is why the ECR endpoints are part of the list.

Three invariants protect the Pod count and the build count: calls for one runtime session are serialized inside a process and by the lease across processes; `start_workload` is serialized per session and refuses a second Pod, so a client that retries a long `workload` invocation does not create duplicates; and a session closed while its Pod was still starting stops that Pod instead of leaving it behind. `remote exec` carries a `request_id`: the client retries a dropped connection once with the same id, and the workload agent joins the command that is already running or returns its stored result instead of running the build a second time (`deduplicated: true` in the result). `status` reports a per-process marker so a reattach after a microVM swap can be told apart from a request served by the same process. kubectl inside the Runtime authenticates with `cwe eks-token`, a presigned STS `GetCallerIdentity` carrying the cluster name, so the image needs no AWS CLI; `cwe.kube.ensure_kubeconfig` writes the kubeconfig from `CWE_EKS_CLUSTER_NAME`. The execution role receives the operator policy and an EKS access entry in the `cwe-operators` group.

## Nodes and KVM

Ordinary system Pods run on a separate system node group. Android nodes are isolated with the label `cwe/workload=android` and the taint `cwe/android=true:NoSchedule`. The EKS launch template sets `cpu_options.nested_virtualization=enabled`, and the AL2023 boot sequence loads `kvm_intel`.

The KVM device plugin discovers `/dev/kvm` and advertises one `devic.es/kvm` slot per node. A node without the device advertises no capacity, so emulator Pods are never scheduled onto it. The default node type is `m8i.2xlarge`, sized for the build container's memory. One emulator Pod is placed per node, so `count=2` requires two ready Android nodes.

Only the device plugin DaemonSet is privileged. The emulator, device agent and builder containers are unprivileged, drop all capabilities, disable privilege escalation and use the default seccomp profile. The namespace enforces the `baseline` Pod Security Standard, which permits the emulator image to start as root but blocks privileged mode, host paths and host networking. Nodes require IMDSv2 with hop limit 1. Container isolation is weaker than microVM isolation and is not a multi-tenant boundary against hostile code.

## Connectivity and permissions

Local access uses `kubectl port-forward` through the Kubernetes API, which requires EKS kubeconfig authentication and namespace RBAC. The tunnel binds `127.0.0.1`. No Service, Ingress or load balancer is created.

`CWE_EKS_ACCESS=pod` exists for an approved in-cluster orchestrator. The network policy admits traffic to port 8080 only from Pods labelled `cwe/role=orchestrator` in namespaces labelled `app.kubernetes.io/part-of=cwe`. The `platform` root does not create that orchestrator Deployment. The `runtime` root deploys AgentCore Runtime in VPC mode and adds the Runtime security group to the `orchestrator_cidrs` ingress rule, which is how the Runtime calls private Pod IPs directly.

The VPC CNI runs with strict network policy enforcement. Device Pods may reach DNS and public HTTPS only, with RFC1918 and link-local destinations excluded, which also blocks instance metadata. Private package repositories or S3 VPC endpoints require an explicit approved rule. CoreDNS has its own policy.

The `cwe-operators` group may create, read and delete Jobs, read Pods and their logs, create port-forwards, and create Secrets in the lab namespace. It cannot read Secrets directly, but creating a Job is enough to mount any Secret in that namespace, so an operator is a trusted role. A shared operator role does not isolate one user's sessions from another's.

## Terraform state

1. `storage`: the long-lived recording bucket, with `prevent_destroy`, versioning, public access block and AES256 encryption.
2. `foundation`: AgentCore, IAM, ECR, EKS, managed node groups and the CNI. It reads the bucket as a data source.
3. `platform`: namespace, service account, RBAC, quota, KVM plugin and network policies, installed after the cluster is reachable. `orchestrator_cidrs` admits the Runtime subnets.
4. `runtime`: the AgentCore Runtime (VPC mode), its security group and the cluster security group rule, execution role with the operator policy, EKS access entry, the session registry table and KMS key.

Create in the order storage → foundation → platform → runtime, then re-apply platform with the Runtime subnet CIDRs. Destroy in the order runtime → platform → foundation. Local state is the example default; shared operation should configure an encrypted, locking remote backend in each root.

## Interfaces relied on

- EC2 nested virtualization: `https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html`
- EKS managed node launch templates: `https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html`
- The `aws_launch_template` and `aws_bedrockagentcore_code_interpreter` resource schemas in the AWS provider
- EKS VPC CNI network policy: `https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html`
- The device configuration format of `https://github.com/squat/generic-device-plugin`

A valid launch template and Terraform plan do not by themselves guarantee that an emulator boots. On a first deployment, confirm node KVM capacity, image boot, SDK builds, and Job termination with Secret garbage collection.
