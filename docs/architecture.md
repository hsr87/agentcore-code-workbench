# Architecture

## Execution layer

`SessionManager → DevSession → Sandbox` is the centre of code execution. Profile provisioning, run creation, command, code and file execution, recording, evaluation and shutdown all pass through it. Code execution always uses AgentCore Code Interpreter; EKS is used only for the Android device lab.

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

## Nodes and KVM

Ordinary system Pods run on a separate system node group. Android nodes are isolated with the label `cwe/workload=android` and the taint `cwe/android=true:NoSchedule`. The EKS launch template sets `cpu_options.nested_virtualization=enabled`, and the AL2023 boot sequence loads `kvm_intel`.

The KVM device plugin discovers `/dev/kvm` and advertises one `devic.es/kvm` slot per node. A node without the device advertises no capacity, so emulator Pods are never scheduled onto it. The default node type is `m8i.2xlarge`, sized for the build container's memory. One emulator Pod is placed per node, so `count=2` requires two ready Android nodes.

Only the device plugin DaemonSet is privileged. The emulator, device agent and builder containers are unprivileged, drop all capabilities, disable privilege escalation and use the default seccomp profile. The namespace enforces the `baseline` Pod Security Standard, which permits the emulator image to start as root but blocks privileged mode, host paths and host networking. Nodes require IMDSv2 with hop limit 1. Container isolation is weaker than microVM isolation and is not a multi-tenant boundary against hostile code.

## Connectivity and permissions

Local access uses `kubectl port-forward` through the Kubernetes API, which requires EKS kubeconfig authentication and namespace RBAC. The tunnel binds `127.0.0.1`. No Service, Ingress or load balancer is created.

`CWE_EKS_ACCESS=pod` exists for an approved in-cluster orchestrator. The network policy admits traffic to port 8080 only from Pods labelled `cwe/role=orchestrator` in namespaces labelled `app.kubernetes.io/part-of=cwe`. This Terraform does not create that orchestrator Deployment, and it does not configure an external AgentCore Runtime to call private Pod IPs directly.

The VPC CNI runs with strict network policy enforcement. Device Pods may reach DNS and public HTTPS only, with RFC1918 and link-local destinations excluded, which also blocks instance metadata. Private package repositories or S3 VPC endpoints require an explicit approved rule. CoreDNS has its own policy.

The `cwe-operators` group may create, read and delete Jobs, read Pods and their logs, create port-forwards, and create Secrets in the lab namespace. It cannot read Secrets directly, but creating a Job is enough to mount any Secret in that namespace, so an operator is a trusted role. A shared operator role does not isolate one user's sessions from another's.

## Terraform state

1. `storage`: the long-lived recording bucket, with `prevent_destroy`, versioning, public access block and AES256 encryption.
2. `foundation`: AgentCore, IAM, ECR, EKS, managed node groups and the CNI. It reads the bucket as a data source.
3. `platform`: namespace, service account, RBAC, quota, KVM plugin and network policies, installed after the cluster is reachable.

Create in the order storage → foundation → platform, and destroy compute in the order platform → foundation. Local state is the example default; shared operation should configure an encrypted, locking remote backend in each root.

## Interfaces relied on

- EC2 nested virtualization: `https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html`
- EKS managed node launch templates: `https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html`
- The `aws_launch_template` and `aws_bedrockagentcore_code_interpreter` resource schemas in the AWS provider
- EKS VPC CNI network policy: `https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html`
- The device configuration format of `https://github.com/squat/generic-device-plugin`

A valid launch template and Terraform plan do not by themselves guarantee that an emulator boots. On a first deployment, confirm node KVM capacity, image boot, SDK builds, and Job termination with Secret garbage collection.
