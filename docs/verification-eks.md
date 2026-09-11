# Verification report

This codebase is a sample showing that an agent's Android development loop — build, install, interact, run instrumented tests, record the evidence and score the result — can be run on AgentCore Code Interpreter and EKS, deployed with Terraform. What follows was run on real AWS, first on 2026-09-10 and again on 2026-09-11 after the Terraform was hardened (KMS secret encryption, full control-plane logging, IAM policies narrowed to the Claude models and one bucket prefix, encrypted system node volume, TLS-only bucket policy, default-deny network policy); the scope and its limits are stated explicitly.

## Deployment under test

- Region `us-east-1`, EKS `1.35`, one system node and one dedicated `m8i.2xlarge` Android node.
- Nested virtualization set in the managed node group's launch template; the instance setting and the node's `devic.es/kvm=1` capacity were both confirmed.
- Code execution in a new AgentCore Code Interpreter; the Android device as an EKS Job holding the emulator, device agent and SDK builder.
- Recordings in a dedicated S3 bucket with versioning, encryption, public access blocked and a TLS-only bucket policy. Kubernetes Secrets envelope-encrypted with a customer-managed KMS key.
- The infrastructure administrator only deployed; the demo itself ran under a separate `session-operator` IAM role.

## What was exercised

| Step | Result |
|---|---|
| Code transfer | Local sample written into the AgentCore workspace, handed to the EKS builder as an S3 snapshot |
| KVM and boot | Emulator booted on EKS and accepted an ADB connection |
| App build | Gradle ran in the SDK builder, producing the app and androidTest APKs |
| Install and UI | Both APKs installed; `Count: 0` became `Count: 3` after three taps |
| Video and live view | PNG capture, MP4 recording, single-use viewer token exchanged for a cookie, MJPEG frame received |
| Tests | Espresso `startsAtZero` and `incrementsOnClick` both passed |
| Agent work | A deliberate `count += 2` bug was found and fixed by the agent, then rebuilt, reinstalled and retested |
| Independent check | The harness re-ran the instrumented tests against the corrected source itself |
| Snapshot | The corrected source was restored into a new AgentCore session and its content verified |
| Recording | JSONL, artifacts, and post-hoc scoring of the closed session |

First real run (2026-09-10): boot including image download took **94.4 s**, and the build including SDK installation took **87.3 s**. On the hardened deployment (2026-09-11) the boot took **54.2 s** with the image already cached on the node and the build **82.2 s**. These are single-run measurements, not a performance guarantee.

## Result

**Integration verification passed on both runs.** On 2026-09-11 the whole demo took 302 s under the `session-operator` role with the narrowed IAM policy: the agent completed the fix, rebuild and test cycle in 5 executions for an estimated $0.08, independent instrumented tests on the final source passed 2 of 2, snapshot restore succeeded, post-hoc evaluation scored 1.0, and all 3 S3 evidence objects were re-read successfully. The device API returned 401 without a token and 403 with the wrong session header.

Local regression tests: **90 passed**. Terraform `storage`, `foundation` and `platform` all planned to **no changes** against the live account after the 2026-09-11 apply, and `infra/verify_eks_security.py` passed all 21 checks against the running session Pod.

The final 2026-09-11 run used only images from the account's ECR: the emulator mirrored from Google's public image under an immutable tag (same digest as the source), and sidecars rebuilt on digest-pinned Amazon Linux 2023 and Temurin bases with `adb` and the Android command-line tools pinned by checksum. ECR scan-on-push reported **no findings** for either sidecar, down from 6 and 57 critical findings on the previous bases.

- [Portable result JSON](evidence/eks/verification.json): measurements, permission checks and file SHA-256 digests, with account identifiers and tokens excluded
- [Initial screen](evidence/eks/before.png), [after three taps](evidence/eks/after.png)
- [Interaction recording](evidence/eks/interaction.mp4), [live stream frame](evidence/eks/live-frame.jpg)

Session and run identifiers and full agent responses stay in the local report and in the S3 recording.

## Security checks

The deployment checker (`infra/verify_eks_security.py`) asserts, against the live account and a running session Pod:

- The EKS API is not open to the internet and the private endpoint is enabled; control-plane audit logging is on; Kubernetes Secrets are envelope-encrypted with a customer-managed KMS key.
- Every node requires IMDSv2 with hop limit 1, Android nodes have nested virtualization enabled, and no node security group has a world-open ingress rule over IPv4, IPv6 or a prefix list.
- The recordings bucket blocks public access and has versioning and encryption enabled.
- The session Pod disables service account token automounting, uses no host path and no host namespace, and every container is unprivileged, disables privilege escalation and drops all capabilities. The device agent and builder additionally run as non-root; the emulator container runs as root inside its container, which the `baseline` Pod Security Standard permits and which is why the namespace is not `restricted`.
- The builder container holds no device token, and instance metadata is unreachable from it.
- Both the default-deny and the device network policies are present.

Separately confirmed: the session role can create Jobs but cannot read Secrets directly or delete nodes, and the device API returns 401 without a token and 403 with the wrong session header. Memory, Evaluations and CloudWatch query permissions are excluded from the default IAM policy.

This is an operator-boundary sample. An operator with namespace access is a trusted principal — creating a Job is enough to mount any Secret in that namespace — so this is not multi-tenant isolation. The node-level KVM device plugin is privileged and deliberately separate from the session Pod.

## Scope and limits

This is a single-device development and verification loop driven from a local or CI harness against AgentCore Code Interpreter, Bedrock and EKS. It does not cover a long-running AgentCore Runtime deployment, a pool of pre-booted emulators, cluster autoscaling, or multi-device load testing. A snapshot captures AgentCore workspace files, not a running Android VM.

## Reproduce

```bash
set -a; source .env.eks; set +a
python examples/eks_demo.py --env-file .env.eks --agent \
  --operator-role-arn "$(terraform -chdir=infra/terraform/foundation output -raw operator_role_arn)"
python infra/verify_eks_security.py --env-file .env.eks
```

Base infrastructure is retained by both commands. Removing it is a separate, explicit step; see [GUIDE.md](../GUIDE.md).
