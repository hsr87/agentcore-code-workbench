# Verification: full deployment and run in Seoul (ap-northeast-2)

What was run on real AWS on 2026-09-14 (UTC) in ap-northeast-2, from an empty region to the same end-to-end proof as
us-east-1: workload Pod build and run, agent fix, Android emulator, AgentCore Runtime in VPC mode with PrivateLink, and
reattach after a real microVM swap. Account identifiers are excluded; raw logs and reports are in
[evidence/seoul/](evidence/seoul/).

## Deployment under test

Fresh deployment with the four Terraform roots, project name `cwe-icn`, in a separate Terraform workspace.

- EKS 1.35 in the region's default VPC (two public subnets in 2a and 2b), API endpoint public to one fixed CIDR plus private.
- Node groups: `system` m6i.large, `android` m8i.2xlarge with nested virtualization, `build` r7i.2xlarge with a 300 GiB volume; one node each.
- Custom Code Interpreter `cwe_icn_public` (PUBLIC network mode).
- Platform stage with the KVM device plugin, RBAC, quota and the three network policies; the KVM column showed `1` on the Android node.
- Images built locally and pushed to the region's ECR: device agent, Android builder, workload agent (Temurin 17 base), Runtime (arm64), and the mirrored Google emulator image under an immutable tag. ECR scan: device agent and builder no findings, workload agent 2 MEDIUM 1 LOW, no CRITICAL.
- Runtime root with `private_access = "endpoints"`: two new private subnets (172.31.96.0/24, 172.31.97.0/24), 9 interface endpoints plus the S3 and DynamoDB gateway endpoints, DynamoDB registry with KMS key, execution role with an EKS access entry, `idle_runtime_session_timeout = 300` to force a microVM swap quickly.
- Models: `CWE_AGENT_MODEL` and `CWE_JUDGE_MODEL` set to `global.anthropic.claude-opus-5`, the only Claude 5 inference profile the region offers; `bedrock_model_ids` widened with `global.anthropic.claude-opus-5*`.

Stage timings: storage 1 min; foundation 8 min for the cluster plus about 1.5 min per node group; platform 10 s; Runtime root 4.5 min for the agent runtime plus about 1 min for the endpoints.

## Results

| Step | Result | Evidence |
|---|---|---|
| Workload demo (laptop, port-forward): sandbox 2.3 s, Pod ready 24.7 s reporting 8 CPU / 61.8 GiB / 293.9 GiB, sync 23 files, `./gradlew test installDist` exit 0 in 20.9 s, `/health` and `/orders/1001` both 200 | PASSED | [workload-demo-20260914T144602Z.json](evidence/seoul/workload-demo-20260914T144602Z.json) |
| Workload demo with agent: same setup, seeded `/health` bug fixed by the agent in 7 executions and 13 turns for an estimated $0.10 (model only), harness re-ran the tests (exit 0) and probed `/health` (200) itself | PASSED | [workload-demo-20260914T144722Z.json](evidence/seoul/workload-demo-20260914T144722Z.json) |
| Android quickstart: emulator booted on the KVM node, ADB device bound to the session, UI dump of Settings, Android 11, two screenshots in S3, evaluation 0.82 with two rules passing and the LLM judge scoring the scripted flow 0.45 | PASSED (score 0.82, threshold 0.7) | [android-quickstart.log](evidence/seoul/android-quickstart.log) |
| Runtime demo through `InvokeAgentRuntime`: sandbox exec via PrivateLink (microVM reports 2 vCPU, 7 GiB, 9.7 GiB disk), workload Pod started from the Runtime and reached by Pod IP, workspace synced, 420 s idle, then `status` served by a different Runtime process with the same session and Pod, workspace file intact, `close` clean | PASSED | [runtime-demo.log](evidence/seoul/runtime-demo.log) |
| Live security audit with the workload Pod present: 22 checks, all true, including read-only root filesystem, token from Secret only, and instance metadata unreachable from inside the Pod | PASSED | [security-report.json](evidence/seoul/security-report.json) |

The first workload run of the day failed at the sync step and is kept as [workload-demo-20260914T144236Z.json](evidence/seoul/workload-demo-20260914T144236Z.json); it is the reproduction of the presigned URL defect below.

## Defects found by the fresh deployment, all fixed in this repository

Every one of these was invisible in us-east-1, where the deployment had grown incrementally and the global S3 and Mantle endpoints coincide with the region.

1. **Foundation would not plan on a fresh account.** The `for_each` of the extra operator access entries subtracted the Terraform-created operator role's ARN, which is unknown until apply. It now subtracts only the admin role.
2. **CoreDNS never became healthy.** With the VPC CNI in strict enforcement from the start, CoreDNS Pods were default-deny (no API server, no upstream DNS, no kubelet probe) until the platform stage created the `cwe-coredns` policy, and the `coredns` addon timed out after 20 minutes. Enforcement mode is now the `network_policy_enforcing_mode` variable, `standard` for cluster creation and switched to `strict` after the platform apply (GUIDE 3.3). Applying the platform stage made CoreDNS recover within a minute.
3. **Workspace sync failed with `SignatureDoesNotMatch`.** The S3 client presigned URLs on the global virtual-host endpoint with a regional signature scope. The store now pins SigV4 and virtual-host addressing so the URL names the bucket's regional endpoint.
4. **The LLM judge could not connect.** There is no `bedrock-mantle` endpoint in ap-northeast-2. The judge now probes the Mantle hostname and falls back to the `bedrock-runtime` endpoint, which serves the same Messages API.
5. **The first Runtime invocation returned 500.** The new lease code used the DynamoDB reserved word `record` in an `UpdateExpression`; the registry write failed and the session was closed as designed. The expression now uses `ExpressionAttributeNames`, and the test double rejects bare reserved words.

Two observations that are not defects: the Claude Agent SDK prints "Sonnet 4.5 not available, using Claude 3.5 Sonnet" for its auxiliary model in this region (set `ANTHROPIC_DEFAULT_SONNET_MODEL` to a `global.` profile to silence it; the main model was Opus 5 as configured), and the `global.` inference profile routes requests to any commercial region, which matters where data must stay in Seoul.

## What this does and does not show

It shows that nothing in the stack is region specific once the model ids are set, and that a clean account can reach the verified state in about an hour by following GUIDE.md. Times are single-run measurements. The Android evaluation score reflects the scripted quick start, not an agent run. The Runtime idle timeout was 300 s for the test; raise it for real use.

## Cleanup

Seoul resources were left running after the run (cluster, three nodes, Runtime endpoints); tear them down with `scripts/cleanup.sh --apply` in the `seoul` workspace of each root, `runtime` first.
