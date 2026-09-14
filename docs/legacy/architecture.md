> Legacy: the earlier EC2 and CloudFormation deployment. It is kept for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# Architecture

## 1. Design goals

1. Developers run code in an isolated environment, the process is kept as a **reproducible recording**, and it is **scored by the same criteria**.
2. Results from coding agents (Claude Agent SDK, built-in or the user's own) are delivered with human-reviewable evidence (transcripts, screenshots, video).
3. Session isolation, authentication, observability and evaluation are left to AWS managed services (AgentCore); only what managed services cannot do (KVM) is split out to EC2.

## 2. Components

| Component | Implementation | AWS |
|---|---|---|
| Session | `DevSession` = sandbox + profile + recorder + evaluator (+ device) | Code Interpreter session (microVM) |
| Profile | `EmulatorProfile`: runtime, packages, env, setup commands, mock services | Provisioned at session start |
| Recorder | `events.jsonl` (exec / message / note / snapshot / eval), artifacts | S3 (or local), Memory |
| Snapshot | Workspace tar.gz | S3 |
| Evaluator | Rules → LLM judge → AgentCore Evaluations | Bedrock, Evaluations |
| Agent | Claude Agent SDK + session tool MCP server (10 code tools, 14 Android tools) + PreToolUse budget hook | Bedrock (CLAUDE_CODE_USE_BEDROCK), Runtime |
| Device Lab | `EC2EmulatorHost` + `device_agent` | EC2 c8i (nested virt), ECR |

## 3. Data flow

```
begin_run ─► write_files / run_command / run_code / device_action ─► end_run ─► evaluate
     │              │ each call normalizes ExecResult, then Recorder.record_exec           │
     │              └─ artifacts (screenshots, video) go through store.put → run.artifacts │
     └─ note(begin_run) ...................................................... eval event
```

- `ExecResult` is the normalized form of the Code Interpreter stream's `structuredContent` (stdout, stderr, exitCode, executionTime, taskId, taskStatus). When the exit code is non-zero the service returns the output as stderr, so the `output` property combines the two.
- `readFiles` returns `file:///path` URIs, so a leading `/` remains even after the SDK strips the scheme. `AgentCoreSandbox.read_files` normalizes based on the requested path.
- A session uses `<root>/workspace` as its working directory and wraps every command as `cd <workspace> && export ENV && <cmd>`. The cwd of `executeCommand` is undocumented, so it is pinned explicitly.

## 4. Evaluation aggregation

```
score = Σ(item.score × weight) / Σ(weight)
passed = score ≥ pass_threshold AND (every rule item with weight ≥ 1 passed)
```

The LLM judge receives the transcript (including the contents of written files) and the rubric and returns a JSON verdict. Whether file contents are included in the transcript strongly affects judging quality (measured: 0.34 without, 0.90 with).

## 4a. Harness: three delegations

| Where probability shows up | Delegated to | Implementation |
|---|---|---|
| Context | Code | Tool results are folded with `summarize_output` before being returned (800 characters by default); the full output is in `DevSession.full_output(ref)` and the recording. `write_and_run` does file write + execution in one call |
| Verification | Harness | `DevSession.verify(command, mode)` runs the verification command directly. `fresh` mode restores the snapshot into a new session and runs there. The pytest rule looks only at this result |
| Execution | Rules | Attach `RunBudget` at `begin_run` and `_record` plus `check_budget` before each tool call check execution count, time and cost; on overrun the run is marked `cancelled` via `BudgetExceeded` |

## 5. Android Device Lab

```
DevSession.start_android(profile, EC2EmulatorHost.from_env())
   └─ run_instances(c8i.xlarge, CpuOptions.NestedVirtualization=enabled, user data)
        user data: modprobe kvm → docker run device-agent(--network host, docker.sock) → docker run android-emulator(--device /dev/kvm)
   └─ (ssm) aws ssm start-session AWS-StartPortForwardingSession → 127.0.0.1:<local> → instance 127.0.0.1:8080
   └─ AndroidDevice(base_url, Bearer <per-host token>, x-cwe-session <session_id>).wait_boot()
```

Security defaults: no security group inbound (only a self-referencing rule for the same SG), device agent bound to 127.0.0.1, IMDSv2 required (hop limit 1), per-host token (SSM SecureString, deleted after boot, startup refused without it) + session binding (pool hosts via `/bind`), authentication on every endpoint, host path inputs restricted to under `/opt/cwe/builds`, Gradle tasks as argv only, user data values via `shlex.quote`, `shutdown -h +N` self-imposed lifetime cap, terminate at session end. The remaining design limitation is the docker socket mount (README security notes).

The device agent finds the emulator container's bridge IP through the docker socket and runs `adb connect`. The instance is terminated when the session ends. Host alternatives reviewed:

| Candidate | Result |
|---|---|
| AgentCore Code Interpreter / Runtime | No `/dev/kvm`, no Java or display (measured) |
| SageMaker Processing | No privileged mode or device mapping |
| AWS Batch (EC2, c8i) | Launch template CpuOptions are not applied to the managed template, so no KVM. Only metal instances work |
| Direct EC2 launch | Works. Adopted |
| EKS managed node group | CpuOptions is not on the launch template prohibited list → recommended for fleet scaling (unverified) |

### 5a. Devin emulator feature coverage (complete)

| Devin | Implementation |
|---|---|
| adb control, Computer Use | device agent HTTP + screenshot vision + UI dump coordinates |
| Recording evidence | screenrecord → S3, PR comment via `attach_evidence` |
| Instrumentation tests | `/instrument` (verified with the sample app's Espresso tests) |
| Blueprint snapshot VM | `infra/bake_ami.py` AMI + `cwe android-pool` standby pool |
| Multiple AVDs / API levels | `scripts/build_emulator_image.sh`, profile `count`/`images`, `for_device(i)` |
| In-loop app build | `android_build` (host Gradle container, snapshot transfer) |
| Skills | `cwe/skills.py` (distill → approve → on-demand load) |
| Auto setup, templates | `cwe/android_setup.py`, `examples/profiles/android/*.yaml` |
| Desktop live screen | `/view` MJPEG viewer (SSM tunnel) |

## 6. Multi-user scaling

- **Session plane**: AgentCore Runtime (microVM per session) + Identity (inbound JWT) + Memory (per actor) + Gateway (device tools as MCP). Multi-user isolation is already in place.
- **Device fleet**: on an EKS node group (c8i nested virt or metal), Pod = emulator + device-agent sidecar. Containers in a Pod share the network namespace, so no docker socket discovery is needed. A warm pool cuts the 5 to 7 minute first boot to a few seconds. A Device Broker handles session → Pod assignment, quotas and idle reclamation.
- **Recordings and artifacts**: stored in S3 under a session ID prefix. The Code Interpreter session API has no tags, so cost allocation is done by session ID prefix.

## 7. What AgentCore alone cannot do

Sessions with KVM (or a managed Android device tool), custom sandbox images and session templates, session snapshots and pause, session port exposure, Code Interpreter session recording. These were worked around with the EC2 host, profile scripts, tar snapshots and a custom recorder.
