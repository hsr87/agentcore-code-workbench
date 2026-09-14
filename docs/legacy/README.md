> Legacy: the earlier EC2 and CloudFormation deployment. It is kept for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# Code Workflow Emulator on AgentCore

A **developer platform for code execution, recording, evaluation and emulation** built on Amazon Bedrock AgentCore. It reproduces the isolated sessions, session replay, machine snapshots and Android emulator verification that Devin Cloud provides using AWS managed services, and scores the results produced by coding agents with rules, an LLM judge and AgentCore Evaluations.

Sessions use **AgentCore Code Interpreter** (one microVM per session), the agent uses **Claude Agent SDK + Claude on Bedrock**, recording uses S3 and **AgentCore Memory**, and evaluation uses **AgentCore Evaluations**. The Android emulator is split out to an **EC2 (nested virtualization) host** because AgentCore microVMs have no KVM. IaC is CloudFormation (`infra/cfn/foundation.yaml`).

> **For demo and sample purposes only.** This code is for learning and reference. Before production you need per-user authentication and authorization separation (the REST API has a single shared key), a switch to VPC mode, a least-privilege re-check, and a cost and capacity re-estimate. Be careful when running it with real code and credentials. The items fixed in the pre-release security review and the remaining limitations are in [Security notes](#security-notes).

## Key features

**Sessions and execution (Devin: Session)**
- **Isolated sandbox**: runs code, shell commands, background jobs and file I/O in an AgentCore Code Interpreter session (Linux aarch64, Python 3.12, Node 24, gcc). It is a custom interpreter in PUBLIC network mode, so pip/npm installs work (the managed `aws.codeinterpreter.v1` has no external network access, as measured).
- **Environment emulation** (`EmulatorProfile`): declare the runtime, packages, environment variables, setup commands and mock HTTP services in YAML and they are provisioned exactly as declared when the session starts. External APIs are pinned as mocks to control experiment conditions.
- **Snapshot/restore** (`snapshot()` / `restore_from=`): stores the workspace in the store and restores it into a new session.

**Recording (Devin: Session replay)**
- Every execution is recorded in `events.jsonl` as events (command, stdout/stderr, exit code, file contents, artifacts), and `ReplaySandbox` replays them deterministically without AWS. Used in CI and for regression tests of the evaluation logic.
- `message` events are also loaded as AgentCore Memory events and extracted as long-term memory across sessions (`CWE_MEMORY_ID`).

**Three evaluation layers**
- Rules (exit code, output contains/regex, file exists, pytest and instrumentation test pass rate, execution time) → LLM judge (Anthropic SDK `AnthropicBedrockMantle`, `anthropic.claude-opus-5`) → AgentCore Evaluations (Runtime session spans, `Builtin.*`).
- Aggregation rule: PASS requires the weighted average to be at or above the threshold and every rule item with weight 1 or more to pass.

**Agent (Devin: Send message)**
- A [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk/overview) agent works with the `run_shell / run_python / write_file / write_and_run / read_file / list_files / run_tests` tools. Session tools are exposed as an in-process MCP server (`cwe_mcp_server(session)`) and budget control is handled by a `PreToolUse` hook (`cwe_hooks(session)`), so an agent already built with `ClaudeAgentOptions` takes the same recording and evaluation path by adding just two entries, `mcp_servers` and `hooks` (`examples/bring_your_own_agent.py`). The model is Bedrock (`CLAUDE_CODE_USE_BEDROCK=1`), the built-in file tools are disabled (`tools=[]`), tools outside the allow list are rejected without asking (`permission_mode="dontAsk"`, `allowed_tools=["mcp__cwe"]`), and the agent is isolated from this machine's Claude Code configuration (temporary `CLAUDE_CONFIG_DIR`, `strict_mcp_config`, unnecessary secrets are not inherited). A run without a budget gets the default budget from settings (`CWE_DEFAULT_MAX_*`). Deploying it as an AgentCore Runtime entrypoint (`runtime/`) adds a microVM per session plus Observability and Evaluations.

**Additions for multi-user use and experiment comparison**
- **Post-hoc scoring**: open a closed session from its recording alone (`SessionManager.open_recorded`, `POST /v1/recorded/{id}/evaluate`) and re-score it in a different process or at a different time. This is the basis for comparing assistants and models.
- **Token and cost tracking**: each agent run records input/output tokens and an estimated cost at list price in `RunRecord.usage / cost_usd_estimate`.
- **Trace correlation**: each run generates a W3C traceparent and passes it to every Code Interpreter call (`RunRecord.trace_id`). This links AgentCore Observability traces to the recording.
- **Resource reclamation**: Android hosts get a `cwe:expires-at` tag, and `cwe reap --apply` reclaims expired instances and stale sandbox sessions. The Runtime entrypoint cleans up sessions on shutdown.
- **API key**: setting `CWE_API_KEY` makes the REST API require `x-api-key` on `/v1/*`. `cwe serve` binds to 127.0.0.1 by default and refuses to bind to an external address without a key.

**Three harness delegations (Autonomy by Design)**
- **Context to code**: only a head/tail summary of tool results (800 characters by default, `CWE_TOOL_OUTPUT_CHARS`) reaches the model; the full output stays in the recording and is available via `read_full_output(ref)`. `write_and_run` writes a file and runs it in one step.
- **Verification to the harness**: when `EvalCriteria.verify_command` is set, the harness runs the tests itself during evaluation and accepts only that result (agent output is ignored). `verify_mode: fresh` restores the snapshot into a new session and verifies it as a black box.
- **Approval to rules**: attach a `RunBudget(max_executions, max_seconds, max_cost_usd)` to a run and the harness stops it when exceeded. The run metadata records the execution count, the number of human approvals (0), the reason the budget was exceeded, and the verification result.

**Android Device Lab (Devin: Android emulator support, all items covered)**
- Runs an emulator container and a **device agent** (adb exposed over HTTP) on EC2 c8i (`NestedVirtualization=enabled`), and the agent operates and verifies the app with the `android_screenshot / android_ui / android_tap / android_swipe / android_type / android_install / android_launch / android_logcat / android_run_tests` tools. Screenshots and screen recordings are kept as artifacts.
- **Host build** (`DevSession.android_build`, tool `android_build`): sends the workspace to the host as a snapshot, builds it with Gradle in an Android SDK container (`thyrlian/android-sdk`), and installs the resulting APK directly. The sandbox has no Java/SDK (PFR R2), so this is a workaround that builds on the host. The Gradle cache stays on the host (`/opt/cwe/gradle`) and in the AMI.
- **Auto setup** (`cwe android-setup <repo>`): reads the repository's Gradle settings (compileSdk, applicationId, instrumentation runner) and framework (native / react-native / flutter / kmp templates, `examples/profiles/android/`) and proposes an emulator profile.
- **Shorter startup time**: `python infra/bake_ami.py --warm-gradle` builds an AMI with the emulator, device agent and build images pre-pulled and the sample app built once (`CWE_ANDROID_AMI_ID`). `cwe android-pool --size N` keeps booted hosts in a standby pool, cutting session start to a few seconds (the counterpart of Devin blueprint snapshot VMs; incurs continuous cost).
- **Multiple API levels and multiple emulators**: `scripts/build_emulator_image.sh --api 34` builds API 30+ images with Google's container scripts and pushes them to ECR. Profile `count` and `images` start several emulators on one host, and `AndroidDevice.for_device(i)` operates each one.
- **Live screen** (`/view`, `/stream.mjpeg`): a person can watch the screen in a browser (SSM tunnel) and tap, go back and type text (the counterpart of Devin Desktop mode). The `android_live_view_url` tool returns the address. The URL carries a 5-minute single-use viewer token rather than the master token, and it is exchanged for an HttpOnly cookie when opened.
- **Skill accumulation** (`cwe skill distill|approve|list`): drafts a procedure document (SKILL.md) from the recording of a successful run, and the agent reads only approved skills on demand via `list_skills / load_skill`.
- **PR attachment** (`cwe.github.attach_evidence`): posts presigned links to screenshots and recordings, the harness verification result, and the execution count and cost as a GitHub PR comment (`GITHUB_TOKEN`).

## Architecture

```mermaid
flowchart TB
    dev["Developer / CI"] --> api["REST API (FastAPI)<br/>or AgentCore Runtime entrypoint"]
    api --> sm["SessionManager → DevSession"]
    subgraph agentcore["Amazon Bedrock AgentCore"]
        ci["Code Interpreter session<br/>(microVM, PUBLIC custom)"]
        mem["Memory (message events)"]
        ev["Evaluations (Builtin / custom)"]
    end
    subgraph aws["AWS"]
        s3["S3 recordings<br/>events.jsonl, snapshots, artifacts"]
        br["Bedrock<br/>Claude Opus 5 (agent, LLM judge)"]
        ec2["EC2 c8i.xlarge (nested virt)<br/>android-emulator + device-agent"]
    end
    sm -- executeCode / executeCommand / files --> ci
    sm -- Recorder --> s3
    sm -- Recorder --> mem
    sm -- Evaluate --> ev
    sm -- Claude Agent SDK agent / LLM judge --> br
    sm -- HTTP (Bearer + session) --> ec2
    replay["ReplaySandbox (offline)"] -. events.jsonl .-> s3
```

Host selection rationale (measured, 2026-09): AgentCore Code Interpreter/Runtime microVMs have no `/dev/kvm`, SageMaker Processing blocks privileged/device access, and AWS Batch ignores the launch template's CpuOptions so nested virtualization does not turn on for c8i. See [`docs/architecture.md`](./docs/architecture.md) for the detailed design.

## Directory layout

```
.
├── src/cwe/                 # library
│   ├── sandbox.py           #   AgentCoreSandbox / ReplaySandbox / FakeSandbox, result normalization
│   ├── session.py           #   DevSession (session, run, snapshot, evaluation, device), SessionManager
│   ├── emulator.py          #   EmulatorProfile provisioning, mock HTTP services
│   ├── recorder.py          #   events.jsonl (local/S3), transcripts, Memory integration
│   ├── evaluator.py         #   rules / LLM judge / AgentCore Evaluations, aggregation
│   ├── snapshots.py         #   workspace tar → store → restore
│   ├── agent.py             #   Claude Agent SDK agent: session tool MCP server, budget hook, run_task
│   ├── android.py           #   AndroidDevice (HTTP client), EC2EmulatorHost (AMI, standby pool, multiple emulators)
│   ├── android_setup.py     #   propose an emulator profile from the repository's Gradle settings
│   ├── skills.py            #   skill store, distill skills from successful runs
│   ├── github.py            #   attach evidence as PR comments
│   ├── api.py               #   Devin API-like REST
│   ├── runtime_app.py       #   AgentCore Runtime entrypoint
│   └── cli.py               #   cwe run / replay / serve / reap / skill / android-setup / android-pool
├── device_agent/            # emulator host sidecar: adb → HTTP (screenshot, ui, tap, install, build, instrument, screenrecord, viewer)
├── infra/cfn/foundation.yaml# Code Interpreter (PUBLIC) + execution role, recordings S3, operator policy, 2 ECR repos, 2 instance profiles (session host / image build), SG
├── infra/bake_ami.py        # bake the emulator host AMI (pre-pull images, warm the Gradle cache)
├── runtime/                 # AgentCore Runtime container (ARM64) and deployment guide
├── scripts/                 # deploy.sh, cleanup.sh, build_emulator_image.sh (API 30+ images)
├── examples/                # quickstart.py, bring_your_own_agent.py, android_quickstart.py, android-sample/ (Espresso sample app), profiles/, criteria/
├── tests/                   # unit tests that run without AWS (FakeSandbox, FakeAndroidDevice, device agent TestClient)
└── docs/                    # architecture.md, operations.md
```

## Prerequisites

| Item | Notes |
|---|---|
| AWS credentials (us-east-1 recommended) | Enable access to `anthropic.claude-opus-5` / `us.anthropic.claude-opus-5` in Bedrock |
| Python 3.12+, [uv](https://github.com/astral-sh/uv) | |
| [Finch](https://runfinch.com/) or Docker | Builds the device agent image (amd64). Switch with `CWE_CONTAINER_CLI=docker` |
| [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) | Android host access (default `ssm` mode) |
| CloudFormation `CAPABILITY_NAMED_IAM` permission | Creates 3 roles and 1 managed policy |
| `pyflakes` (optional) | Static check with `python -m pyflakes src device_agent tests` |

## Run order

```bash
# 0) Dependencies
uv venv --python 3.12 .venv && source .venv/bin/activate && uv pip install -e ".[dev]"
python -m pytest -q                      # 67 tests without AWS (including device agent security regressions)

# 1) Deploy foundation resources (CloudFormation + device agent image + .env)
./scripts/legacy/deploy.sh --region us-east-1   # options: --no-android, --allowed-cidr <fixed CIDR> (opt-in public access)
set -a && source .env && set +a

# 2) Code workflow: provision profile → mock payment API → pytest → snapshot → evaluate → offline replay
python examples/quickstart.py
python examples/quickstart.py --agent    # delegate the implementation to a Claude Agent SDK agent
python examples/bring_your_own_agent.py  # attach a session to your own ClaudeAgentOptions

# 3) Android: start EC2 host (first boot 5 to 7 min, 1 to 2 min with an AMI) → screenshot/UI dump/tap/record → evaluate → terminate instance
python examples/android_quickstart.py
python examples/android_quickstart.py --agent
cwe android-setup examples/android-sample          # propose a profile from the repository
python infra/bake_ami.py --warm-gradle             # (optional) AMI for faster startup → CWE_ANDROID_AMI_ID in .env
./scripts/build_emulator_image.sh --api 34         # (optional) API 30+ image → ECR
cwe android-pool --size 1                          # (optional) standby pool

# 4) REST API (default 127.0.0.1:8000. External addresses are refused without CWE_API_KEY)
CWE_API_KEY=<random> cwe serve           # http://localhost:8000/docs (x-api-key header)

# 5) Operations: reclaim expired hosts/sessions (run periodically via cron or EventBridge)
cwe reap            # dry run
cwe reap --apply
```

## Security notes

The code went through a security review (2026-09-10) before release. Below is what the code guarantees now and the limitations left because it is a sample.

**Credentials and permissions**
- Secrets live only in `.env` (gitignored); see `.env.example`. `GITHUB_TOKEN`, `CWE_API_KEY` and `ANTHROPIC_*` are not passed to the agent CLI process (`cwe_env()` overwrites them with empty values).
- Attach only the stack-created `cwe-operator` managed policy to the principal that runs this. `ec2:RunInstances` is restricted by the `project` tag and the allowed instance types (c8i/m8i/r8i/metal); `TerminateInstances`, `ssm:StartSession`, `ssm:SendCommand` and `CreateImage` are restricted to instances with the `project` tag. `CreateTags` for pool claims cannot change the `project` tag.
- The Code Interpreter execution role trusts `bedrock-agentcore.amazonaws.com` only with `SourceAccount`/`SourceArn` conditions.
- The session host's instance role can only read its own token parameter and pull from ECR. Emulator image push exists only in the profile dedicated to `build_emulator_image.sh` (`cwe-emulator-image-build-profile`).

**Device agent (EC2 host)**
- The default is **no inbound rules + SSM Session Manager port forwarding** (`CWE_ANDROID_ACCESS=ssm`). The device agent binds only to 127.0.0.1 on the host, and the local side connects with `aws ssm start-session` (AWS-StartPortForwardingSession). IMDSv2 is required, `HttpPutResponseHopLimit=1` (build containers cannot reach the instance role).
- Each host gets a new Bearer token (192 bits) delivered only as an SSM SecureString, and the parameter is deleted as soon as the agent responds. The agent refuses to start if the token is empty (fail closed). Comparison is constant time. `x-cwe-session` is a routing guard that prevents accidentally attaching to the wrong host (not a secret), and standby pool hosts are bound to a session exactly once via `/bind` right after being claimed.
- Every device endpoint, including `/health`, requires authentication (only `/healthz` is unauthenticated liveness). `build_id` for `/build` and `path` for `/install` are allowed only under `/opt/cwe/builds`, Gradle tasks are passed as argv only with no shell interpretation, and source tars are extracted with `filter="data"` to prevent path escape. Downloads are https only, with a 512 MB size cap.
- The browser viewer (`/view`) exchanges a 5-minute single-use viewer token, not the master token, for an HttpOnly cookie, and the cookie allows only the viewer paths (stream, tap, key, input).
- User data uses `set -euo pipefail`, every value is inserted via `shlex.quote`, and `shutdown -h +N` makes the instance terminate itself when the job time limit passes (nothing is left behind even if the reaper dies).
  - Agents inside the VPC (VPC-mode AgentCore Runtime): give them the same security group and use `CWE_ANDROID_ACCESS=private` (private IP).
  - Only when you have a fixed office/VPN CIDR, opt in to public access (`public`) with `./scripts/legacy/deploy.sh --allowed-cidr <CIDR>`. This mode is **plain HTTP**, so the Bearer token is exposed on the path; use it only from a trusted VPN range. The template rejects `0.0.0.0/0`. `/32` does not work in environments where the NAT egress IP changes.
- **Known limitation (by design)**: the device agent container mounts the docker socket to create Gradle build containers. If the agent process is compromised, that is equivalent to root on that host. The host is created fresh for each session, terminated when it ends, and the instance role's permissions are reduced as described above, limiting the blast radius to one session. When scaling to a fleet, an EKS Pod structure (emulator + agent sidecar, no socket needed) is recommended (`docs/architecture.md` section 6).

**REST API and sessions**
- `CWE_API_KEY` is a single shared key. Anyone holding the key can access every session, recording and snapshot; there is no per-user authorization separation. For multiple users, put it behind AgentCore Runtime (IAM/JWT authentication, isolation per runtimeSessionId) or put ALB + Cognito in front. `cwe serve` defaults to 127.0.0.1 and refuses to bind to an external address without a key.
- Client-supplied session and snapshot IDs are accepted only in the server-generated format (`sess_…`, `snap_…`). Store keys reject `..`, absolute paths and the reserved namespace (`_skills`). Request bodies have size caps (execution input 200 KB, upload 10 MB, message 20 KB).
- Profile `env` values are passed to the sandbox's `.cwe/env` (600) rather than on the command line, so they do not leak into recordings, transcripts, LLM judge prompts or skill distillation, and they are masked as `***` in API responses. They are excluded from snapshots too.
- Agent runs never run without a budget. If no `budget` is given, `CWE_DEFAULT_MAX_EXECUTIONS / _SECONDS / _COST_USD / _TURNS` (defaults 60 / 1200 / 5.0 / 40) apply, and the PreToolUse hook rejects even on internal errors (fail closed).
- The LLM judge treats the transcript as **untrusted data**, wrapped in tags with a different random id on every call, and gives harness verification results priority over agent output. It cannot fully prevent score manipulation, so also include rule items such as `harness_verification`/`pytest` (weight ≥ 1).
- Presigned URLs last 1 hour by default, and once attached to a PR comment anyone can open them until they expire. Local store paths are never exposed externally.
- The Runtime container runs as non-root (`app`).

**Sandbox**
- PUBLIC mode has open outbound internet. For internal code, VPC mode + EFS/S3 Files mounts are recommended. Running commands inside the sandbox is a designed feature, so `..` paths or arbitrary commands inside the sandbox are not something to block.

## Cost

| Resource | Basis | Notes |
|---|---|---|
| Code Interpreter session | Billed for active session time | 30-minute timeout by default, `mgr.close()` ends it immediately |
| Bedrock Claude Opus 5 | Tokens | Agent and LLM judge. Judging can be disabled with `CWE_ENABLE_LLM_JUDGE=false` |
| EC2 c8i.xlarge | About $0.19/h | Only during Android sessions. Terminated when the session ends |
| S3 / ECR | Stored volume | A few MB |
| Standing stack cost | $0 | No charge when there are no instances or sessions |

## Cleanup

```bash
./scripts/legacy/cleanup.sh --region us-east-1                  # terminate instances, stop sessions, delete stack (recordings bucket is kept)
./scripts/legacy/cleanup.sh --region us-east-1 --delete-bucket  # also delete the recordings bucket
```

## Known limitations

- Google's public emulator images go up to API 30 (Android 11). For newer APIs, build with [android-emulator-container-scripts](https://github.com/google/android-emulator-container-scripts), push to ECR, and change `AndroidEmulatorProfile.image`.
- Code Interpreter sessions last at most 8 hours and their data is lost on termination. Persistence across sessions is handled with snapshots or EFS/S3 Files mounts.
- `executeCommand` returns the output as `stderr` when the exit code is non-zero. `ExecResult.output` combines the two.

## References

- [AgentCore Code Interpreter](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-tool.html), [AgentCore Evaluations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/built-in-evaluators-overview.html)
- [Devin Android emulator support](https://docs.devin.ai/onboard-devin/environment/android-emulation)
- [Amazon EC2 nested virtualization](https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual)
