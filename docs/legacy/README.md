> Legacy: the earlier EC2 and CloudFormation deployment. It is kept in Korean for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# Code Workflow Emulator on AgentCore

Amazon Bedrock AgentCore 위에 구축한 **개발자용 코드 실행 · 기록 · 평가 · 에뮬레이션 플랫폼**입니다. Devin Cloud 가 제공하는 격리 세션, 세션 리플레이, 머신 스냅샷, Android 에뮬레이터 검증을 AWS 관리형 서비스로 재현하고, 코딩 에이전트가 만든 결과를 규칙·LLM 심사·AgentCore Evaluations 로 채점합니다.

세션은 **AgentCore Code Interpreter**(세션당 microVM), 에이전트는 **Claude Agent SDK + Claude on Bedrock**, 기록은 S3 와 **AgentCore Memory**, 평가는 **AgentCore Evaluations** 를 씁니다. Android 에뮬레이터는 AgentCore microVM 에 KVM 이 없어 **EC2(nested virtualization) 호스트** 로 분리했습니다. IaC 는 CloudFormation(`infra/cfn/foundation.yaml`)입니다.

> ⚠️ **데모/샘플 목적 전용입니다.** 학습과 참조를 위한 코드이며, 프로덕션 전에는 사용자별 인증·권한 분리(REST API 는 공유 키 하나), VPC 모드 전환, 최소 권한 재점검, 비용·용량 재산정이 필요합니다. 실제 코드·자격증명으로 실행할 때 유의하세요. 공개 전 보안 리뷰에서 고친 항목과 남은 한계는 [보안 참고 사항](#보안-참고-사항)에 있습니다.

## 주요 기능

**세션과 실행 (Devin: Session)**
- **격리 샌드박스**: AgentCore Code Interpreter 세션(Linux aarch64, Python 3.12, Node 24, gcc)에서 코드·셸·백그라운드 작업·파일 I/O 를 실행합니다. PUBLIC 네트워크 모드 커스텀 인터프리터라 pip/npm 설치가 됩니다(관리형 `aws.codeinterpreter.v1` 은 외부 네트워크 불가 — 실측).
- **환경 에뮬레이션** (`EmulatorProfile`): 런타임·패키지·환경변수·셋업 명령·mock HTTP 서비스를 YAML 로 선언하면 세션 시작 시 그대로 프로비저닝됩니다. 외부 API 를 mock 으로 고정해 실험 조건을 통제합니다.
- **스냅샷/복원** (`snapshot()` / `restore_from=`): 워크스페이스를 저장소에 보관하고 새 세션에 복원합니다.

**기록 (Devin: Session replay)**
- 모든 실행이 `events.jsonl` 에 이벤트(명령·stdout/stderr·종료 코드·파일 내용·아티팩트)로 남고, `ReplaySandbox` 가 AWS 없이 결정적으로 재생합니다. CI 와 평가 로직 회귀 테스트에 씁니다.
- `message` 이벤트는 AgentCore Memory 이벤트로도 적재되어 세션 간 장기 기억으로 추출됩니다(`CWE_MEMORY_ID`).

**평가 3계층**
- 규칙(종료 코드, 출력 포함/정규식, 파일 존재, pytest·계측 테스트 통과율, 실행 시간) → LLM 심사관(Anthropic SDK `AnthropicBedrockMantle`, `anthropic.claude-opus-5`) → AgentCore Evaluations(Runtime 세션 span, `Builtin.*`).
- 집계 규칙: 가중 평균이 임계값 이상이고 가중치 1 이상의 규칙 항목이 모두 통과해야 PASS.

**에이전트 (Devin: Send message)**
- [Claude Agent SDK](https://docs.claude.com/en/api/agent-sdk/overview) 에이전트가 `run_shell / run_python / write_file / write_and_run / read_file / list_files / run_tests` 도구로 작업합니다. 세션 도구는 인프로세스 MCP 서버(`cwe_mcp_server(session)`)로 노출되고 예산 통제는 `PreToolUse` 훅(`cwe_hooks(session)`)이 맡으므로, 이미 `ClaudeAgentOptions` 로 만든 에이전트는 `mcp_servers` 와 `hooks` 두 항목만 더하면 같은 기록·평가 경로를 탑니다(`examples/bring_your_own_agent.py`). 모델은 Bedrock(`CLAUDE_CODE_USE_BEDROCK=1`), 내장 파일 도구는 끄고(`tools=[]`) 허용 목록 밖의 도구는 묻지 않고 거부하며(`permission_mode="dontAsk"`, `allowed_tools=["mcp__cwe"]`) 이 머신의 Claude Code 설정과 격리합니다(`CLAUDE_CONFIG_DIR` 임시 디렉터리, `strict_mcp_config`, 불필요한 비밀은 상속하지 않음). budget 을 주지 않은 run 에는 설정의 기본 예산(`CWE_DEFAULT_MAX_*`)이 걸립니다. AgentCore Runtime 진입점(`runtime/`)으로 배포하면 세션당 microVM 과 Observability·Evaluations 가 붙습니다.

**다중 사용자·실험 비교를 위한 보강**
- **사후 채점**: 닫힌 세션을 기록만으로 열어(`SessionManager.open_recorded`, `POST /v1/recorded/{id}/evaluate`) 다른 프로세스·다른 시점에 재채점합니다. 어시스턴트·모델 간 비교의 기반입니다.
- **토큰·비용 추적**: 에이전트 run 마다 입력/출력 토큰과 정가 기준 추정 비용을 `RunRecord.usage / cost_usd_estimate` 에 남깁니다.
- **트레이스 상관관계**: run 마다 W3C traceparent 를 생성해 모든 Code Interpreter 호출에 전달합니다(`RunRecord.trace_id`). AgentCore Observability 트레이스와 기록을 잇습니다.
- **리소스 회수**: Android 호스트에 `cwe:expires-at` 태그를 붙이고 `cwe reap --apply` 가 만료 인스턴스·오래된 샌드박스 세션을 회수합니다. Runtime 진입점은 종료 시 세션을 정리합니다.
- **API 키**: `CWE_API_KEY` 를 설정하면 REST API 의 `/v1/*` 에 `x-api-key` 를 요구합니다. `cwe serve` 는 기본 127.0.0.1 에 붙고, 키 없이 외부 주소에 붙이는 것은 거부합니다.

**하네스 3가지 위임 (Autonomy by Design)**
- **컨텍스트는 코드로**: 도구 결과는 앞뒤 요약(기본 800자, `CWE_TOOL_OUTPUT_CHARS`)만 모델에 들어가고 전체 출력은 기록과 `read_full_output(ref)` 로 남습니다. `write_and_run` 이 파일 쓰기와 실행을 한 번에 합니다.
- **검증은 하네스가**: `EvalCriteria.verify_command` 를 두면 평가 시 하네스가 직접 테스트를 실행하고 그 결과만 인정합니다(에이전트 출력 무시). `verify_mode: fresh` 는 스냅샷을 새 세션에 복원해 블랙박스로 검증합니다.
- **승인은 규칙이**: `RunBudget(max_executions, max_seconds, max_cost_usd)` 를 run 에 걸면 하네스가 초과 시 중단합니다. run 메타에 실행 횟수, 사람 승인 횟수(0), 예산 초과 사유, 검증 결과가 남습니다.

**Android Device Lab (Devin: Android emulator support, 전 항목 대응)**
- EC2 c8i(`NestedVirtualization=enabled`)에 에뮬레이터 컨테이너와 **device agent**(adb 를 HTTP 로 노출)를 띄우고, 에이전트가 `android_screenshot / android_ui / android_tap / android_swipe / android_type / android_install / android_launch / android_logcat / android_run_tests` 도구로 앱을 조작·검증합니다. 스크린샷·화면 녹화가 아티팩트로 남습니다.
- **호스트 빌드** (`DevSession.android_build`, 도구 `android_build`): 워크스페이스를 스냅샷으로 호스트에 보내 Android SDK 컨테이너(`thyrlian/android-sdk`)로 Gradle 빌드하고 결과 APK 를 그대로 설치합니다. 샌드박스에는 Java/SDK 가 없어(PFR R2) 호스트에서 빌드하는 우회입니다. Gradle 캐시는 호스트(`/opt/cwe/gradle`)와 AMI 에 남습니다.
- **자동 설정** (`cwe android-setup <repo>`): 저장소의 Gradle 설정(compileSdk, applicationId, 계측 러너)과 프레임워크(native / react-native / flutter / kmp 템플릿, `examples/profiles/android/`)를 읽어 에뮬레이터 프로파일을 제안합니다.
- **준비 시간 단축**: `python infra/bake_ami.py --warm-gradle` 이 에뮬레이터·device agent·빌드 이미지를 미리 풀고 샘플 앱을 한 번 빌드한 AMI 를 만듭니다(`CWE_ANDROID_AMI_ID`). `cwe android-pool --size N` 은 부팅된 호스트를 대기 풀로 유지해 세션 시작을 수 초로 줄입니다(Devin 블루프린트 스냅샷 VM 대응, 상시 비용 발생).
- **여러 API 레벨과 다중 에뮬레이터**: `scripts/build_emulator_image.sh --api 34` 가 Google 컨테이너 스크립트로 API 30 이상 이미지를 빌드해 ECR 에 올립니다. 프로파일 `count` 와 `images` 로 한 호스트에 에뮬레이터를 여러 대 띄우고 `AndroidDevice.for_device(i)` 로 각각 조작합니다.
- **실시간 화면** (`/view`, `/stream.mjpeg`): 사람이 브라우저(SSM 터널)로 화면을 보며 탭, 뒤로가기, 텍스트 입력을 할 수 있습니다(Devin Desktop 모드 대응). 도구 `android_live_view_url` 이 주소를 알려줍니다. 주소에는 마스터 토큰이 아니라 5분짜리 1회용 뷰어 토큰이 실리고, 열면 HttpOnly 쿠키로 바뀝니다.
- **스킬 축적** (`cwe skill distill|approve|list`): 성공한 run 의 기록에서 절차서(SKILL.md) 초안을 만들고, 승인된 스킬만 에이전트가 `list_skills / load_skill` 로 필요할 때 읽습니다.
- **PR 첨부** (`cwe.github.attach_evidence`): 스크린샷·녹화의 presigned 링크, 하네스 검증 결과, 실행 횟수와 비용을 GitHub PR 코멘트로 남깁니다(`GITHUB_TOKEN`).

## 아키텍처

```mermaid
flowchart TB
    dev["개발자 / CI"] --> api["REST API (FastAPI)<br/>또는 AgentCore Runtime 진입점"]
    api --> sm["SessionManager → DevSession"]
    subgraph agentcore["Amazon Bedrock AgentCore"]
        ci["Code Interpreter 세션<br/>(microVM, PUBLIC 커스텀)"]
        mem["Memory (message 이벤트)"]
        ev["Evaluations (Builtin / custom)"]
    end
    subgraph aws["AWS"]
        s3["S3 recordings<br/>events.jsonl · 스냅샷 · 아티팩트"]
        br["Bedrock<br/>Claude Opus 5 (에이전트·LLM 심사)"]
        ec2["EC2 c8i.xlarge (nested virt)<br/>android-emulator + device-agent"]
    end
    sm -- executeCode / executeCommand / files --> ci
    sm -- Recorder --> s3
    sm -- Recorder --> mem
    sm -- Evaluate --> ev
    sm -- Claude Agent SDK 에이전트 / LLM 심사 --> br
    sm -- HTTP (Bearer + session) --> ec2
    replay["ReplaySandbox (오프라인)"] -. events.jsonl .-> s3
```

호스트 선택 근거(실측, 2026-09): AgentCore Code Interpreter/Runtime microVM 은 `/dev/kvm` 이 없고, SageMaker Processing 은 privileged/디바이스 접근을 막으며, AWS Batch 는 런치 템플릿의 CpuOptions 를 무시해 c8i 에서 nested virtualization 이 켜지지 않습니다. 세부 설계는 [`docs/architecture.md`](./docs/architecture.md) 를 보세요.

## 디렉토리 구성

```
.
├── src/cwe/                 # 라이브러리
│   ├── sandbox.py           #   AgentCoreSandbox / ReplaySandbox / FakeSandbox, 결과 정규화
│   ├── session.py           #   DevSession(세션·run·스냅샷·평가·디바이스), SessionManager
│   ├── emulator.py          #   EmulatorProfile 프로비저닝, mock HTTP 서비스
│   ├── recorder.py          #   events.jsonl(로컬/S3), 트랜스크립트, Memory 연동
│   ├── evaluator.py         #   규칙 / LLM 심사 / AgentCore Evaluations, 집계
│   ├── snapshots.py         #   워크스페이스 tar → 저장소 → 복원
│   ├── agent.py             #   Claude Agent SDK 에이전트: 세션 도구 MCP 서버, 예산 훅, run_task
│   ├── android.py           #   AndroidDevice(HTTP 클라이언트), EC2EmulatorHost(AMI, 대기 풀, 다중 에뮬레이터)
│   ├── android_setup.py     #   저장소 Gradle 설정으로 에뮬레이터 프로파일 제안
│   ├── skills.py            #   스킬 저장소, 성공한 run 에서 스킬 증류
│   ├── github.py            #   증빙을 PR 코멘트로 첨부
│   ├── api.py               #   Devin API 유사 REST
│   ├── runtime_app.py       #   AgentCore Runtime 진입점
│   └── cli.py               #   cwe run / replay / serve / reap / skill / android-setup / android-pool
├── device_agent/            # 에뮬레이터 호스트 사이드카: adb → HTTP (screenshot, ui, tap, install, build, instrument, screenrecord, viewer)
├── infra/cfn/foundation.yaml# Code Interpreter(PUBLIC)+실행 역할, recordings S3, operator 정책, ECR 2개, 인스턴스 프로파일 2개(세션 호스트/이미지 빌드), SG
├── infra/bake_ami.py        # 에뮬레이터 호스트 AMI 굽기 (이미지 선풀, Gradle 캐시 예열)
├── runtime/                 # AgentCore Runtime 컨테이너(ARM64) 와 배포 안내
├── scripts/                 # deploy.sh, cleanup.sh, build_emulator_image.sh(API 30 이상 이미지)
├── examples/                # quickstart.py, bring_your_own_agent.py, android_quickstart.py, android-sample/(Espresso 샘플 앱), profiles/, criteria/
├── tests/                   # AWS 없이 도는 단위 테스트 (FakeSandbox, FakeAndroidDevice, device agent TestClient)
└── docs/                    # architecture.md, operations.md
```

## 사전 준비

| 항목 | 비고 |
|---|---|
| AWS 자격증명 (us-east-1 권장) | Bedrock 에서 `anthropic.claude-opus-5` / `us.anthropic.claude-opus-5` 접근 활성화 |
| Python 3.12+, [uv](https://github.com/astral-sh/uv) | |
| [Finch](https://runfinch.com/) 또는 Docker | device agent 이미지 빌드(amd64). `CWE_CONTAINER_CLI=docker` 로 전환 가능 |
| [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html) | Android 호스트 접속(기본 `ssm` 모드) |
| CloudFormation `CAPABILITY_NAMED_IAM` 권한 | 역할 3개, 관리형 정책 1개 생성 |
| `pyflakes` (선택) | `python -m pyflakes src device_agent tests` 로 정적 검사 |

## 실행 순서

```bash
# 0) 의존성
uv venv --python 3.12 .venv && source .venv/bin/activate && uv pip install -e ".[dev]"
python -m pytest -q                      # AWS 없이 67개 테스트 (device agent 보안 회귀 포함)

# 1) 기반 리소스 배포 (CloudFormation + device agent 이미지 + .env)
./scripts/legacy/deploy.sh --region us-east-1   # 옵션: --no-android, --allowed-cidr <고정 CIDR>(공인 접근 opt-in)
set -a && source .env && set +a

# 2) 코드 워크플로: 프로파일 프로비저닝 → mock 결제 API → pytest → 스냅샷 → 평가 → 오프라인 리플레이
python examples/quickstart.py
python examples/quickstart.py --agent    # Claude Agent SDK 에이전트에게 구현 위임
python examples/bring_your_own_agent.py  # 자기 ClaudeAgentOptions 에 세션을 붙이는 형태

# 3) Android: EC2 호스트 기동(첫 부팅 5~7분, AMI 사용 시 1~2분) → 스크린샷/UI 덤프/탭/녹화 → 평가 → 인스턴스 종료
python examples/android_quickstart.py
python examples/android_quickstart.py --agent
cwe android-setup examples/android-sample          # 저장소에서 프로파일 제안
python infra/bake_ami.py --warm-gradle             # (선택) 준비 시간 단축용 AMI → .env 에 CWE_ANDROID_AMI_ID
./scripts/build_emulator_image.sh --api 34         # (선택) API 30 이상 이미지 → ECR
cwe android-pool --size 1                          # (선택) 대기 풀

# 4) REST API (기본 127.0.0.1:8000. 외부 주소는 CWE_API_KEY 없이는 거부)
CWE_API_KEY=<random> cwe serve           # http://localhost:8000/docs (x-api-key 헤더)

# 5) 운영: 만료 호스트/세션 회수 (cron 또는 EventBridge 로 주기 실행)
cwe reap            # 드라이런
cwe reap --apply
```

## 보안 참고 사항

공개 전 코드 보안 리뷰(2026-09-10)를 거쳤습니다. 아래는 지금 코드가 보장하는 것과, 샘플이라 남겨 둔 한계입니다.

**자격증명과 권한**
- 시크릿은 `.env`(gitignored)에만 둡니다. 예시는 `.env.example`. 에이전트 CLI 프로세스에는 `GITHUB_TOKEN`, `CWE_API_KEY`, `ANTHROPIC_*` 를 넘기지 않습니다(`cwe_env()` 가 빈 값으로 덮어씀).
- 실행 주체에는 스택이 만든 `cwe-operator` 관리형 정책만 붙이세요. `ec2:RunInstances` 는 `project` 태그와 허용 인스턴스 타입(c8i/m8i/r8i/metal)으로, `TerminateInstances`·`ssm:StartSession`·`ssm:SendCommand`·`CreateImage` 는 `project` 태그가 붙은 인스턴스로 제한됩니다. 풀 클레임용 `CreateTags` 는 `project` 태그를 바꿀 수 없습니다.
- Code Interpreter 실행 역할은 `bedrock-agentcore.amazonaws.com` 을 `SourceAccount`/`SourceArn` 조건으로만 신뢰합니다.
- 세션 호스트의 인스턴스 역할은 자기 토큰 파라미터 읽기와 ECR pull 뿐입니다. 에뮬레이터 이미지 push 는 `build_emulator_image.sh` 전용 프로파일(`cwe-emulator-image-build-profile`)에만 있습니다.

**디바이스 에이전트(EC2 호스트)**
- 기본값은 **인바운드 규칙 없음 + SSM Session Manager 포트 포워딩**(`CWE_ANDROID_ACCESS=ssm`)입니다. device agent 는 호스트의 127.0.0.1 에만 바인드되고, 로컬에서는 `aws ssm start-session`(AWS-StartPortForwardingSession)으로 붙습니다. IMDSv2 필수, `HttpPutResponseHopLimit=1`(빌드 컨테이너에서 인스턴스 역할에 닿지 못함).
- 호스트마다 새 Bearer 토큰(192비트)을 SSM SecureString 으로만 전달하고, 에이전트가 응답하면 파라미터를 바로 지웁니다. 토큰이 비어 있으면 에이전트가 기동을 거부합니다(fail closed). 비교는 상수 시간. `x-cwe-session` 은 잘못된 호스트에 붙는 사고를 막는 라우팅 가드이며(비밀 아님), 대기 풀 호스트는 클레임 직후 `/bind` 로 한 번만 세션에 묶입니다.
- `/health` 를 포함한 모든 디바이스 엔드포인트가 인증을 요구합니다(`/healthz` 만 무인증 liveness). `/build` 의 `build_id` 와 `/install` 의 `path` 는 `/opt/cwe/builds` 아래로만 허용되고, Gradle 태스크는 셸 해석 없이 argv 로만 전달되며, 소스 tar 는 `filter="data"` 로 풀어 경로 탈출을 막습니다. 다운로드는 https 만, 크기 상한 512 MB.
- 브라우저 뷰어(`/view`)는 마스터 토큰 대신 5분짜리 1회용 뷰어 토큰을 HttpOnly 쿠키로 교환하고, 쿠키로는 뷰어 경로(스트림, 탭, 키, 입력)만 허용합니다.
- user data 는 `set -euo pipefail` 이고 모든 값이 `shlex.quote` 로 들어가며, `shutdown -h +N` 으로 작업 시간 상한이 지나면 인스턴스가 스스로 terminate 됩니다(리퍼가 죽어도 남지 않음).
  - VPC 내부 에이전트(VPC 모드 AgentCore Runtime): 같은 보안 그룹을 부여하고 `CWE_ANDROID_ACCESS=private`(사설 IP).
  - 고정 사무실/VPN CIDR 만 있을 때만 `./scripts/legacy/deploy.sh --allowed-cidr <CIDR>` 로 공인 접근을 opt-in(`public`). 이 모드는 **평문 HTTP** 라 Bearer 토큰이 경로상에 노출되므로 신뢰하는 VPN 대역에서만 쓰고, `0.0.0.0/0` 은 템플릿이 거부합니다. NAT 출구 IP 가 바뀌는 환경에서 `/32` 는 동작하지 않습니다.
- **알려진 한계(설계)**: device agent 컨테이너는 Gradle 빌드 컨테이너를 만들기 위해 docker 소켓을 마운트합니다. 에이전트 프로세스가 뚫리면 그 호스트의 root 와 같습니다. 호스트는 세션마다 새로 만들고 끝나면 terminate 하며 인스턴스 역할의 권한을 위와 같이 줄여 피해 범위를 한 세션으로 제한했습니다. 플릿으로 확장할 때는 EKS Pod(에뮬레이터 + 에이전트 사이드카, 소켓 불필요) 구조를 권장합니다(`docs/architecture.md` 6절).

**REST API 와 세션**
- `CWE_API_KEY` 는 공유 키 하나입니다. 키 보유자는 모든 세션·기록·스냅샷에 접근할 수 있고 사용자별 권한 분리는 없습니다. 다중 사용자는 AgentCore Runtime(IAM/JWT 인증, runtimeSessionId 단위 격리) 뒤에 두거나 ALB + Cognito 를 앞에 두세요. `cwe serve` 는 기본 127.0.0.1 이며 키 없이 외부 주소에 붙는 것은 거부합니다.
- 클라이언트가 주는 세션·스냅샷 ID 는 서버가 만드는 형식(`sess_…`, `snap_…`)만 받습니다. 저장소 키는 `..`, 절대 경로, 예약 네임스페이스(`_skills`)를 거부합니다. 요청 본문에는 크기 상한이 있습니다(실행 입력 200 KB, 업로드 10 MB, 메시지 20 KB).
- 프로파일 `env` 값은 명령줄이 아니라 샌드박스의 `.cwe/env`(600) 로 전달되어 기록·트랜스크립트·LLM 심사 프롬프트·스킬 증류에 새지 않고, API 응답에서는 `***` 로 가려집니다. 스냅샷에서도 제외됩니다.
- 에이전트 run 은 예산 없이 돌지 않습니다. `budget` 을 주지 않으면 `CWE_DEFAULT_MAX_EXECUTIONS / _SECONDS / _COST_USD / _TURNS`(기본 60 / 1200 / 5.0 / 40)가 걸리고, PreToolUse 훅은 내부 오류 시에도 거부합니다(fail closed).
- LLM 심사관은 트랜스크립트를 호출마다 다른 무작위 id 의 태그로 감싼 **신뢰할 수 없는 데이터** 로 다루고, 하네스 검증 결과를 에이전트 출력보다 우선합니다. 점수 조작을 완전히 막지는 못하므로 `harness_verification`/`pytest` 같은 규칙 항목(가중치 ≥ 1)을 함께 두세요.
- presigned URL 은 기본 1시간이며 PR 코멘트에 붙으면 만료 전까지 누구나 열 수 있습니다. 로컬 저장소 경로는 밖에 내지 않습니다.
- Runtime 컨테이너는 non-root(`app`)로 실행됩니다.

**샌드박스**
- PUBLIC 모드는 아웃바운드 인터넷이 열립니다. 사내 코드에는 VPC 모드 + EFS/S3 Files 마운트를 권장합니다. 샌드박스 안에서 명령을 실행하는 것은 설계된 기능이므로 샌드박스 내부의 `..` 경로나 임의 명령은 차단 대상이 아닙니다.

## 비용

| 리소스 | 기준 | 비고 |
|---|---|---|
| Code Interpreter 세션 | 세션 활성 시간 과금 | 기본 30분 타임아웃, `mgr.close()` 로 즉시 종료 |
| Bedrock Claude Opus 5 | 토큰 | 에이전트·LLM 심사. `CWE_ENABLE_LLM_JUDGE=false` 로 심사 비활성 가능 |
| EC2 c8i.xlarge | 약 $0.19/h | Android 세션 동안만. 세션 종료 시 terminate |
| S3 / ECR | 저장 용량 | 수 MB 수준 |
| 스택 상시 비용 | $0 | 인스턴스·세션이 없으면 과금 없음 |

## 리소스 정리

```bash
./scripts/legacy/cleanup.sh --region us-east-1                  # 인스턴스 종료, 세션 정지, 스택 삭제 (기록 버킷은 보존)
./scripts/legacy/cleanup.sh --region us-east-1 --delete-bucket  # 기록 버킷까지 삭제
```

## 알려진 제약

- Google 공개 에뮬레이터 이미지는 API 30(Android 11)까지입니다. 최신 API 는 [android-emulator-container-scripts](https://github.com/google/android-emulator-container-scripts) 로 빌드해 ECR 에 올리고 `AndroidEmulatorProfile.image` 를 바꿉니다.
- Code Interpreter 세션은 최대 8시간이며 종료 시 데이터가 사라집니다. 세션 간 지속은 스냅샷 또는 EFS/S3 Files 마운트로 처리합니다.
- `executeCommand` 는 종료 코드가 0 이 아니면 출력을 `stderr` 로 돌려줍니다. `ExecResult.output` 이 둘을 합쳐 줍니다.

## 참고

- [AgentCore Code Interpreter](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-tool.html) · [AgentCore Evaluations](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/built-in-evaluators-overview.html)
- [Devin Android emulator support](https://docs.devin.ai/onboard-devin/environment/android-emulation)
- [Amazon EC2 nested virtualization](https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual)
