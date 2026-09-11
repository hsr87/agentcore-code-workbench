> Legacy: the earlier EC2 and CloudFormation deployment. It is kept in Korean for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# 아키텍처

## 1. 설계 목표

1. 개발자가 격리된 환경에서 코드를 실행하고, 그 과정을 **재현 가능한 기록**으로 남기고, **같은 기준으로 채점**한다.
2. 코딩 에이전트(Claude Agent SDK, 내장 또는 사용자의 것)의 결과를 사람이 검토 가능한 증빙(트랜스크립트·스크린샷·영상)과 함께 제공한다.
3. 세션 격리·인증·관측성·평가는 AWS 관리형(AgentCore)에 맡기고, 관리형이 못 하는 것(KVM)만 EC2 로 분리한다.

## 2. 구성요소

| 구성요소 | 구현 | AWS |
|---|---|---|
| Session | `DevSession` = 샌드박스 + 프로파일 + 기록기 + 평가기 (+ 디바이스) | Code Interpreter 세션 (microVM) |
| Profile | `EmulatorProfile`: 런타임, 패키지, env, 셋업 명령, mock 서비스 | 세션 시작 시 프로비저닝 |
| Recorder | `events.jsonl` (exec / message / note / snapshot / eval), 아티팩트 | S3 (또는 로컬), Memory |
| Snapshot | 워크스페이스 tar.gz | S3 |
| Evaluator | 규칙 → LLM 심사 → AgentCore Evaluations | Bedrock, Evaluations |
| Agent | Claude Agent SDK + 세션 도구 MCP 서버 (코드 10개, Android 14개) + PreToolUse 예산 훅 | Bedrock (CLAUDE_CODE_USE_BEDROCK), Runtime |
| Device Lab | `EC2EmulatorHost` + `device_agent` | EC2 c8i (nested virt), ECR |

## 3. 데이터 흐름

```
begin_run ─► write_files / run_command / run_code / device_action ─► end_run ─► evaluate
     │              │ 각 호출마다 ExecResult 정규화 후 Recorder.record_exec           │
     │              └─ 아티팩트(스크린샷·영상)는 store.put → run.artifacts             │
     └─ note(begin_run) ...................................................... eval 이벤트
```

- `ExecResult` 는 Code Interpreter 스트림의 `structuredContent`(stdout, stderr, exitCode, executionTime, taskId, taskStatus)를 정규화한 것이다. 종료 코드가 0 이 아니면 서비스가 출력을 stderr 로 돌려주므로 `output` 프로퍼티가 둘을 합친다.
- `readFiles` 는 `file:///path` URI 를 돌려주므로 SDK 가 벗긴 뒤에도 선행 `/` 가 남는다. `AgentCoreSandbox.read_files` 가 요청 경로 기준으로 정규화한다.
- 세션은 `<root>/workspace` 를 작업 디렉토리로 쓰며 모든 명령을 `cd <workspace> && export ENV && <cmd>` 로 감싼다. `executeCommand` 의 cwd 는 문서화되어 있지 않아 명시적으로 고정한다.

## 4. 평가 집계

```
score = Σ(item.score × weight) / Σ(weight)
passed = score ≥ pass_threshold AND (weight ≥ 1 인 규칙 항목 모두 passed)
```

LLM 심사관은 트랜스크립트(작성 파일 내용 포함)와 루브릭을 받아 JSON 판정을 낸다. 파일 내용을 트랜스크립트에 포함하는지가 심사 품질을 크게 좌우한다(실측: 미포함 시 0.34, 포함 시 0.90).

## 4a. 하네스: 세 가지 위임

| 확률이 드러나는 자리 | 위임 대상 | 구현 |
|---|---|---|
| 컨텍스트 | 코드 | 도구 결과를 `summarize_output` 으로 접어 반환(기본 800자), 전체는 `DevSession.full_output(ref)` 와 기록. `write_and_run` 은 파일 쓰기+실행을 한 호출로 |
| 검증 | 하네스 | `DevSession.verify(command, mode)` 가 검증 명령을 직접 실행. `fresh` 모드는 스냅샷을 새 세션에 복원해 실행. pytest 규칙은 이 결과만 본다 |
| 실행 | 규칙 | `RunBudget` 을 `begin_run` 에 걸면 `_record` 와 도구 호출 전 `check_budget` 이 실행 횟수·시간·비용을 검사하고 초과 시 `BudgetExceeded` 로 run 을 `cancelled` 처리 |

## 5. Android Device Lab

```
DevSession.start_android(profile, EC2EmulatorHost.from_env())
   └─ run_instances(c8i.xlarge, CpuOptions.NestedVirtualization=enabled, user data)
        user data: modprobe kvm → docker run device-agent(--network host, docker.sock) → docker run android-emulator(--device /dev/kvm)
   └─ (ssm) aws ssm start-session AWS-StartPortForwardingSession → 127.0.0.1:<local> → 인스턴스 127.0.0.1:8080
   └─ AndroidDevice(base_url, Bearer <per-host token>, x-cwe-session <session_id>).wait_boot()
```

보안 기본값: 보안 그룹 인바운드 없음(같은 SG 자기참조 규칙만), device agent 는 127.0.0.1 바인드, IMDSv2 필수(hop limit 1), 호스트별 토큰(SSM SecureString, 부팅 후 삭제, 없으면 기동 거부) + 세션 바인딩(풀 호스트는 `/bind`), 모든 엔드포인트 인증, 호스트 경로 입력은 `/opt/cwe/builds` 아래로 제한, Gradle 태스크는 argv 로만, user data 값은 `shlex.quote`, `shutdown -h +N` 자체 수명 상한, 세션 종료 시 terminate. 남은 설계상 한계는 docker 소켓 마운트(README 보안 참고 사항).

device agent 는 docker 소켓으로 에뮬레이터 컨테이너의 bridge IP 를 찾아 `adb connect` 한다. 세션 종료 시 인스턴스를 terminate 한다. 호스트 대안 검토 결과:

| 후보 | 결과 |
|---|---|
| AgentCore Code Interpreter / Runtime | `/dev/kvm` 없음, Java·디스플레이 없음 (실측) |
| SageMaker Processing | privileged·디바이스 매핑 불가 |
| AWS Batch (EC2, c8i) | 런치 템플릿 CpuOptions 를 관리 템플릿에 반영하지 않아 KVM 없음. metal 인스턴스만 가능 |
| EC2 직접 기동 | 동작. 채택 |
| EKS 관리형 노드 그룹 | 런치 템플릿 금지 항목에 CpuOptions 없음 → 플릿 확장 시 권장 (미검증) |

### 5a. Devin 에뮬레이터 기능 대응 (전체)

| Devin | 구현 |
|---|---|
| adb 조작, Computer Use | device agent HTTP + 스크린샷 비전 + UI 덤프 좌표 |
| 녹화 증빙 | screenrecord → S3, `attach_evidence` 로 PR 코멘트 |
| 계측 테스트 | `/instrument` (샘플 앱 Espresso 로 실검증) |
| 블루프린트 스냅샷 VM | `infra/bake_ami.py` AMI + `cwe android-pool` 대기 풀 |
| 여러 AVD / API 레벨 | `scripts/build_emulator_image.sh`, 프로파일 `count`/`images`, `for_device(i)` |
| 루프 안 앱 빌드 | `android_build` (호스트 Gradle 컨테이너, 스냅샷 전달) |
| 스킬 | `cwe/skills.py` (증류 → 승인 → 온디맨드 로드) |
| 자동 설정, 템플릿 | `cwe/android_setup.py`, `examples/profiles/android/*.yaml` |
| Desktop 실시간 화면 | `/view` MJPEG 뷰어 (SSM 터널) |

## 6. 다중 사용자 확장

- **세션 플레인**: AgentCore Runtime(세션당 microVM) + Identity(인바운드 JWT) + Memory(actor 별) + Gateway(디바이스 도구를 MCP 로). 이미 다중 사용자 격리가 된다.
- **디바이스 플릿**: EKS 노드 그룹(c8i nested virt 또는 metal) 위에 Pod = emulator + device-agent 사이드카. Pod 안에서는 네트워크 네임스페이스를 공유하므로 docker 소켓 탐색이 필요 없다. 워밍 풀로 첫 부팅 5~7분을 수 초로 줄인다. Device Broker 가 세션 → Pod 할당, 쿼터, 유휴 회수를 맡는다.
- **기록·아티팩트**: 세션 ID 프리픽스로 S3 에 적재. Code Interpreter 세션 API 에는 태그가 없어 비용 배분은 세션 ID 프리픽스로 한다.

## 7. AgentCore 만으로 되지 않는 것

KVM 이 있는 세션(또는 관리형 Android 디바이스 도구), 사용자 정의 샌드박스 이미지와 세션 템플릿, 세션 스냅샷과 일시정지, 세션 포트 노출, Code Interpreter 세션 녹화. 이 항목들은 EC2 호스트, 프로파일 스크립트, tar 스냅샷, 자체 기록기로 우회했다.
