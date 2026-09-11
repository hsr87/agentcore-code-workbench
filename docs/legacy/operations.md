> Legacy: the earlier EC2 and CloudFormation deployment. It is kept in Korean for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# 운영 가이드

## 배포

```bash
./scripts/legacy/deploy.sh --region us-east-1                      # 기본: 인바운드 없음, SSM 포트 포워딩
./scripts/legacy/deploy.sh --region us-east-1 --allowed-cidr 10.0.0.0/8   # 고정 사무실/VPN CIDR 이 있을 때만
set -a && source .env && set +a
```

`deploy.sh` 는 멱등이다. 스택 변경이 없으면 그대로 통과하고, 이미지는 매번 다시 빌드·푸시한다. 스택 이름은 `CWE_STACK_NAME`(기본 `cwe-foundation`), 리소스 접두어는 `CWE_PROJECT_NAME`(기본 `cwe`)으로 바꾼다.

## 일상 점검

| 항목 | 명령 | 기대값 |
|---|---|---|
| 열린 샌드박스 세션 | `aws bedrock-agentcore list-code-interpreter-sessions --code-interpreter-identifier $CWE_CODE_INTERPRETER_ID --status READY` | 작업 중이 아니면 0개 |
| 남은 Android 호스트 | `aws ec2 describe-instances --filters Name=tag:project,Values=cwe Name=instance-state-name,Values=running` | 세션 종료 후 0개 |
| 기록 크기 | `aws s3 ls s3://<bucket>/cwe/ --recursive --summarize` | 세션당 수 MB |

세션을 닫지 않고 프로세스가 죽으면 샌드박스 세션은 타임아웃(기본 30분)까지, EC2 호스트는 terminate 될 때까지 과금된다. 회수 수단은 두 가지다.

- `cwe reap [--apply] [--max-age-hours 4]` — `project` 태그가 붙은 인스턴스 중 `cwe:expires-at` 이 지났거나(태그가 없으면 기동 4시간 초과) READY 상태로 4시간을 넘긴 샌드박스 세션을 회수한다. cron 또는 EventBridge Scheduler(컨테이너/Lambda) 로 10분 주기 실행을 권장한다.
- `scripts/cleanup.sh` — 전체 철거.

## 장애 대응

| 증상 | 원인 | 조치 |
|---|---|---|
| `pip install` 이 `pypi.org` 이름 해석 실패 | 관리형 `aws.codeinterpreter.v1` 사용 중 | `CWE_CODE_INTERPRETER_ID` 를 스택 출력(PUBLIC 커스텀)으로 설정 |
| `snapshot archive not found` | `readFiles` 경로 키 불일치 | SDK 래퍼가 정규화한다. 상대 경로로 요청했는지 확인 |
| Android `device did not boot within 600s` | 이미지 풀(4.4 GB) 지연 또는 KVM 미적용 | SSM 으로 `ls -l /dev/kvm; docker ps` 확인. CpuOptions 가 `enabled` 인지 `describe-instances` 로 확인 |
| device agent 401 / 403 | 토큰 또는 세션 헤더 불일치 | 호스트는 세션마다 새 토큰이다. 다른 세션의 IP 에 붙었는지, 풀 호스트가 이미 다른 세션에 `/bind` 되었는지 확인 |
| device agent 컨테이너가 바로 죽음 (`DEVICE_AGENT_TOKEN is required`) | SSM 파라미터 읽기 실패로 토큰이 비어 있음 | `/var/log/cloud-init-output.log` 에서 `aws ssm get-parameter` 오류 확인 (인스턴스 역할, `ProjectName` 접두어). 토큰 없이 기동하지 않는 것이 의도된 동작 |
| `cwe serve` 가 기동 거부 | `CWE_API_KEY` 없이 외부 주소(`--host 0.0.0.0`)에 바인드 | 키를 설정하거나 127.0.0.1 로. 개발용 예외는 `CWE_ALLOW_UNAUTHENTICATED=1` |
| device agent 연결 불가 (`ssm`) | 인스턴스가 SSM 에 미등록, 플러그인 없음 | `aws ssm describe-instance-information` 으로 Online 확인, `session-manager-plugin` 설치, 인스턴스 아웃바운드(443) 확인 |
| device agent 연결 불가 (`public`) | 보안 그룹 CIDR 과 실제 출구 IP 불일치(NAT 회전) | `ssm` 모드로 전환하거나 출구 IP 대역 전체를 `--allowed-cidr` 로 지정 |
| LLM 심사 `judge error` | 모델 접근 미활성 또는 리전 불일치 | Bedrock 콘솔에서 `anthropic.claude-opus-5` 활성, `AWS_REGION` 확인 |
| 에이전트 run 의 입력 토큰이 턴당 5만 이상 | 이 머신의 Claude Code 설정(MCP 서버, 플러그인)이 CLI 에 상속됨 | `build_options` 기본값 유지(`CLAUDE_CONFIG_DIR` 임시 디렉터리, `strict_mcp_config=True`). 직접 옵션을 만들면 `cwe_env()` 를 env 로 |
| 에이전트가 `CLINotFoundError` | Claude Agent SDK 의 번들 CLI 를 못 찾음 | `pip install claude-agent-sdk` 재설치(플랫폼 휠에 CLI 포함). 컨테이너는 linux/arm64 휠 |

## 로그와 관측성

- Code Interpreter 호출은 CloudTrail 과 AgentCore 콘솔의 Built-in tools 지표에 남는다.
- Runtime 으로 배포하면 `opentelemetry-instrument` 가 span 을 CloudWatch 로 보내고, `EvaluationClient.run(evaluator_ids, session_id, agent_id)` 로 세션을 평가할 수 있다.
- 실행 단위 기록은 `s3://<bucket>/cwe/<session_id>/events.jsonl`, 아티팩트는 `.../artifacts/`, 스냅샷은 `.../snap_*.tar.gz`.
- run 마다 `RunRecord.trace_id` 가 Code Interpreter 호출의 `traceParent` 로 전달되므로, CloudWatch 의 AgentCore 트레이스에서 같은 trace id 로 기록을 찾을 수 있다.
- 사후 채점: `python -c "from cwe.session import SessionManager; s=SessionManager().open_recorded('<session_id>'); print(s.evaluate(criteria, run_id=...))"` 또는 `POST /v1/recorded/{session_id}/evaluate`.

## Android 호스트 준비 시간과 비용

| 방식 | 세션 시작까지 (실측) | 상시 비용 |
|---|---|---|
| 기본 AMI (매번 이미지 풀) | 약 2분 (122초) | 없음 |
| 구운 AMI (`infra/bake_ami.py`) | 약 3.5분 (210초). EBS 스냅샷 지연 로드 때문에 부팅은 오히려 느리고, 이점은 Gradle 캐시(빌드 126초 → 101초) | AMI 스냅샷 저장 (월 수 달러) |
| 대기 풀 (`cwe android-pool`) | 12초 | 인스턴스 대수 × 시간당 약 $0.19 |

대기 풀 호스트에는 `cwe:expires-at` 태그가 있고 user data 의 `shutdown -h +N` 으로 스스로도 내려간다. `cwe reap` 이 만료분을 회수한다. 풀 토큰은 SSM 파라미터 `/<project>/pool/<instance>/token` 에 보관되며 세션이 호스트를 놓을 때 삭제된다. 클레임 직후 device agent 의 `/bind` 로 세션에 묶이므로 다른 세션의 요청은 403 이다.

`scripts/build_emulator_image.sh` 는 세션 호스트 프로파일이 아니라 `.env` 의 `CWE_ANDROID_BUILD_INSTANCE_PROFILE`(ECR push 권한이 있는 유일한 역할)로 빌드 호스트를 띄운다. 스택을 갱신하지 않은 `.env` 에는 이 값이 없으므로 `scripts/deploy.sh` 를 다시 돌린다.

## 쿼터

- Code Interpreter 세션 최대 8시간, 인라인 파일 업로드 100 MB. 큰 데이터는 EFS/S3 Files 마운트(VPC 모드).
- EC2 c8i 온디맨드 vCPU 한도가 낮은 신규 계정은 Service Quotas 에서 `Running On-Demand Standard instances` 를 올린다.

## 정리

```bash
./scripts/legacy/cleanup.sh --region us-east-1                  # 인스턴스·세션·스택
./scripts/legacy/cleanup.sh --region us-east-1 --delete-bucket  # 기록 버킷까지
```
