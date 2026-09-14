> Legacy: the earlier EC2 and CloudFormation deployment. It is kept for existing installations only. For the current EKS and Terraform release, see the top-level README.md and GUIDE.md.

# Operations guide

## Deployment

```bash
./scripts/legacy/deploy.sh --region us-east-1                      # default: no inbound, SSM port forwarding
./scripts/legacy/deploy.sh --region us-east-1 --allowed-cidr 10.0.0.0/8   # only when you have a fixed office/VPN CIDR
set -a && source .env && set +a
```

`deploy.sh` is idempotent. If there are no stack changes it passes through, and the image is rebuilt and pushed every time. Change the stack name with `CWE_STACK_NAME` (default `cwe-foundation`) and the resource prefix with `CWE_PROJECT_NAME` (default `cwe`).

## Routine checks

| Item | Command | Expected |
|---|---|---|
| Open sandbox sessions | `aws bedrock-agentcore list-code-interpreter-sessions --code-interpreter-identifier $CWE_CODE_INTERPRETER_ID --status READY` | 0 when no work is in progress |
| Remaining Android hosts | `aws ec2 describe-instances --filters Name=tag:project,Values=cwe Name=instance-state-name,Values=running` | 0 after sessions end |
| Recording size | `aws s3 ls s3://<bucket>/cwe/ --recursive --summarize` | A few MB per session |

If a process dies without closing its session, the sandbox session is billed until the timeout (30 minutes by default) and the EC2 host until it is terminated. There are two ways to reclaim them.

- `cwe reap [--apply] [--max-age-hours 4]`: reclaims instances with the `project` tag whose `cwe:expires-at` has passed (or that have been up for more than 4 hours if the tag is missing), and sandbox sessions that have been READY for more than 4 hours. Running it every 10 minutes via cron or EventBridge Scheduler (container/Lambda) is recommended.
- `scripts/cleanup.sh`: full teardown.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `pip install` fails to resolve `pypi.org` | Using the managed `aws.codeinterpreter.v1` | Set `CWE_CODE_INTERPRETER_ID` to the stack output (PUBLIC custom) |
| `snapshot archive not found` | `readFiles` path key mismatch | The SDK wrapper normalizes it. Check that the request used a relative path |
| Android `device did not boot within 600s` | Slow image pull (4.4 GB) or KVM not applied | Check `ls -l /dev/kvm; docker ps` over SSM. Confirm CpuOptions is `enabled` with `describe-instances` |
| device agent 401 / 403 | Token or session header mismatch | Each host gets a new token per session. Check whether you connected to another session's IP or the pool host was already bound to another session via `/bind` |
| device agent container dies immediately (`DEVICE_AGENT_TOKEN is required`) | Token is empty because the SSM parameter read failed | Check `/var/log/cloud-init-output.log` for `aws ssm get-parameter` errors (instance role, `ProjectName` prefix). Refusing to start without a token is the intended behavior |
| `cwe serve` refuses to start | Bound to an external address (`--host 0.0.0.0`) without `CWE_API_KEY` | Set a key or use 127.0.0.1. Development-only exception: `CWE_ALLOW_UNAUTHENTICATED=1` |
| Cannot connect to device agent (`ssm`) | Instance not registered with SSM, plugin missing | Confirm Online with `aws ssm describe-instance-information`, install `session-manager-plugin`, check instance outbound (443) |
| Cannot connect to device agent (`public`) | Security group CIDR does not match the actual egress IP (NAT rotation) | Switch to `ssm` mode or pass the whole egress IP range as `--allowed-cidr` |
| LLM judge `judge error` | Model access not enabled or region mismatch | Enable `anthropic.claude-opus-5` in the Bedrock console, check `AWS_REGION` |
| Agent run input tokens exceed 50k per turn | This machine's Claude Code configuration (MCP servers, plugins) is inherited by the CLI | Keep the `build_options` defaults (temporary `CLAUDE_CONFIG_DIR`, `strict_mcp_config=True`). If you build options yourself, use `cwe_env()` as env |
| Agent raises `CLINotFoundError` | The Claude Agent SDK's bundled CLI was not found | Reinstall with `pip install claude-agent-sdk` (the platform wheel includes the CLI). Containers use the linux/arm64 wheel |

## Logs and observability

- Code Interpreter calls appear in CloudTrail and in the Built-in tools metrics of the AgentCore console.
- When deployed on Runtime, `opentelemetry-instrument` sends spans to CloudWatch, and the session can be evaluated with `EvaluationClient.run(evaluator_ids, session_id, agent_id)`.
- Per-execution recordings are at `s3://<bucket>/cwe/<session_id>/events.jsonl`, artifacts under `.../artifacts/`, snapshots at `.../snap_*.tar.gz`.
- Each run's `RunRecord.trace_id` is passed as the `traceParent` of Code Interpreter calls, so the recording can be found by the same trace id in the AgentCore traces in CloudWatch.
- Post-hoc scoring: `python -c "from cwe.session import SessionManager; s=SessionManager().open_recorded('<session_id>'); print(s.evaluate(criteria, run_id=...))"` or `POST /v1/recorded/{session_id}/evaluate`.

## Android host startup time and cost

| Method | Time to session start (measured) | Standing cost |
|---|---|---|
| Default AMI (image pull every time) | About 2 minutes (122 s) | None |
| Baked AMI (`infra/bake_ami.py`) | About 3.5 minutes (210 s). Boot is actually slower because of EBS snapshot lazy loading; the benefit is the Gradle cache (build 126 s → 101 s) | AMI snapshot storage (a few dollars per month) |
| Standby pool (`cwe android-pool`) | 12 seconds | Number of instances × about $0.19 per hour |

Standby pool hosts have the `cwe:expires-at` tag and also shut themselves down via `shutdown -h +N` in user data. `cwe reap` reclaims expired ones. Pool tokens are kept in the SSM parameter `/<project>/pool/<instance>/token` and deleted when a session releases the host. Right after a claim the host is bound to the session via the device agent's `/bind`, so requests from other sessions get 403.

`scripts/build_emulator_image.sh` starts the build host with `CWE_ANDROID_BUILD_INSTANCE_PROFILE` from `.env` (the only role with ECR push permission), not the session host profile. A `.env` from before the stack update does not have this value, so run `scripts/deploy.sh` again.

## Quotas

- Code Interpreter sessions last at most 8 hours, inline file upload up to 100 MB. For large data, use EFS/S3 Files mounts (VPC mode).
- New accounts with a low EC2 c8i on-demand vCPU limit should raise `Running On-Demand Standard instances` in Service Quotas.

## Cleanup

```bash
./scripts/legacy/cleanup.sh --region us-east-1                  # instances, sessions, stack
./scripts/legacy/cleanup.sh --region us-east-1 --delete-bucket  # also the recordings bucket
```
