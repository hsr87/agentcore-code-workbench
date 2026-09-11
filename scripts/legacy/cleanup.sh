#!/usr/bin/env bash
# 실행 중인 샌드박스 세션·Android 호스트를 정리하고 기반 스택을 삭제한다. 기록 버킷은 Retain 이므로 --delete-bucket 을 줘야 지운다.
#   ./scripts/cleanup.sh [--region us-east-1] [--delete-bucket]
set -euo pipefail
cd "$(dirname "$0")/../.."
REGION="${AWS_REGION:-us-east-1}"; STACK="${CWE_STACK_NAME:-cwe-foundation}"; PROJECT="${CWE_PROJECT_NAME:-cwe}"; DELETE_BUCKET=false
while [[ $# -gt 0 ]]; do case "$1" in --region) REGION="$2"; shift 2;; --delete-bucket) DELETE_BUCKET=true; shift;; --stack) STACK="$2"; shift 2;; *) shift;; esac; done
out() { aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text 2>/dev/null || true; }

echo "1/4 terminate Android hosts tagged project=$PROJECT ..."
IDS=$(aws ec2 describe-instances --region "$REGION" --filters Name=tag:project,Values="$PROJECT" Name=instance-state-name,Values=pending,running,stopping,stopped --query "Reservations[].Instances[].InstanceId" --output text)
[[ -n "$IDS" ]] && aws ec2 terminate-instances --region "$REGION" --instance-ids $IDS >/dev/null && echo "  terminated: $IDS"
[[ -n "$IDS" ]] && aws ec2 wait instance-terminated --region "$REGION" --instance-ids $IDS

echo "2/4 stop open Code Interpreter sessions ..."
CI_ID=$(out CodeInterpreterId)
if [[ -n "$CI_ID" && "$CI_ID" != "None" ]]; then
  for S in $(aws bedrock-agentcore list-code-interpreter-sessions --region "$REGION" --code-interpreter-identifier "$CI_ID" --status READY --query "items[].sessionId" --output text); do
    aws bedrock-agentcore stop-code-interpreter-session --region "$REGION" --code-interpreter-identifier "$CI_ID" --session-id "$S" >/dev/null && echo "  stopped $S"; done
fi

echo "2b/4 delete host token parameters and baked AMIs tagged project=$PROJECT ..."
for P in $(aws ssm get-parameters-by-path --region "$REGION" --path "/$PROJECT" --recursive --query "Parameters[].Name" --output text 2>/dev/null); do
  aws ssm delete-parameter --region "$REGION" --name "$P" && echo "  deleted parameter $P"; done
for AMI in $(aws ec2 describe-images --region "$REGION" --owners self --filters Name=tag:project,Values="$PROJECT" --query "Images[].ImageId" --output text); do
  SNAPS=$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" --query "Images[0].BlockDeviceMappings[].Ebs.SnapshotId" --output text)
  aws ec2 deregister-image --region "$REGION" --image-id "$AMI" && echo "  deregistered $AMI"
  for S in $SNAPS; do aws ec2 delete-snapshot --region "$REGION" --snapshot-id "$S" && echo "  deleted snapshot $S"; done
done

BUCKET=$(out RecordingsBucket)
echo "3/4 delete stack $STACK ..."
aws cloudformation delete-stack --region "$REGION" --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --region "$REGION" --stack-name "$STACK" && echo "  deleted"

if $DELETE_BUCKET && [[ -n "$BUCKET" && "$BUCKET" != "None" ]]; then
  echo "4/4 delete bucket $BUCKET (all versions) ..."
  python3 - "$BUCKET" "$REGION" <<'PY'
import boto3, sys
b = boto3.resource("s3", region_name=sys.argv[2]).Bucket(sys.argv[1]); b.object_versions.delete(); b.delete(); print("  bucket deleted")
PY
else
  echo "4/4 bucket kept: $BUCKET (use --delete-bucket to remove)"
fi
