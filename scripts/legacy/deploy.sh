#!/usr/bin/env bash
# code-workflow-emulator: 기반 리소스 배포 + device agent 이미지 빌드/푸시 + .env 생성
#   ./scripts/deploy.sh [--region us-east-1] [--no-android] [--vpc vpc-xxx] [--allowed-cidr 10.0.0.0/8]
# 기본은 인바운드를 열지 않고 SSM Session Manager 포트 포워딩으로 device agent 에 접속한다 (session-manager-plugin 필요).
# --allowed-cidr 는 사무실/VPN 고정 CIDR 이 있을 때만 opt-in 으로 쓴다.
set -euo pipefail
cd "$(dirname "$0")/../.."

REGION="${AWS_REGION:-us-east-1}"; STACK="${CWE_STACK_NAME:-cwe-foundation}"; PROJECT="${CWE_PROJECT_NAME:-cwe}"
ANDROID=true; ALLOWED_CIDR=""; VPC_ID=""; CLI="${CWE_CONTAINER_CLI:-finch}"
while [[ $# -gt 0 ]]; do case "$1" in
  --region) REGION="$2"; shift 2;; --allowed-cidr) ALLOWED_CIDR="$2"; shift 2;; --vpc) VPC_ID="$2"; shift 2;;
  --no-android) ANDROID=false; shift;; --stack) STACK="$2"; shift 2;; *) echo "unknown arg $1"; exit 1;; esac; done

[[ -z "$VPC_ID" ]] && VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true --query "Vpcs[0].VpcId" --output text)
ACCESS="ssm"; [[ -n "$ALLOWED_CIDR" ]] && ACCESS="public"
if [[ "$ACCESS" == "ssm" ]] && ! command -v session-manager-plugin >/dev/null; then
  echo "session-manager-plugin 이 없습니다. https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html" >&2; exit 1
fi
echo "region=$REGION stack=$STACK vpc=$VPC_ID access=$ACCESS allowed_cidr=${ALLOWED_CIDR:-<none>} android=$ANDROID"

echo "1/3 CloudFormation ..."
aws cloudformation deploy --region "$REGION" --stack-name "$STACK" --template-file infra/cfn/foundation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ProjectName="$PROJECT" VpcId="$VPC_ID" AllowedCidr="$ALLOWED_CIDR" CreateAndroidResources="$ANDROID" \
  --tags project="$PROJECT" --no-fail-on-empty-changeset
out() { aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
CI_ID=$(out CodeInterpreterId); BUCKET=$(out RecordingsBucket)

IMAGE=""; PROFILE=""; SG=""; SUBNET=""; BUILD_PROFILE=""
if $ANDROID; then
  echo "2/3 device agent image ($CLI) ..."
  REPO=$(out DeviceAgentRepositoryUri); IMAGE="$REPO:latest"; PROFILE=$(out AndroidInstanceProfile); SG=$(out AndroidSecurityGroupId); EMU_REPO=$(out EmulatorImageRepositoryUri)
  BUILD_PROFILE=$(out EmulatorImageBuildInstanceProfile)
  SUBNET=$(aws ec2 describe-subnets --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" Name=default-for-az,Values=true --query "Subnets[0].SubnetId" --output text)
  [[ "$SUBNET" == "None" ]] && SUBNET=$(aws ec2 describe-subnets --region "$REGION" --filters Name=vpc-id,Values="$VPC_ID" --query "Subnets[0].SubnetId" --output text)
  aws ecr get-login-password --region "$REGION" | "$CLI" login --username AWS --password-stdin "${REPO%%/*}" >/dev/null
  "$CLI" build --platform linux/amd64 -t "$IMAGE" device_agent/
  "$CLI" push "$IMAGE"
else
  echo "2/3 (android skipped)"
fi

echo "3/3 .env ..."
MANAGED="CWE_ANDROID_BACKEND CWE_ANDROID_EMULATOR_REPO CWE_ANDROID_BUILD_INSTANCE_PROFILE AWS_REGION CWE_CODE_INTERPRETER_ID CWE_STORAGE_URI CWE_SESSION_TIMEOUT_SECONDS CWE_JUDGE_MODEL CWE_AGENT_MODEL CWE_ENABLE_LLM_JUDGE CWE_ANDROID_SUBNET_ID CWE_ANDROID_SECURITY_GROUP_ID CWE_ANDROID_INSTANCE_PROFILE CWE_ANDROID_DEVICE_AGENT_IMAGE CWE_ANDROID_INSTANCE_TYPE CWE_ANDROID_ACCESS"
EXTRA=""
if [[ -f .env ]]; then  # 사용자가 추가한 키(CWE_MEMORY_ID, CWE_API_KEY 등)는 보존
  while IFS= read -r line; do
    key="${line%%=*}"; [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    grep -qw "$key" <<<"$MANAGED" || EXTRA+="$line"$'\n'
  done < .env
fi
cat > .env <<ENV
AWS_REGION=$REGION
CWE_CODE_INTERPRETER_ID=$CI_ID
CWE_STORAGE_URI=s3://$BUCKET/cwe
CWE_SESSION_TIMEOUT_SECONDS=1800
CWE_JUDGE_MODEL=anthropic.claude-opus-5
CWE_AGENT_MODEL=us.anthropic.claude-opus-5
CWE_ENABLE_LLM_JUDGE=true
# Android emulator host (EC2, nested virtualization)
CWE_ANDROID_BACKEND=ec2
CWE_ANDROID_SUBNET_ID=$SUBNET
CWE_ANDROID_SECURITY_GROUP_ID=$SG
CWE_ANDROID_INSTANCE_PROFILE=$PROFILE
CWE_ANDROID_DEVICE_AGENT_IMAGE=$IMAGE
CWE_ANDROID_INSTANCE_TYPE=c8i.xlarge
# ssm: 인바운드 없이 SSM 포트 포워딩(기본) | public: --allowed-cidr 로 연 공인 IP | private: 같은 SG 의 VPC 내부 에이전트
CWE_ANDROID_ACCESS=$ACCESS
CWE_ANDROID_EMULATOR_REPO=${EMU_REPO:-}
CWE_ANDROID_BUILD_INSTANCE_PROFILE=${BUILD_PROFILE:-}
ENV
[[ -n "$EXTRA" ]] && { echo "# preserved"; printf "%s" "$EXTRA"; } >> .env
echo "wrote .env  ->  set -a; source .env; set +a"
