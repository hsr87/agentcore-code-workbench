#!/usr/bin/env bash
# Build an Android emulator container image for API 30+ on an EC2 host (x86_64, docker) and push it to ECR.
#   ./scripts/build_emulator_image.sh --api 34 [--variant google_apis] [--instance-id i-xxx]
# Uses Google's android-emulator-container-scripts (emu-docker). Running it means accepting the Android SDK license, so review it before running.
# Result: $CWE_ANDROID_EMULATOR_REPO:<api>-<variant>-x64  -> set as AndroidEmulatorProfile.image
set -euo pipefail
cd "$(dirname "$0")/.."
API=34; VARIANT=google_apis; IID=""; REGION="${AWS_REGION:-us-east-1}"
while [[ $# -gt 0 ]]; do case "$1" in --api) API="$2"; shift 2;; --variant) VARIANT="$2"; shift 2;; --instance-id) IID="$2"; shift 2;; *) shift;; esac; done
[[ -z "${CWE_ANDROID_EMULATOR_REPO:-}" ]] && { echo "CWE_ANDROID_EMULATOR_REPO is not set (run scripts/deploy.sh, then load .env)"; exit 1; }
BUILD_PROFILE="${CWE_ANDROID_BUILD_INSTANCE_PROFILE:-}"   # only this dedicated profile has image-push permission (the session host role does not)
[[ -z "$BUILD_PROFILE" ]] && { echo "CWE_ANDROID_BUILD_INSTANCE_PROFILE is not set (re-run scripts/deploy.sh to update the stack)"; exit 1; }
PROJECT="${CWE_PROJECT_NAME:-cwe}"
TAG="$CWE_ANDROID_EMULATOR_REPO:${API}-${VARIANT}-x64"; REGISTRY="${CWE_ANDROID_EMULATOR_REPO%%/*}"
OWN=false
if [[ -z "$IID" ]]; then
  echo "launching a build host (terminated when done)"
  AMI=$(aws ssm get-parameter --region "$REGION" --name /aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id --query Parameter.Value --output text)
  IID=$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" --instance-type c8i.xlarge --subnet-id "$CWE_ANDROID_SUBNET_ID" --security-group-ids "$CWE_ANDROID_SECURITY_GROUP_ID" \
    --iam-instance-profile Name="$BUILD_PROFILE" --associate-public-ip-address --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1 \
    --instance-initiated-shutdown-behavior terminate \
    --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":80,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=cwe-emulator-image-build},{Key=project,Value=$PROJECT}]" --query "Instances[0].InstanceId" --output text)
  OWN=true; echo "instance $IID"; aws ec2 wait instance-running --region "$REGION" --instance-ids "$IID"
  until aws ssm describe-instance-information --region "$REGION" --filters "Key=InstanceIds,Values=$IID" --query "InstanceInformationList[0].PingStatus" --output text 2>/dev/null | grep -q Online; do sleep 10; done
fi
PARAMS=$(python3 - "$API" "$VARIANT" "$TAG" "$REGION" "$REGISTRY" <<'PY'
import json, sys
api, variant, tag, region, registry = sys.argv[1:]
# emu-docker selects an image using the "letter-code tag arch" format (e.g. "U google_apis x86_64" = API 34)
letters = {26: "O", 27: "O", 28: "P", 29: "Q", 30: "R", 31: "S", 32: "S", 33: "T", 34: "U", 35: "V", 36: "W"}
letter = letters.get(int(api), "U")
script = f"""set -eo pipefail
(dnf install -y python3.11 python3.11-pip git || yum install -y python3.11 python3.11-pip git) >/dev/null 2>&1
# emu-docker is not on PyPI. Install it from Google's repo (EMU_DOCKER_REF can pin a commit: supply-chain pinning)
cd /opt && rm -rf android-emulator-container-scripts && git clone -q https://github.com/google/android-emulator-container-scripts
cd android-emulator-container-scripts && git checkout -q "${{EMU_DOCKER_REF:-master}}" && python3.11 -m pip install -q . 2>&1 | tail -2
export PATH=$PATH:/usr/local/bin:$(python3.11 -m site --user-base)/bin
cd /opt && rm -rf emu-build && mkdir emu-build && cd emu-build
emu-docker licenses --accept 2>&1 | tail -3      # accepts the Android SDK license (the script's runner is the one agreeing)
# --repo defaults to a Google registry prefix, so pin a local name with --repo "" and --name, then re-tag it to our ECR tag
emu-docker create --no-metrics stable "{letter} {variant} x86_64" --repo "" --name "cwe-emu-{api}" 2>&1 | tail -8
docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}} {{{{.Size}}}}' | head -8
SRC=$(docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}}' | grep -E '^cwe-emu-{api}:' | head -1)
[ -n "$SRC" ] || {{ echo "built image not found"; exit 1; }}
docker tag "$SRC" "{tag}"
echo "built image: $SRC -> {tag}"
aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {registry}
docker push "{tag}" | tail -2
docker logout {registry} >/dev/null 2>&1 || true
echo IMAGE_PUSHED"""
print(json.dumps({"commands": [script], "executionTimeout": ["3600"]}))
PY
)
CID=$(aws ssm send-command --region "$REGION" --instance-ids "$IID" --document-name AWS-RunShellScript --timeout-seconds 3600 --parameters "$PARAMS" --query Command.CommandId --output text)
echo "ssm command $CID (build takes 10-20 minutes)"
while true; do
  ST=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$IID" --query Status --output text 2>/dev/null || echo Pending)
  case "$ST" in Success|Failed|Cancelled|TimedOut) break;; esac; sleep 30; printf .
done; echo
aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$IID" --query "[Status,StandardOutputContent,StandardErrorContent]" --output text | tail -40
$OWN && aws ec2 terminate-instances --region "$REGION" --instance-ids "$IID" >/dev/null && echo "build host terminated"
[[ "$ST" == "Success" ]] || { echo "image build failed (status=$ST)"; exit 1; }
echo "image: $TAG"
