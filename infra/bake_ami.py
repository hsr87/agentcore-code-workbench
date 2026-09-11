"""Bake an emulator host AMI so a session does not pay the image pull and SDK download on every start.

    python infra/bake_ami.py [--emulator-image ...] [--warm-gradle]

Launches an instance, pre-pulls the emulator image, device agent, and Android SDK build image (optionally: builds the sample app once to warm the Gradle cache),
creates an AMI, then terminates. Using the resulting AMI ID as CWE_ANDROID_AMI_ID in .env cuts session start time from 5-7 minutes down to 1-2 minutes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import boto3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from cwe.android import EC2EmulatorHost  # noqa: E402
from cwe.config import get_settings  # noqa: E402

BAKE_USER_DATA = """#!/bin/bash
set -x
for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
mkdir -p /opt/cwe/builds /opt/cwe/gradle
aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {registry}
docker pull {agent_image}
docker pull {emulator_image}
docker pull {build_image}
{warm}
touch /opt/cwe/BAKED
"""
WARM_GRADLE = """# Warm the Gradle cache: build the sample app once (the pre-downloaded dependencies stay in the AMI)
mkdir -p /opt/cwe/warm && cd /opt/cwe/warm && aws s3 cp {sample_url} sample.tar.gz && tar -xzf sample.tar.gz && rm sample.tar.gz
docker run --rm -v /opt/cwe/warm:/work -v /opt/cwe/gradle:/root/.gradle -w /work {build_image} sh -c "chmod +x ./gradlew && ./gradlew --no-daemon -q assembleDebug assembleDebugAndroidTest" > /var/log/cwe-warm.log 2>&1
rm -rf /opt/cwe/warm
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--warm-gradle", action="store_true", help="build the sample app to warm the Gradle cache (needs S3 storage)")
    ap.add_argument("--emulator-image", default="us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:latest")
    ap.add_argument("--name", default=None)
    a = ap.parse_args()
    st = get_settings(); host = EC2EmulatorHost.from_env(use_pool=False)
    ec2, ssm = host.ec2, host.ssm
    base_ami = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id")["Parameter"]["Value"]
    warm = ""
    if a.warm_gradle:
        import tarfile, tempfile

        s3 = boto3.client("s3", region_name=st.region)
        assert st.storage_uri.startswith("s3://"), "--warm-gradle needs CWE_STORAGE_URI=s3://..."
        bucket, _, prefix = st.storage_uri[5:].partition("/")
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as f:
            with tarfile.open(f.name, "w:gz") as tar:
                tar.add("examples/android-sample", arcname=".")
            key = f"{prefix.strip('/')}/_bake/android-sample.tar.gz"
            s3.upload_file(f.name, bucket, key)
        warm = WARM_GRADLE.format(sample_url=f"s3://{bucket}/{key}", build_image=host.build_image)
    user_data = BAKE_USER_DATA.format(region=st.region, registry=host.agent_image.split("/")[0], agent_image=host.agent_image,
                                      emulator_image=a.emulator_image, build_image=host.build_image, warm=warm)
    r = ec2.run_instances(ImageId=base_ami, InstanceType=host.instance_type, MinCount=1, MaxCount=1, CpuOptions={"NestedVirtualization": "enabled"},
                          NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": host.subnet_id, "Groups": [host.security_group], "AssociatePublicIpAddress": True}],
                          IamInstanceProfile={"Name": host.instance_profile}, UserData=user_data, MetadataOptions={"HttpTokens": "required"},
                          BlockDeviceMappings=[{"DeviceName": "/dev/xvda", "Ebs": {"VolumeSize": 60, "VolumeType": "gp3", "DeleteOnTermination": True}}],
                          TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "cwe-ami-bake"}, {"Key": "project", "Value": host.project}]}])
    iid = r["Instances"][0]["InstanceId"]; print("bake instance", iid, flush=True)
    ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
    # wait for the completion marker via SSM
    for i in range(120):
        info = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [iid]}])["InstanceInformationList"]
        if info and info[0].get("PingStatus") == "Online":
            break
        time.sleep(10)
    t0 = time.time()
    while time.time() - t0 < 2400:
        cid = ssm.send_command(InstanceIds=[iid], DocumentName="AWS-RunShellScript", Parameters={"commands": ["test -f /opt/cwe/BAKED && echo BAKED || (tail -2 /var/log/cloud-init-output.log; echo WAIT)"]})["Command"]["CommandId"]
        time.sleep(8)
        out = ssm.get_command_invocation(CommandId=cid, InstanceId=iid).get("StandardOutputContent", "")
        if "BAKED" in out:
            break
        print("  waiting:", out.strip().splitlines()[-1][:100] if out.strip() else "...", flush=True)
        time.sleep(30)
    else:
        raise SystemExit("bake did not finish in time")
    # bring the containers down and create the image (user data brings them back up on boot)
    # wipe the ECR login token (12h) and shell history so they don't stay in the image
    ssm.send_command(InstanceIds=[iid], DocumentName="AWS-RunShellScript", Parameters={"commands": [
        "docker rm -f cwe-device-agent 2>/dev/null; docker ps -aq | xargs -r docker rm -f",
        "docker logout >/dev/null 2>&1 || true; rm -f /root/.docker/config.json /root/.bash_history; rm -rf /var/lib/cloud/instances/*; sync"]})
    time.sleep(10)
    name = a.name or f"cwe-android-host-{time.strftime('%Y%m%d-%H%M')}"
    ami = ec2.create_image(InstanceId=iid, Name=name, Description="code-workflow-emulator Android host: emulator + device agent + Android SDK build image pre-pulled",
                           TagSpecifications=[{"ResourceType": "image", "Tags": [{"Key": "project", "Value": host.project}]}])["ImageId"]
    print("creating AMI", ami, flush=True)
    ec2.get_waiter("image_available").wait(ImageIds=[ami], WaiterConfig={"Delay": 15, "MaxAttempts": 80})
    ec2.terminate_instances(InstanceIds=[iid])
    print(json.dumps({"ami_id": ami, "name": name, "bake_seconds": round(time.time() - t0)}))
    print(f"\nAdd to .env:  CWE_ANDROID_AMI_ID={ami}")


if __name__ == "__main__":
    main()
