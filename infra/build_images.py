"""Build and push the EKS sidecar images, optionally mirror the emulator image into ECR, and write .env.eks.

    python infra/build_images.py --tag v1                 # device agent + builder sidecars
    python infra/build_images.py --mirror-emulator        # copy the public emulator image into ECR under an immutable tag
    python infra/build_images.py --tag v1 --mirror-emulator

.env is never overwritten; keys already present in .env.eks that this run does not generate are preserved.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EMULATOR_IMAGE = "us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:latest"
TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def scan_findings(repository: str, tag: str, region: str, timeout: int = 600) -> dict[str, int]:
    """Wait for the scan-on-push result and return severity counts, e.g. {"CRITICAL": 2, "HIGH": 5}.

    Uses the AWS CLI like the rest of this script, so it runs under the system python3 that deploy.sh invokes."""
    import time

    deadline = time.monotonic() + timeout
    while True:
        result = subprocess.run(["aws", "ecr", "describe-image-scan-findings", "--region", region, "--repository-name", repository,
                                 "--image-id", f"imageTag={tag}", "--output", "json"], capture_output=True, text=True)
        if result.returncode == 0:
            response = json.loads(result.stdout)
            status = response["imageScanStatus"]["status"]
            if status == "COMPLETE":
                return {k: int(v) for k, v in response.get("imageScanFindings", {}).get("findingSeverityCounts", {}).items()}
            if status in ("FAILED", "UNSUPPORTED_IMAGE"):
                print(f"ECR scan {repository}:{tag} {status}: {response['imageScanStatus'].get('description', '')}")
                return {}
        elif "ScanNotFoundException" not in result.stderr:
            raise SystemExit(f"describe-image-scan-findings failed: {result.stderr.strip()[:300]}")
        if time.monotonic() > deadline:
            raise SystemExit(f"ECR scan for {repository}:{tag} did not complete within {timeout}s")
        time.sleep(10)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", help="ECR tag for the device-agent and builder images (tags are immutable)")
    parser.add_argument("--mirror-emulator", action="store_true",
                        help="pull the emulator image for linux/amd64 and push it to the android-emulator ECR repository")
    parser.add_argument("--emulator-source", default=PUBLIC_EMULATOR_IMAGE, help="image to mirror (default: public API 30 image)")
    parser.add_argument("--emulator-tag", help="ECR tag for the mirrored emulator image (default: 30-google-x64-<UTC date>)")
    parser.add_argument("--allow-critical", action="store_true",
                        help="write .env.eks even if the ECR scan of a sidecar image reports CRITICAL findings")
    args = parser.parse_args()
    if not args.tag and not args.mirror_emulator:
        parser.error("give --tag to build the sidecars, --mirror-emulator to mirror the emulator image, or both")
    if args.tag and not TAG_RE.fullmatch(args.tag):
        parser.error("invalid image tag")
    emulator_tag = args.emulator_tag or f"30-google-x64-{datetime.now(timezone.utc):%Y%m%d}"
    if not TAG_RE.fullmatch(emulator_tag):
        parser.error("invalid emulator tag")

    output = json.loads(subprocess.check_output(
        ["terraform", f"-chdir={ROOT / 'infra/terraform/foundation'}", "output", "-json"], text=True
    ))
    values = {k: v["value"] for k, v in output.items()}
    repos = values["repositories"]
    registry = repos["device-agent"].split("/")[0]
    cli = os.environ.get("CWE_CONTAINER_CLI", "finch")
    password = subprocess.check_output(["aws", "ecr", "get-login-password", "--region", values["region"]])
    subprocess.run([cli, "login", "--username", "AWS", "--password-stdin", registry], input=password, check=True)

    env = {
        "AWS_REGION": values["region"],
        "CWE_PROJECT_NAME": values["project_name"],
        "CWE_CODE_INTERPRETER_ID": values["code_interpreter_id"],
        "CWE_STORAGE_URI": f"s3://{values['recordings_bucket']}/cwe",
        "CWE_ANDROID_BACKEND": "eks",
        "CWE_EKS_CONTEXT": values["cluster_arn"],
        "CWE_EKS_CLUSTER_NAME": values["cluster_name"],
        "CWE_OPERATOR_ROLE_ARN": values["operator_role_arn"],
        "CWE_EKS_NAMESPACE": "cwe",
        "CWE_EKS_ACCESS": "port-forward",
        "CWE_ANDROID_EMULATOR_REPO": repos["android-emulator"],
    }
    if args.tag:
        for key, dockerfile in (("device-agent", "Dockerfile"), ("android-builder", "Dockerfile.builder")):
            image = f"{repos[key]}:{args.tag}"
            subprocess.run([cli, "build", "--platform", "linux/amd64", "-f", str(ROOT / "device_agent" / dockerfile),
                            "-t", image, str(ROOT / "device_agent")], check=True)
            subprocess.run([cli, "push", image], check=True)
        # ECR scans on push. A sidecar runs next to customer code, so a CRITICAL finding blocks the rollout by default.
        for key in ("device-agent", "android-builder"):
            counts = scan_findings(repos[key].split("/")[-1], args.tag, values["region"])
            print(f"ECR scan {repos[key].split('/')[-1]}:{args.tag}: {counts or 'no findings'}")
            if counts.get("CRITICAL") and not args.allow_critical:
                raise SystemExit(f"{key}:{args.tag} has {counts['CRITICAL']} CRITICAL findings; fix the base image or pass --allow-critical")
        env["CWE_ANDROID_DEVICE_AGENT_IMAGE"] = f"{repos['device-agent']}:{args.tag}"
        env["CWE_EKS_BUILDER_IMAGE"] = f"{repos['android-builder']}:{args.tag}"
    if args.mirror_emulator:
        target = f"{repos['android-emulator']}:{emulator_tag}"
        # Emulator nodes are x86_64; pull that platform explicitly so an arm64 workstation does not mirror the wrong one.
        subprocess.run([cli, "pull", "--platform", "linux/amd64", args.emulator_source], check=True)
        subprocess.run([cli, "tag", args.emulator_source, target], check=True)
        subprocess.run([cli, "push", target], check=True)
        digest = subprocess.run([cli, "image", "inspect", args.emulator_source, "--format", "{{index .RepoDigests 0}}"],
                                capture_output=True, text=True).stdout.strip()
        print(f"Mirrored {args.emulator_source} ({digest or 'digest unavailable'}) -> {target}")
        env["CWE_ANDROID_EMULATOR_IMAGE"] = target

    path = ROOT / ".env.eks"
    # Preserve user-added settings and values from earlier runs; values generated now take precedence.
    extra = []
    if path.exists():
        for line in path.read_text().splitlines():
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line) and line.split("=", 1)[0] not in env:
                extra.append(line)
    text = "\n".join([*(f"{k}={shlex.quote(v)}" for k, v in env.items()), *extra]) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)
    path.chmod(0o600)
    print("Wrote .env.eks; run: set -a; source .env.eks; set +a")


if __name__ == "__main__":
    main()
