"""EKS access without the AWS CLI: a kubeconfig writer and an exec credential plugin.

AgentCore Runtime containers carry kubectl but no `aws` binary. `ensure_kubeconfig` describes the
cluster with boto3 and writes a kubeconfig whose exec plugin is this module, so kubectl obtains a
token from the container's own IAM credentials (the Runtime execution role).

The token format is the one `aws eks get-token` produces: a presigned STS GetCallerIdentity URL
carrying the x-k8s-aws-id header, base64url-encoded behind the k8s-aws-v1. prefix.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

TOKEN_PREFIX = "k8s-aws-v1."
TOKEN_TTL = timedelta(minutes=14)   # the server accepts the presigned URL for 15 minutes
_CLUSTER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}")


def eks_token(cluster_name: str, region: str, session=None) -> str:
    """Bearer token for the EKS API, derived from the caller's IAM credentials."""
    import boto3

    if not _CLUSTER_RE.fullmatch(cluster_name or ""):
        raise ValueError("invalid EKS cluster name")
    session = session or boto3.Session()
    sts = session.client("sts", region_name=region, endpoint_url=f"https://sts.{region}.amazonaws.com")

    def _inject(request, **_kwargs):
        request.headers["x-k8s-aws-id"] = cluster_name

    sts.meta.events.register("before-sign.sts.GetCallerIdentity", _inject)
    url = sts.generate_presigned_url("get_caller_identity", Params={}, ExpiresIn=60, HttpMethod="GET")
    return TOKEN_PREFIX + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def exec_credential(cluster_name: str, region: str) -> dict:
    """The ExecCredential object kubectl expects on stdout from an exec plugin."""
    return {"kind": "ExecCredential", "apiVersion": "client.authentication.k8s.io/v1",
            "spec": {"interactive": False},
            "status": {"token": eks_token(cluster_name, region),
                       "expirationTimestamp": (datetime.now(timezone.utc) + TOKEN_TTL).strftime("%Y-%m-%dT%H:%M:%SZ")}}


def kubeconfig_document(cluster_arn: str, endpoint: str, ca_data: str, cluster_name: str, region: str,
                        python: str | None = None) -> dict:
    """kubeconfig with one cluster, one user and one context, all named after the cluster ARN."""
    return {
        "apiVersion": "v1", "kind": "Config", "preferences": {}, "current-context": cluster_arn,
        "clusters": [{"name": cluster_arn, "cluster": {"server": endpoint, "certificate-authority-data": ca_data}}],
        "contexts": [{"name": cluster_arn, "context": {"cluster": cluster_arn, "user": cluster_arn}}],
        "users": [{"name": cluster_arn, "user": {"exec": {
            "apiVersion": "client.authentication.k8s.io/v1",
            "command": python or sys.executable,
            "args": ["-m", "cwe.kube", "token", "--cluster", cluster_name, "--region", region],
            "interactiveMode": "Never",
            "provideClusterInfo": False,
        }}}],
    }


def ensure_kubeconfig(cluster_name: str, region: str, path: str | None = None, session=None) -> tuple[str, str]:
    """Write (or refresh) a dedicated kubeconfig for the cluster. Returns (path, context_name).

    A separate file avoids merging into the operator's own ~/.kube/config; the caller passes it
    with --kubeconfig. Mode 0600: it carries no secret, but it does name the API endpoint."""
    import boto3

    if not _CLUSTER_RE.fullmatch(cluster_name or ""):
        raise ValueError("invalid EKS cluster name")
    from botocore.config import Config

    session = session or boto3.Session()
    # Fail within seconds when the EKS control-plane API is unreachable (a VPC without an eks endpoint or NAT),
    # instead of sitting in botocore's default retry ladder for minutes.
    eks = session.client("eks", region_name=region, config=Config(connect_timeout=5, read_timeout=20, retries={"max_attempts": 2}))
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    path = path or os.path.join(os.path.expanduser("~"), ".kube", f"cwe-{cluster_name}.yaml")
    os.makedirs(os.path.dirname(path), exist_ok=True, mode=0o700)
    doc = kubeconfig_document(cluster["arn"], cluster["endpoint"], cluster["certificateAuthority"]["data"], cluster_name, region)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(doc, stream)   # JSON is valid YAML, and kubectl reads it as such
    return path, cluster["arn"]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m cwe.kube")
    sub = parser.add_subparsers(dest="cmd", required=True)
    token = sub.add_parser("token", help="print an ExecCredential for kubectl")
    token.add_argument("--cluster", required=True)
    token.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")
    write = sub.add_parser("kubeconfig", help="write a kubeconfig for the cluster and print its path")
    write.add_argument("--cluster", required=True)
    write.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")
    write.add_argument("--path")
    args = parser.parse_args(argv)
    if args.cmd == "token":
        json.dump(exec_credential(args.cluster, args.region), sys.stdout)
    else:
        path, context = ensure_kubeconfig(args.cluster, args.region, args.path)
        print(f"{path}\t{context}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
