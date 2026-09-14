"""cwe.kube: EKS tokens and kubeconfig without the AWS CLI."""
import base64
import json
from urllib.parse import parse_qs, urlsplit

import boto3
import pytest
from botocore.stub import Stubber

from cwe.kube import TOKEN_PREFIX, eks_token, exec_credential, kubeconfig_document


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def test_eks_token_is_a_presigned_get_caller_identity_with_cluster_header(creds):
    token = eks_token("cwe-eks", "ap-northeast-2", session=boto3.Session(region_name="ap-northeast-2"))
    assert token.startswith(TOKEN_PREFIX)
    padded = token[len(TOKEN_PREFIX):] + "=" * (-len(token[len(TOKEN_PREFIX):]) % 4)
    url = base64.urlsafe_b64decode(padded).decode()
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert parts.scheme == "https" and parts.netloc == "sts.ap-northeast-2.amazonaws.com"
    assert q["Action"] == ["GetCallerIdentity"] and q["X-Amz-Expires"] == ["60"]
    assert "x-k8s-aws-id" in q["X-Amz-SignedHeaders"][0].split(";")
    with pytest.raises(ValueError):
        eks_token("bad name!", "us-east-1")


def test_exec_credential_shape(creds):
    cred = exec_credential("cwe-eks", "us-east-1")
    assert cred["apiVersion"] == "client.authentication.k8s.io/v1" and cred["kind"] == "ExecCredential"
    assert cred["status"]["token"].startswith(TOKEN_PREFIX) and cred["status"]["expirationTimestamp"].endswith("Z")


def test_kubeconfig_document_uses_the_cwe_exec_plugin():
    doc = kubeconfig_document("arn:aws:eks:us-east-1:123:cluster/cwe-eks", "https://x.eks.amazonaws.com", "Q0E=", "cwe-eks", "us-east-1", python="/usr/bin/python3")
    assert doc["current-context"] == "arn:aws:eks:us-east-1:123:cluster/cwe-eks"
    user = doc["users"][0]["user"]["exec"]
    assert user["command"] == "/usr/bin/python3" and user["args"] == ["-m", "cwe.kube", "token", "--cluster", "cwe-eks", "--region", "us-east-1"]
    assert user["interactiveMode"] == "Never"
    assert doc["clusters"][0]["cluster"] == {"server": "https://x.eks.amazonaws.com", "certificate-authority-data": "Q0E="}
    json.dumps(doc)   # kubectl reads JSON kubeconfig files


def test_ensure_kubeconfig_writes_a_private_file(tmp_path, creds):
    from cwe.kube import ensure_kubeconfig

    session = boto3.Session(region_name="us-east-1")
    eks = session.client("eks")
    stub = Stubber(eks)
    stub.add_response("describe_cluster", {"cluster": {"name": "cwe-eks", "arn": "arn:aws:eks:us-east-1:123:cluster/cwe-eks",
                                                       "endpoint": "https://x.eks.amazonaws.com", "certificateAuthority": {"data": "Q0E="}}},
                      {"name": "cwe-eks"})
    stub.activate()

    class S:
        def client(self, name, region_name=None, config=None):
            assert name == "eks"
            return eks
    path, context = ensure_kubeconfig("cwe-eks", "us-east-1", str(tmp_path / "kube" / "c.yaml"), session=S())
    assert context == "arn:aws:eks:us-east-1:123:cluster/cwe-eks"
    assert oct((tmp_path / "kube" / "c.yaml").stat().st_mode & 0o777) == "0o600"
    assert json.loads((tmp_path / "kube" / "c.yaml").read_text())["current-context"] == context


def test_resolve_context_prefers_explicit_context(monkeypatch):
    from cwe.config import Settings
    from cwe.eks import resolve_context

    assert resolve_context(Settings(eks_context="ctx", eks_cluster_name="c")) == ("ctx", None)
    assert resolve_context(Settings()) == (None, None)
    monkeypatch.setattr("cwe.kube.ensure_kubeconfig", lambda name, region, path: ("/tmp/k.yaml", "arn:ctx"))
    assert resolve_context(Settings(eks_cluster_name="c")) == ("arn:ctx", "/tmp/k.yaml")
