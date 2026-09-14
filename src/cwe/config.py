"""Environment-variable-based settings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    region: str = field(default_factory=lambda: os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")
    code_interpreter_id: str = field(default_factory=lambda: os.environ.get("CWE_CODE_INTERPRETER_ID") or "aws.codeinterpreter.v1")
    session_timeout_seconds: int = field(default_factory=lambda: int(os.environ.get("CWE_SESSION_TIMEOUT_SECONDS") or 1800))
    storage_uri: str = field(default_factory=lambda: os.environ.get("CWE_STORAGE_URI") or ".cwe_data")
    memory_id: str | None = field(default_factory=lambda: os.environ.get("CWE_MEMORY_ID") or None)
    judge_model: str = field(default_factory=lambda: os.environ.get("CWE_JUDGE_MODEL") or "anthropic.claude-opus-5")
    agent_model: str = field(default_factory=lambda: os.environ.get("CWE_AGENT_MODEL") or "us.anthropic.claude-opus-5")
    enable_llm_judge: bool = field(default_factory=lambda: _env_bool("CWE_ENABLE_LLM_JUDGE", True))
    # Log group used by AgentCore Evaluations (agent session span evaluation). Auto-derived when deployed to the runtime.
    agent_runtime_id: str | None = field(default_factory=lambda: os.environ.get("CWE_AGENT_RUNTIME_ID") or None)
    project_name: str = field(default_factory=lambda: os.environ.get("CWE_PROJECT_NAME") or "cwe")
    android_backend: str = field(default_factory=lambda: os.environ.get("CWE_ANDROID_BACKEND") or "eks")
    eks_namespace: str = field(default_factory=lambda: os.environ.get("CWE_EKS_NAMESPACE") or "cwe")
    eks_context: str | None = field(default_factory=lambda: os.environ.get("CWE_EKS_CONTEXT") or None)
    eks_access: str = field(default_factory=lambda: os.environ.get("CWE_EKS_ACCESS") or "port-forward")
    eks_builder_image: str | None = field(default_factory=lambda: os.environ.get("CWE_EKS_BUILDER_IMAGE") or None)
    # Runtime path: a cluster name is enough; cwe.kube writes a kubeconfig from the execution role's credentials.
    eks_cluster_name: str | None = field(default_factory=lambda: os.environ.get("CWE_EKS_CLUSTER_NAME") or None)
    eks_kubeconfig: str | None = field(default_factory=lambda: os.environ.get("CWE_EKS_KUBECONFIG") or None)
    # Heavy build/run Pods (WorkloadProfile). The image comes from device_agent/Dockerfile.workload.
    workload_image: str | None = field(default_factory=lambda: os.environ.get("CWE_WORKLOAD_IMAGE") or None)
    # Sticky sessions across Runtime microVM replacement: DynamoDB table (infra/terraform/runtime) or the recordings store.
    session_table: str | None = field(default_factory=lambda: os.environ.get("CWE_SESSION_TABLE") or None)
    registry_kms_key_id: str | None = field(default_factory=lambda: os.environ.get("CWE_REGISTRY_KMS_KEY_ID") or None)
    session_registry_ttl_seconds: int = field(default_factory=lambda: int(os.environ.get("CWE_SESSION_REGISTRY_TTL_SECONDS") or 24 * 3600))
    # Android emulator host (written to .env by scripts/deploy.sh)
    android_subnet_id: str | None = field(default_factory=lambda: os.environ.get("CWE_ANDROID_SUBNET_ID") or None)
    android_security_group_id: str | None = field(default_factory=lambda: os.environ.get("CWE_ANDROID_SECURITY_GROUP_ID") or None)
    android_instance_profile: str = field(default_factory=lambda: os.environ.get("CWE_ANDROID_INSTANCE_PROFILE") or "cwe-android-instance-profile")
    android_device_agent_image: str | None = field(default_factory=lambda: os.environ.get("CWE_ANDROID_DEVICE_AGENT_IMAGE") or None)
    android_instance_type: str = field(default_factory=lambda: os.environ.get("CWE_ANDROID_INSTANCE_TYPE") or "c8i.xlarge")
    android_access: str = field(default_factory=lambda: os.environ.get("CWE_ANDROID_ACCESS") or "ssm")  # ssm | public | private
    android_ami_id: str | None = field(default_factory=lambda: os.environ.get("CWE_ANDROID_AMI_ID") or None)   # result of scripts/bake_ami (reduces boot time)
    android_build_image: str = field(default_factory=lambda: os.environ.get("CWE_ANDROID_BUILD_IMAGE") or "thyrlian/android-sdk:latest")
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN") or None)
    skills_prefix: str = field(default_factory=lambda: os.environ.get("CWE_SKILLS_PREFIX") or "_skills")
    android_associate_public_ip: bool = field(default_factory=lambda: _env_bool("CWE_ANDROID_ASSOCIATE_PUBLIC_IP", True))  # default VPC needs a public IP for egress
    # Default budget for agent runs (applied when the API/Runtime caller doesn't supply a budget). Leaving it unlimited would let an external caller run up unbounded Bedrock costs
    default_max_executions: int = field(default_factory=lambda: int(os.environ.get("CWE_DEFAULT_MAX_EXECUTIONS") or 60))
    default_max_seconds: int = field(default_factory=lambda: int(os.environ.get("CWE_DEFAULT_MAX_SECONDS") or 1200))
    default_max_cost_usd: float = field(default_factory=lambda: float(os.environ.get("CWE_DEFAULT_MAX_COST_USD") or 5.0))
    default_max_turns: int = field(default_factory=lambda: int(os.environ.get("CWE_DEFAULT_MAX_TURNS") or 40))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
