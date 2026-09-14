# Container for AgentCore Runtime (ARM64 required)
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim

# kubectl for the EKS lab (Jobs, Pod lookups, port-forward when not in VPC mode). Pinned by version and
# checksum; the token comes from `cwe eks-token` (boto3), so no AWS CLI is needed.
ARG KUBECTL_VERSION=v1.33.13
ARG KUBECTL_SHA256=9fe8aadd5aab9421978c7ac95de6fad304a3c4c0ce9dbf4127579779e0699080
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/arm64/kubectl" \
    && echo "${KUBECTL_SHA256}  /usr/local/bin/kubectl" | sha256sum -c - \
    && chmod 0755 /usr/local/bin/kubectl \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
# the linux/arm64 wheel of claude-agent-sdk bundles the Claude Code CLI, so no Node install is needed
RUN pip install --no-cache-dir . "aws-opentelemetry-distro"
# do not run as root: the Claude Code CLI refuses permission-bypass mode as root, and it limits the blast radius of a container escape
RUN useradd -m -u 10001 app && chown -R app /app && mkdir -p /home/app/.kube && chown app /home/app/.kube
USER app
# CWE_* settings are injected by infra/terraform/runtime as Runtime environment variables.
ENV \
    AWS_REGION=us-east-1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/app
EXPOSE 8080
# wrapping with opentelemetry-instrument auto-sends spans to AgentCore Observability/Evaluations
CMD ["opentelemetry-instrument", "python", "-m", "cwe.runtime_app"]
