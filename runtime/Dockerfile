# Container for AgentCore Runtime (ARM64 required)
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
# the linux/arm64 wheel of claude-agent-sdk bundles the Claude Code CLI, so no Node install is needed
RUN pip install --no-cache-dir . "aws-opentelemetry-distro"
# do not run as root: the Claude Code CLI refuses permission-bypass mode as root, and it limits the blast radius of a container escape
RUN useradd -m -u 10001 app && chown -R app /app
USER app
# CWE_STORAGE_URI / CWE_CODE_INTERPRETER_ID are injected as runtime environment variables (see the .env produced by scripts/deploy.sh)
ENV \
    AWS_REGION=us-east-1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/app
EXPOSE 8080
# wrapping with opentelemetry-instrument auto-sends spans to AgentCore Observability/Evaluations
CMD ["opentelemetry-instrument", "python", "-m", "cwe.runtime_app"]
