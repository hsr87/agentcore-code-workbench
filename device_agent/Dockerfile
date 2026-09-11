# Device agent: adb next to the emulator, exposed as an authenticated HTTP API.
# Build: finch build --platform linux/amd64 (Android nodes are x86_64)
#
# Amazon Linux 2023 minimal rather than a Debian python image: Debian's essential perl-base and its glibc/zlib/sqlite
# carried unfixed findings in every scan, while AL2023 ships no perl and patches its base quickly. The base is pinned
# by digest so a rebuild is reproducible and a base change is a deliberate edit.
# To refresh: aws ecr-public get-login-password --region us-east-1 | finch login --username AWS --password-stdin public.ecr.aws
#             finch pull --platform linux/amd64 public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
#             finch image inspect public.ecr.aws/amazonlinux/amazonlinux:2023-minimal --format '{{index .RepoDigests 0}}'
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:efd25114254db410846f270efcee4df9c24a31228b0ce97b4f695992ce075f8f

# adb comes from Google's platform-tools release, pinned by URL and checksum, so the version is ours.
ARG PLATFORM_TOOLS_URL=https://dl.google.com/android/repository/platform-tools_r36.0.0-linux.zip
ARG PLATFORM_TOOLS_SHA256=0ead642c943ffe79701fccca8f5f1c69c4ce4f43df2eefee553f6ccb27cbfbe8

RUN dnf -y update \
    && dnf -y install python3.12 python3.12-pip ca-certificates \
    && dnf clean all && rm -rf /var/cache/dnf /var/cache/yum
RUN python3.12 - <<'EOF'
import hashlib, io, os, urllib.request, zipfile
url, want = os.environ["PLATFORM_TOOLS_URL"], os.environ["PLATFORM_TOOLS_SHA256"]
data = urllib.request.urlopen(url, timeout=120).read()
got = hashlib.sha256(data).hexdigest()
if got != want:
    raise SystemExit(f"platform-tools checksum mismatch: {got} != {want}")
with zipfile.ZipFile(io.BytesIO(data)) as z, open("/usr/local/bin/adb", "wb") as out:
    out.write(z.read("platform-tools/adb"))
os.chmod("/usr/local/bin/adb", 0o755)
EOF
RUN adb version
RUN python3.12 -m pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "pillow>=10"
COPY app.py /app/app.py
WORKDIR /app
# BUILD_BACKEND=sidecar is the default; the Docker Engine path is opt-in and only used by the legacy EC2 host.
ENV ADB=/usr/local/bin/adb ADB_SERIAL=auto PYTHONUNBUFFERED=1 DEVICE_AGENT_HOST=0.0.0.0 BUILD_BACKEND=sidecar
EXPOSE 8080
# With DEVICE_AGENT_HOST=127.0.0.1 the agent is reachable only through a port-forward or an SSM tunnel.
CMD ["sh", "-c", "python3.12 -m uvicorn app:app --host ${DEVICE_AGENT_HOST} --port 8080"]
