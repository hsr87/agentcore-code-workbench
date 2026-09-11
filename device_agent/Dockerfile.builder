# Gradle builder sidecar: JDK 17 plus the Android command-line tools, nothing else.
# Build: finch build --platform linux/amd64 (Android nodes are x86_64)
#
# Built from a digest-pinned Temurin image instead of a community all-in-one SDK image, so the package set is small,
# every component is pinned, and a base change is a deliberate edit. The Gradle build downloads any SDK component
# the project needs that is not pre-installed below; licenses are accepted at build time.
# To refresh the base: finch pull --platform linux/amd64 eclipse-temurin:17-jdk-noble
#                      finch image inspect eclipse-temurin:17-jdk-noble --format '{{index .RepoDigests 0}}'
FROM eclipse-temurin@sha256:1acf864adb20be14ffa9039e44ba4c8e120e78a14492e67d67eafc6d5b52219a

ARG CMDLINE_TOOLS_URL=https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
ARG CMDLINE_TOOLS_SHA256=7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee
# Pre-installed for the sample app (compileSdk 34). Add your project's versions here to avoid a download per Pod.
ARG SDK_PACKAGES="platform-tools platforms;android-34 build-tools;34.0.0 build-tools;35.0.0"

ENV ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk \
    PATH=/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:$PATH

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends python3 ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    python3 -c "import hashlib,sys,urllib.request; d=urllib.request.urlopen(sys.argv[1],timeout=300).read(); \
      assert hashlib.sha256(d).hexdigest()==sys.argv[2], 'cmdline-tools checksum mismatch'; open('/tmp/clt.zip','wb').write(d)" \
      "$CMDLINE_TOOLS_URL" "$CMDLINE_TOOLS_SHA256"; \
    mkdir -p "$ANDROID_HOME/cmdline-tools"; \
    unzip -q /tmp/clt.zip -d "$ANDROID_HOME/cmdline-tools"; \
    mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"; \
    rm /tmp/clt.zip
RUN yes | sdkmanager --licenses > /dev/null \
    && sdkmanager $SDK_PACKAGES > /dev/null \
    && chown -R 1000:1000 "$ANDROID_HOME"
COPY builder.py /app/builder.py
ENV PYTHONUNBUFFERED=1 HOME=/tmp GRADLE_USER_HOME=/opt/cwe/gradle
USER 1000:1000
CMD ["python3", "/app/builder.py"]
