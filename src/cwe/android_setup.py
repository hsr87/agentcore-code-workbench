"""Android auto-setup: read a repository's Gradle configuration and propose an emulator profile from it.

Fills in compileSdk, applicationId, and the instrumentation runner based on the framework
templates (examples/profiles/android/*.yaml).
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from cwe.android import AndroidEmulatorProfile

API_IMAGE = {  # API level -> emulator image (public images only go up to 30; above that, build to ECR with scripts/build_emulator_image.sh)
    28: "us-docker.pkg.dev/android-emulator-268719/images/28-google-x64:latest",
    29: "us-docker.pkg.dev/android-emulator-268719/images/29-google-x64:latest",
    30: os.environ.get("CWE_ANDROID_EMULATOR_IMAGE") or "us-docker.pkg.dev/android-emulator-268719/images/30-google-x64:latest",
}

_PATTERNS = {
    "compile_sdk": r"compileSdk(?:Version)?\s*[=(]?\s*(\d+)",
    "min_sdk": r"minSdk(?:Version)?\s*[=(]?\s*(\d+)",
    "application_id": r"applicationId\s*[=(]?\s*[\"']([\w.]+)[\"']",
    "namespace": r"namespace\s*[=(]?\s*[\"']([\w.]+)[\"']",
    "runner": r"testInstrumentationRunner\s*[=(]?\s*[\"']([\w.]+)[\"']",
}


def detect_framework(root: str) -> str:
    files = set(os.listdir(root)) if os.path.isdir(root) else set()
    if "pubspec.yaml" in files:
        return "flutter"
    if "package.json" in files and os.path.isdir(os.path.join(root, "android")):
        return "react-native"
    if any(f.endswith(".kts") for f in files) and os.path.isdir(os.path.join(root, "shared")):
        return "kmp"
    return "native"


def scan_gradle(root: str) -> dict[str, Any]:
    """Extract the SDK level, package, and instrumentation runner from the app module's build.gradle(.kts)."""
    found: dict[str, Any] = {}
    for dirpath, _, files in os.walk(root):
        if any(x in dirpath for x in ("/build/", "/.gradle", "/node_modules")):
            continue
        for f in files:
            if f in ("build.gradle", "build.gradle.kts"):
                text = open(os.path.join(dirpath, f), encoding="utf-8", errors="replace").read()
                for key, pat in _PATTERNS.items():
                    m = re.search(pat, text)
                    if m and key not in found:
                        found[key] = int(m.group(1)) if key.endswith("sdk") else m.group(1)
    return found


def load_template(framework: str, templates_dir: str) -> dict[str, Any]:
    path = os.path.join(templates_dir, f"{framework}.yaml")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def propose_profile(root: str, templates_dir: str, custom_images: dict[int, str] | None = None) -> tuple[AndroidEmulatorProfile, dict[str, Any]]:
    """Read the repository and return an AndroidEmulatorProfile together with the evidence (scan results) behind it. A human approves it before it is used in a session."""
    fw = detect_framework(root)
    scan = scan_gradle(os.path.join(root, "android") if fw in ("react-native", "flutter") and os.path.isdir(os.path.join(root, "android")) else root)
    tpl = load_template(fw, templates_dir)
    images = {**API_IMAGE, **(custom_images or {})}
    api = scan.get("compile_sdk") or tpl.get("api_level") or 30
    image = images.get(api) or images[max(k for k in images if k <= api)] if any(k <= api for k in images) else images[30]
    pkg = scan.get("application_id") or scan.get("namespace")
    profile = AndroidEmulatorProfile(
        name=f"{fw}-api{api}", image=image, api_level=api, framework=fw,
        package=pkg, test_package=f"{pkg}.test" if pkg else None,
        test_runner=scan.get("runner") or tpl.get("test_runner", "androidx.test.runner.AndroidJUnitRunner"),
        build_tasks=tpl.get("build_tasks", "assembleDebug assembleDebugAndroidTest"),
        emulator_params=tpl.get("emulator_params", "-gpu swiftshader_indirect -no-audio -memory 3072"),
    )
    return profile, {"framework": fw, "scan": scan, "template": tpl, "image_api_used": api}
