"""Run scan engines inside a locked-down Docker container.

Design notes
------------
Only the engines that *parse untrusted code* run in the container
(semgrep, gitleaks). SCA (OSV lookups) stays on the host: it only reads
manifests and needs the network, so isolating it would break it without
adding safety.

The container is launched with:
  --network none        no exfiltration / no SSRF from a compromised engine
  --read-only           container rootfs immutable
  -v target:/target:ro  the untrusted code is mounted read-only
  --cap-drop ALL        no new privileges possible
  --pids-limit 256      fork-bomb containment
  --memory / --cpus     resource exhaustion containment

``--config auto`` needs the network, so the image vendors a pinned
snapshot of the semgrep ruleset at *build* time (see
deploy/docker/scan-runner.Dockerfile); the entrypoint scans with the
vendored rules plus our own custom rules. A build without network
access fails loudly instead of shipping a rule-less image.

Contract: ``run_scan_isolated(target_dir, scope=None)`` returns findings
in the exact schema of ``scan_engine`` (host-absolute ``file`` paths),
so callers (api/tasks.py) can swap the engine invocation without any
other change.
"""
import json
import os
import shutil
import subprocess
import tempfile

DOCKER_BIN = os.environ.get("BRAIMSEC_DOCKER_BIN", "docker")
RUNNER_IMAGE = os.environ.get("BRAIMSEC_SCAN_RUNNER_IMAGE",
                              "braimsec/scan-runner:latest")
CONTAINER_TIMEOUT = int(os.environ.get("BRAIMSEC_SCAN_CONTAINER_TIMEOUT",
                                       "600"))
CONTAINER_MEMORY = os.environ.get("BRAIMSEC_SCAN_CONTAINER_MEMORY", "2g")
CONTAINER_CPUS = os.environ.get("BRAIMSEC_SCAN_CONTAINER_CPUS", "2")
CONTAINER_PIDS = os.environ.get("BRAIMSEC_SCAN_CONTAINER_PIDS", "256")


class ContainerError(RuntimeError):
    """The isolated scan could not run. Fail closed: never fall back to
    an un-isolated scan silently."""


def sandbox_mode() -> str:
    """'docker' or 'local' (default)."""
    return os.environ.get("BRAIMSEC_SCAN_SANDBOX", "local").strip().lower()


def _docker_available() -> bool:
    return shutil.which(DOCKER_BIN) is not None


def build_command(target_dir: str, out_dir: str,
                  image: str = RUNNER_IMAGE) -> list:
    """The hardened `docker run` invocation. Pure function, unit-tested."""
    cmd = [
        DOCKER_BIN, "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    if CONTAINER_PIDS:
        cmd += ["--pids-limit", CONTAINER_PIDS]
    if CONTAINER_MEMORY:
        cmd += ["--memory", CONTAINER_MEMORY]
    if CONTAINER_CPUS:
        cmd += ["--cpus", CONTAINER_CPUS]
    cmd += [
        "-v", f"{os.path.abspath(target_dir)}:/target:ro",
        "-v", f"{os.path.abspath(out_dir)}:/out",
        # Writable scratch the engines need (semgrep temp files, HOME).
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=512m",
        "-e", "HOME=/tmp",
        image,
    ]
    return cmd


def run_scan_isolated(target_dir: str, scope=None) -> list:
    """Run semgrep+gitleaks in the sandbox container on target_dir.

    scope: optional list of absolute host paths (incremental scans);
    translated to /target-relative paths for the container.
    Returns findings with host-absolute `file` paths.
    Raises ContainerError on any failure (fail closed).
    """
    if not _docker_available():
        raise ContainerError(
            f"docker binary not found ({DOCKER_BIN!r}); refusing to scan "
            "outside the sandbox")
    target_abs = os.path.abspath(target_dir)
    if not os.path.isdir(target_abs):
        raise ContainerError(f"target not a directory: {target_abs}")

    out_dir = tempfile.mkdtemp(prefix="braimsec-sandbox-out-")
    try:
        if scope:
            rel_scope = [os.path.relpath(p, target_abs) for p in scope]
            with open(os.path.join(out_dir, "scope.json"), "w") as f:
                json.dump(rel_scope, f)

        cmd = build_command(target_abs, out_dir)
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=CONTAINER_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise ContainerError(
                f"sandboxed scan timed out after {CONTAINER_TIMEOUT}s")
        if proc.returncode != 0:
            raise ContainerError(
                f"sandboxed scan failed (rc={proc.returncode}): "
                f"{proc.stderr.strip()[-500:]}")

        findings_path = os.path.join(out_dir, "findings.json")
        if not os.path.isfile(findings_path):
            raise ContainerError(
                "sandboxed scan produced no findings.json "
                f"(stdout: {proc.stdout.strip()[-300:]})")
        with open(findings_path) as f:
            findings = json.load(f)

        # Translate container paths (/target/...) back to host paths.
        for item in findings:
            fp = item.get("file", "")
            if fp.startswith("/target/"):
                item["file"] = os.path.join(target_abs,
                                            fp[len("/target/"):])
            elif fp == "/target":
                item["file"] = target_abs
        return findings
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
