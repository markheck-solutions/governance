from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
import time
import tokenize
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from governance_eval.architecture_gate import run_architecture_gate
from governance_eval.benchmark import BENCHMARK_PASS, validate_benchmark_result
from governance_eval.checkout_receipt import (
    CheckoutReceipt,
    CheckoutReceiptError,
    validate_checkout_receipt_v1,
)
from governance_eval.docker_process import (
    DockerCommandRecord,
    DockerProcessError,
    DockerProcessResult,
    run_docker_container,
    run_docker_control,
    validate_bind_source,
)
from governance_eval.docker_gate_command import (
    validate_gate_command,
    validate_gate_run_command,
)
from governance_eval.docker_toolchain import (
    CERTIFIED_TOOLCHAIN_BUNDLE_ID,
    MANIFEST_NAME,
    ToolchainError,
    verify_toolchain_bundle,
)
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2,
    assess_execution_plan_v2,
)
from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.scope_manifest import build_scope_manifest

_MAX_TREE_FILES = 20_000
_MAX_TREE_FILE_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 1024 * 1024 * 1024
_SUMMARY_MARKERS = {
    "tests": b"GOVERNANCE_UNITTEST_SUMMARY=",
    "package_audit": b"GOVERNANCE_PACKAGE_AUDIT_SUMMARY=",
}


class DockerRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    workspace: Path
    base_tests: Path
    scope: Path
    input: Path
    staging: Path
    output: Path


def execute_plan_v2(
    *,
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt | Mapping[str, object],
    target_root: Path,
    evaluator_root: Path,
    toolchain_root: Path | None,
    artifacts_root: Path,
    scope_manifest: Mapping[str, object],
    input_artifacts: Sequence[Mapping[str, object]] = (),
    input_artifact_paths: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    started = datetime.now(UTC)
    monotonic_started = time.monotonic()
    records: list[DockerCommandRecord] = []
    errors: list[str] = []
    outcome: DockerProcessResult | None = None
    command: list[str] = []
    artifacts: list[dict[str, Any]] = []
    paths: RuntimePaths | None = None
    trusted_receipt: dict[str, Any] | None = None
    try:
        trusted_receipt = _validate_inputs(
            plan,
            receipt,
            target_root,
            evaluator_root,
            scope_manifest,
            toolchain_root,
            input_artifacts,
        )
        paths = _prepare_paths(
            plan,
            target_root,
            evaluator_root,
            toolchain_root,
            artifacts_root,
        )
        if plan.step["execution"] == "trusted_judge":
            outcome, artifacts = _execute_trusted_judge(
                plan,
                trusted_receipt,
                target_root,
                paths,
                scope_manifest,
            )
            command = list(outcome.command)
            records.extend(outcome.records)
        else:
            outcome, artifacts = _execute_docker_adapter(
                plan,
                trusted_receipt,
                target_root,
                evaluator_root,
                toolchain_root,
                paths,
                scope_manifest,
                input_artifacts,
                input_artifact_paths or {},
                records,
                monotonic_started,
            )
            command = list(outcome.command)
            _extend_records(records, outcome.records)
            errors.extend(outcome.errors)
    except (
        CheckoutReceiptError,
        DockerProcessError,
        DockerRuntimeError,
        OSError,
        subprocess.SubprocessError,
        ToolchainError,
        ValueError,
    ) as exc:
        errors.append(_bounded_error(exc))
        if isinstance(exc, (DockerProcessError, ToolchainError)):
            _extend_records(records, exc.records)
    finally:
        errors.extend(
            _post_execution_checks(
                plan,
                trusted_receipt,
                target_root,
                evaluator_root,
                scope_manifest,
            )
        )
        errors.extend(_cleanup_runtime(paths))
    return _execution_result(
        plan,
        started,
        datetime.now(UTC),
        command,
        outcome,
        records,
        artifacts,
        errors,
        scope_manifest,
    )


def docker_gate_argv(
    *,
    plan: ExecutionPlanV2,
    docker: Path,
    paths: RuntimePaths,
    evaluator_root: Path,
    toolchain_root: Path | None,
    container_name: str,
) -> list[str]:
    runtime = plan.runtime
    argv = [
        str(docker),
        f"--host={runtime['docker']['host']}",
        "run",
        f"--name={container_name}",
        "--pull=never",
        "--init",
        "--read-only",
        "--network=none",
        "--user=65532:65532",
        "--cpus=1.0",
        "--memory=536870912",
        "--memory-swap=536870912",
        "--pids-limit=128",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=268435456",
    ]
    if plan.step["mount_profile"] == "wheel-only.v1":
        argv.append("--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=268435456")
    for value in _gate_environment(plan):
        argv.append(f"--env={value}")
    argv.append(f"--workdir={plan.step['working_directory']}")
    for source, destination, readonly in _mounts(
        plan, paths, evaluator_root, toolchain_root
    ):
        argv.extend(
            [
                "--mount",
                f"type=bind,src={validate_bind_source(source)},dst={destination}"
                + (",readonly" if readonly else ""),
            ]
        )
    return [*argv, runtime["image"]["reference"], *plan.step["argv"]]


def _validate_inputs(
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt | Mapping[str, object],
    target_root: Path,
    evaluator_root: Path,
    scope_manifest: Mapping[str, object],
    toolchain_root: Path | None,
    input_artifacts: Sequence[Mapping[str, object]],
) -> dict[str, Any]:
    trusted = validate_checkout_receipt_v1(receipt)
    trusted_scope = build_scope_manifest(
        receipt=trusted,
        adapter=_plan_adapter(plan),
        target_root=target_root,
        evaluator_root=evaluator_root,
    )
    if trusted_scope != scope_manifest:
        raise DockerRuntimeError("scope manifest changed after plan compilation")
    toolchain = plan.inputs["toolchain"]
    assessment = assess_execution_plan_v2(
        plan.to_json(),
        receipt,
        capability=plan.step["capability"],
        adapter_id=plan.step["adapter_id"],
        scope_manifest=scope_manifest,
        target_root=target_root,
        evaluator_root=evaluator_root,
        toolchain_manifest=toolchain,
        input_artifacts=input_artifacts,
    )
    if assessment["capability_status"] != "PASS":
        raise DockerRuntimeError("execution plan is not evaluator-owned")
    _require_authoritative_adapter(plan)
    _validate_toolchain_root(plan, toolchain_root)
    return trusted


def _plan_adapter(plan: ExecutionPlanV2):
    from governance_eval.capability_catalog import get_capability_adapter

    try:
        return get_capability_adapter(plan.step["capability"], plan.step["adapter_id"])
    except KeyError as exc:
        raise DockerRuntimeError("execution plan adapter is unsupported") from exc


def _require_authoritative_adapter(plan: ExecutionPlanV2) -> None:
    if plan.step["adapter_id"] == "python.unittest.v1":
        raise DockerRuntimeError(
            "python.unittest.v1 cannot authenticate success from candidate-controlled "
            "code in the assertion interpreter"
        )


def _validate_toolchain_root(
    plan: ExecutionPlanV2, toolchain_root: Path | None
) -> None:
    required = plan.inputs["toolchain"] is not None
    if not required:
        if toolchain_root is not None:
            raise DockerRuntimeError("execution plan does not accept a toolchain")
        return
    if toolchain_root is None:
        raise DockerRuntimeError("certified toolchain is unavailable")
    manifest = verify_toolchain_bundle(toolchain_root, CERTIFIED_TOOLCHAIN_BUNDLE_ID)
    if manifest["lock_sha256"] != plan.inputs["toolchain"]["lock_sha256"]:
        raise DockerRuntimeError("toolchain lock differs from execution plan")
    manifest_path = toolchain_root.resolve(strict=True) / MANIFEST_NAME
    if (
        sha256_file(manifest_path, max_bytes=4 * 1024 * 1024)
        != plan.inputs["toolchain"]["manifest_sha256"]
    ):
        raise DockerRuntimeError("toolchain manifest differs from execution plan")


def _prepare_paths(
    plan: ExecutionPlanV2,
    target_root: Path,
    evaluator_root: Path,
    toolchain_root: Path | None,
    artifacts_root: Path,
) -> RuntimePaths:
    protected = [target_root, evaluator_root]
    if toolchain_root is not None:
        protected.append(toolchain_root)
    artifacts_root = _link_free_existing(artifacts_root, "artifact root")
    _require_external(artifacts_root, protected, "artifact root")
    output = artifacts_root / plan.plan_id
    root = artifacts_root / f".runtime-{plan.plan_id}"
    if output.exists() or root.exists():
        raise DockerRuntimeError("plan artifact directory already exists")
    try:
        root.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
    except OSError as exc:
        _remove_empty_paths(output, root)
        raise DockerRuntimeError("runtime directories could not be created") from exc
    try:
        paths = RuntimePaths(
            root=root,
            workspace=root / "workspace",
            base_tests=root / "base-tests",
            scope=root / "scope",
            input=root / "input",
            staging=root / "staging",
            output=output,
        )
        for path in (
            paths.workspace,
            paths.base_tests,
            paths.scope,
            paths.input,
            paths.staging,
        ):
            path.mkdir()
        _make_container_writable(paths.workspace)
        _make_container_writable(paths.input)
        _make_container_writable(paths.staging)
    except OSError as exc:
        _discard_unexposed_paths(root, output)
        raise DockerRuntimeError("runtime layout could not be prepared") from exc
    return paths


def _link_free_existing(path: Path, label: str) -> Path:
    lexical = Path(os.path.abspath(path))
    for candidate in (lexical, *lexical.parents):
        if _is_link_or_junction(candidate):
            raise DockerRuntimeError(f"{label} contains a link")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise DockerRuntimeError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise DockerRuntimeError(f"{label} is not a directory")
    return resolved


def _remove_empty_paths(*paths: Path) -> None:
    for path in paths:
        try:
            path.rmdir()
        except OSError:
            pass


def _discard_unexposed_paths(root: Path, output: Path) -> None:
    try:
        shutil.rmtree(root)
    except OSError:
        pass
    _remove_empty_paths(output, root)


def _require_external(path: Path, protected: Sequence[Path], label: str) -> None:
    if _is_link_or_junction(path):
        raise DockerRuntimeError(f"{label} cannot be a link")
    for root in protected:
        resolved = root.resolve(strict=True)
        if path == resolved or _inside(path, resolved) or _inside(resolved, path):
            raise DockerRuntimeError(f"{label} overlaps a protected checkout")


def _execute_docker_adapter(
    plan: ExecutionPlanV2,
    receipt: Mapping[str, Any],
    target_root: Path,
    evaluator_root: Path,
    toolchain_root: Path | None,
    paths: RuntimePaths,
    scope_manifest: Mapping[str, object],
    input_artifacts: Sequence[Mapping[str, object]],
    input_paths: Mapping[str, Path],
    records: list[DockerCommandRecord],
    monotonic_started: float,
) -> tuple[DockerProcessResult, list[dict[str, Any]]]:
    docker = _trusted_docker(plan)
    _verify_image(plan, docker, records)
    _materialize_mounts(
        plan,
        receipt,
        target_root,
        evaluator_root,
        paths,
        scope_manifest,
        input_artifacts,
        input_paths,
    )
    _preflight_adapter(plan, paths.workspace, scope_manifest)
    remaining = plan.step["total_timeout_seconds"] - (
        time.monotonic() - monotonic_started
    )
    if remaining < 1:
        raise DockerRuntimeError("execution total deadline expired before gate start")
    timeout = min(plan.step["timeout_seconds"], max(1, int(remaining)))
    container_name = f"governance-{plan.plan_id[:32]}"
    command = docker_gate_argv(
        plan=plan,
        docker=docker,
        paths=paths,
        evaluator_root=evaluator_root,
        toolchain_root=toolchain_root,
        container_name=container_name,
    )
    command_errors = validate_gate_run_command(command, plan.to_json())
    if command_errors:
        raise DockerRuntimeError(command_errors[0])
    outcome = run_docker_container(
        command,
        docker=docker,
        docker_host=plan.runtime["docker"]["host"],
        container_name=container_name,
        purpose="gate",
        expected_mounts=_mounts(plan, paths, evaluator_root, toolchain_root),
        scratch_root=paths.root,
        timeout_seconds=timeout,
        output_limit_bytes=plan.step["output_limit_bytes"],
    )
    command_errors = validate_gate_command(outcome.command, plan.to_json())
    artifacts, artifact_errors = _capture_artifacts(plan, paths, outcome)
    if command_errors or artifact_errors:
        outcome = DockerProcessResult(
            command=outcome.command,
            termination=outcome.termination,
            exit_code=outcome.exit_code,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            started_at=outcome.started_at,
            completed_at=outcome.completed_at,
            errors=(*outcome.errors, *command_errors, *artifact_errors),
            stdout_truncated=outcome.stdout_truncated,
            stderr_truncated=outcome.stderr_truncated,
            records=outcome.records,
        )
    return outcome, artifacts


def _trusted_docker(plan: ExecutionPlanV2) -> Path:
    identity = plan.runtime["docker"]
    try:
        path = Path(identity["path"]).resolve(strict=True)
    except OSError as exc:
        raise DockerRuntimeError("Docker CLI is unavailable") from exc
    if (
        not path.is_file()
        or sha256_file(path, max_bytes=256 * 1024 * 1024) != identity["sha256"]
    ):
        raise DockerRuntimeError("Docker CLI digest mismatch")
    return path


def _verify_image(
    plan: ExecutionPlanV2, docker: Path, records: list[DockerCommandRecord]
) -> None:
    image = plan.runtime["image"]
    try:
        result = run_docker_control(
            [
                str(docker),
                f"--host={plan.runtime['docker']['host']}",
                "image",
                "inspect",
                "--format={{json .}}",
                image["reference"],
            ],
            docker=docker,
            docker_host=plan.runtime["docker"]["host"],
            timeout_seconds=30,
            output_limit_bytes=65_536,
        )
    except DockerProcessError as exc:
        _extend_records(records, exc.records)
        raise
    _extend_records(records, result.records)
    if result.termination != "EXITED" or result.exit_code != 0 or result.errors:
        raise DockerRuntimeError("Docker image inspection failed")
    try:
        metadata = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerRuntimeError("Docker image identity is malformed") from exc
    if (
        not isinstance(metadata, dict)
        or image["reference"] not in metadata.get("RepoDigests", [])
        or metadata.get("Id") != image["image_id"]
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != "amd64"
    ):
        raise DockerRuntimeError("Docker image identity mismatch")


def _materialize_mounts(
    plan: ExecutionPlanV2,
    receipt: Mapping[str, Any],
    target_root: Path,
    evaluator_root: Path,
    paths: RuntimePaths,
    scope_manifest: Mapping[str, object],
    input_artifacts: Sequence[Mapping[str, object]],
    input_paths: Mapping[str, Path],
) -> None:
    _write_canonical_json(paths.scope / "scope-manifest.json", scope_manifest)
    profile = plan.step["mount_profile"]
    if profile == "wheel-only.v1":
        _materialize_input_wheel(
            paths.input,
            input_artifacts,
            input_paths,
            protected=(target_root, evaluator_root),
        )
        return
    if profile == "evaluator-toolchain.v1":
        _materialize_tree(
            evaluator_root,
            receipt["evaluator"]["commit_sha"],
            paths.workspace,
            Path(receipt["runtime"]["git"]["path"]),
        )
    else:
        _materialize_tree(
            target_root,
            receipt["pull_request"]["head"]["commit_sha"],
            paths.workspace,
            Path(receipt["runtime"]["git"]["path"]),
        )
    if profile == "target-toolchain-base-tests.v1":
        _materialize_base_tests(
            target_root,
            receipt["pull_request"]["base"]["commit_sha"],
            paths.base_tests,
            Path(receipt["runtime"]["git"]["path"]),
        )
    (paths.workspace / ".home").mkdir(exist_ok=True)
    _make_container_writable(paths.workspace)


def _materialize_tree(root: Path, commit: str, output: Path, git: Path) -> None:
    entries = _git_tree_entries(git, root, commit)
    total = sum(entry["size_bytes"] for entry in entries)
    if len(entries) > _MAX_TREE_FILES or total > _MAX_TREE_BYTES:
        raise DockerRuntimeError(
            "authenticated Git tree exceeds materialization limits"
        )
    blobs = _git_blobs(git, root, entries)
    for entry, content in zip(entries, blobs, strict=True):
        destination = _safe_destination(output, entry["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        if entry["mode"] == "100755" and os.name != "nt":
            destination.chmod(0o755)


def _materialize_base_tests(
    root: Path, commit: str, destination: Path, git: Path
) -> None:
    entries = [
        entry
        for entry in _git_tree_entries(git, root, commit)
        if entry["path"].startswith("tests/")
    ]
    if not entries:
        raise DockerRuntimeError("protected base test suite is empty")
    blobs = _git_blobs(git, root, entries)
    for entry, content in zip(entries, blobs, strict=True):
        relative = str(entry["path"])[len("tests/") :]
        target = _safe_destination(destination, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _git_tree_entries(git: Path, root: Path, commit: str) -> list[dict[str, Any]]:
    raw = _git(
        git,
        root,
        "ls-tree",
        "-r",
        "-z",
        "--long",
        "--full-tree",
        commit,
        output_limit=64 * 1024 * 1024,
    )
    entries = [_parse_tree_entry(item) for item in raw.split(b"\0") if item]
    return sorted(entries, key=lambda item: item["path"])


def _parse_tree_entry(raw: bytes) -> dict[str, Any]:
    try:
        header, encoded_path = raw.split(b"\t", 1)
        mode, kind, blob, size = header.decode("ascii").split()
        path = encoded_path.decode("utf-8")
        parsed_size = int(size)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DockerRuntimeError("authenticated Git tree entry is malformed") from exc
    if (
        kind != "blob"
        or mode not in {"100644", "100755"}
        or not re.fullmatch(r"[0-9a-f]{40}", blob)
        or not 0 <= parsed_size <= _MAX_TREE_FILE_BYTES
    ):
        raise DockerRuntimeError("authenticated Git tree entry is unsupported")
    _canonical_path(path)
    return {"path": path, "mode": mode, "blob_sha": blob, "size_bytes": parsed_size}


def _git_blobs(
    git: Path, root: Path, entries: Sequence[Mapping[str, Any]]
) -> list[bytes]:
    if not entries:
        return []
    request = "".join(f"{entry['blob_sha']}\n" for entry in entries).encode("ascii")
    raw = _git(
        git,
        root,
        "cat-file",
        "--batch",
        input_bytes=request,
        output_limit=sum(int(entry["size_bytes"]) + 128 for entry in entries),
    )
    blobs: list[bytes] = []
    position = 0
    for entry in entries:
        newline = raw.find(b"\n", position)
        if newline < 0:
            raise DockerRuntimeError("Git blob batch output is truncated")
        header = raw[position:newline].decode("ascii", errors="strict").split()
        expected = [entry["blob_sha"], "blob", str(entry["size_bytes"])]
        if header != expected:
            raise DockerRuntimeError("Git blob batch identity mismatch")
        start = newline + 1
        end = start + int(entry["size_bytes"])
        content = raw[start:end]
        if len(content) != entry["size_bytes"] or raw[end : end + 1] != b"\n":
            raise DockerRuntimeError("Git blob batch content is malformed")
        blobs.append(content)
        position = end + 1
    if position != len(raw):
        raise DockerRuntimeError("Git blob batch output has trailing data")
    return blobs


def _git(
    git: Path,
    root: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    output_limit: int,
) -> bytes:
    command = [
        str(git),
        f"--git-dir={root / '.git'}",
        f"--work-tree={root}",
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            timeout=30,
            env=_git_environment(git),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DockerRuntimeError("authenticated Git command failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > output_limit:
        raise DockerRuntimeError("authenticated Git command failed")
    return completed.stdout


def _git_environment(git: Path) -> dict[str, str]:
    environment = {
        "PATH": str(git.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment


def _materialize_input_wheel(
    destination: Path,
    artifacts: Sequence[Mapping[str, object]],
    paths: Mapping[str, Path],
    *,
    protected: Sequence[Path],
) -> None:
    if len(artifacts) != 1:
        raise DockerRuntimeError("package audit input wheel is missing")
    artifact = artifacts[0]
    filename = str(artifact["filename"])
    if set(paths) != {filename}:
        raise DockerRuntimeError("package audit input path set is invalid")
    source = _link_free_path(paths[filename])
    _require_external(source, protected, "package audit input")
    if not source.is_file():
        raise DockerRuntimeError("package audit input is not a regular file")
    if (
        source.stat().st_size != artifact["size_bytes"]
        or sha256_file(source, max_bytes=64 * 1024 * 1024) != artifact["sha256"]
    ):
        raise DockerRuntimeError("package audit input digest mismatch")
    copied = _seal_staged_file(source, destination / filename)
    if (
        copied.stat().st_size != artifact["size_bytes"]
        or sha256_file(copied, max_bytes=64 * 1024 * 1024) != artifact["sha256"]
    ):
        raise DockerRuntimeError("sealed package audit input differs")


def _link_free_path(path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    for candidate in (lexical, *lexical.parents):
        if _is_link_or_junction(candidate):
            raise DockerRuntimeError("package audit input path contains a link")
    try:
        return lexical.resolve(strict=True)
    except OSError as exc:
        raise DockerRuntimeError("package audit input is unavailable") from exc


def _preflight_adapter(
    plan: ExecutionPlanV2,
    workspace: Path,
    scope_manifest: Mapping[str, object],
) -> None:
    if plan.step["adapter_id"] != "python.mypy.v1":
        return
    for entry in _manifest_entries(scope_manifest):
        path = workspace.joinpath(*PurePosixPath(entry["path"]).parts)
        try:
            tokens = tokenize.tokenize(BytesIO(path.read_bytes()).readline)
            comments = [
                token.string for token in tokens if token.type == tokenize.COMMENT
            ]
        except (OSError, SyntaxError, tokenize.TokenError) as exc:
            raise DockerRuntimeError(
                "mypy preflight could not tokenize source"
            ) from exc
        if any(
            re.search(r"#\s*(?:type\s*:\s*ignore|mypy\s*:)", item) for item in comments
        ):
            raise DockerRuntimeError("mypy suppression is forbidden by adapter policy")


def _gate_environment(plan: ExecutionPlanV2) -> tuple[str, ...]:
    common = (
        "HOME=/workspace/.home"
        if plan.step["mount_profile"] != "wheel-only.v1"
        else "HOME=/tmp/home",
        "TMPDIR=/tmp",
        "PYTHONNOUSERSITE=1",
        "PYTHONDONTWRITEBYTECODE=1",
    )
    if plan.step["mount_profile"] == "wheel-only.v1":
        return common
    pythonpath = "/opt/governance-toolchain/python"
    if plan.step["mount_profile"] == "evaluator-toolchain.v1":
        pythonpath = f"/workspace:{pythonpath}"
    return (
        *common,
        f"PYTHONPATH={pythonpath}",
        "GIT_EXEC_PATH=/opt/governance-toolchain/git/bin",
        "GIT_TEMPLATE_DIR=/opt/governance-toolchain/git/templates",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
    )


def _mounts(
    plan: ExecutionPlanV2,
    paths: RuntimePaths,
    evaluator_root: Path,
    toolchain_root: Path | None,
) -> list[tuple[Path, str, bool]]:
    profile = plan.step["mount_profile"]
    mounts: list[tuple[Path, str, bool]] = []
    if profile != "wheel-only.v1":
        mounts.append((paths.workspace, "/workspace", False))
        if toolchain_root is None:
            raise DockerRuntimeError("toolchain mount is missing")
        mounts.append((toolchain_root, "/opt/governance-toolchain", True))
    mounts.extend(_judge_mounts(plan, evaluator_root))
    mounts.append((paths.scope, "/scope", True))
    if plan.step["capability"] in {"build", "benchmark"}:
        mounts.append((paths.staging, "/governance-output", False))
    if profile == "wheel-only.v1":
        mounts.append((paths.input, "/input", True))
    if profile == "target-toolchain-base-tests.v1":
        mounts.append((paths.base_tests, "/workspace/tests", True))
    return mounts


def _judge_mounts(
    plan: ExecutionPlanV2, evaluator_root: Path
) -> list[tuple[Path, str, bool]]:
    relative = {
        "python.mypy.v1": "governance_eval/judges/mypy_v1.ini",
        "python.unittest.v1": "governance_eval/judges/unittest_gate_v1.py",
        "python.package-audit-isolated.v1": (
            "governance_eval/judges/package_audit_v1.py"
        ),
    }.get(plan.step["adapter_id"])
    if relative is None:
        return []
    source = evaluator_root.resolve(strict=True).joinpath(
        *PurePosixPath(relative).parts
    )
    if not source.is_file() or _is_link_or_junction(source):
        raise DockerRuntimeError("evaluator-owned judge asset is unavailable")
    return [(source, f"/opt/governance-judge/{relative}", True)]


def _capture_artifacts(
    plan: ExecutionPlanV2,
    paths: RuntimePaths,
    outcome: DockerProcessResult,
) -> tuple[list[dict[str, Any]], list[str]]:
    if outcome.termination != "EXITED" or outcome.exit_code != 0 or outcome.errors:
        return [], []
    capability = plan.step["capability"]
    if capability == "build":
        return _capture_wheel(paths.staging, paths.output)
    if capability == "benchmark":
        return _capture_benchmark(paths.staging, paths.output)
    if capability in _SUMMARY_MARKERS:
        return _capture_summary(
            paths.output,
            plan,
            _SUMMARY_MARKERS[capability],
            outcome.stdout,
        )
    return [], []


def _capture_wheel(
    staging: Path, output: Path
) -> tuple[list[dict[str, Any]], list[str]]:
    files = _safe_staged_files(staging, allowed_directories=set())
    if len(files) != 1 or files[0].parent != staging or files[0].suffix != ".whl":
        return [], ["wheel build did not produce exactly one top-level wheel"]
    sealed = _seal_staged_file(files[0], output / files[0].name)
    return [_artifact("python-wheel", "python-wheel", sealed)], []


def _capture_benchmark(
    staging: Path, output: Path
) -> tuple[list[dict[str, Any]], list[str]]:
    phase1 = staging / "phase1"
    files = _safe_staged_files(staging, allowed_directories={"phase1"})
    latest = phase1 / "governance-benchmark-latest.json"
    run_files = [
        path
        for path in files
        if path.parent == phase1
        and path.name.startswith("governance-benchmark-")
        and path.name != latest.name
        and path.suffix == ".json"
    ]
    if set(files) != {latest, *run_files} or len(run_files) != 1:
        return [], ["Phase 1 benchmark artifact inventory is invalid"]
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
        validate_benchmark_result(payload)
    except (OSError, ValueError) as exc:
        return [], [f"Phase 1 benchmark artifact is invalid: {type(exc).__name__}"]
    metrics = payload.get("metrics", {})
    if (
        payload.get("phase1_decision") != BENCHMARK_PASS
        or metrics.get("critical_defect_recall") != 1.0
        or metrics.get("false_blocks") != 0
        or metrics.get("deterministic_flake_rate") != 0.0
        or payload.get("repeat_count") != 3
    ):
        return [], ["Phase 1 benchmark acceptance metrics failed"]
    if latest.read_bytes() != run_files[0].read_bytes():
        return [], ["Phase 1 benchmark artifacts disagree"]
    sealed = _seal_staged_file(latest, output / latest.name)
    return [_artifact("phase1-benchmark", "phase1-benchmark", sealed)], []


def _safe_staged_files(root: Path, *, allowed_directories: set[str]) -> list[Path]:
    if _is_link_or_junction(root):
        raise DockerRuntimeError("artifact staging root is unsafe")
    files: list[Path] = []
    directories: set[str] = set()
    total = 0
    for path in root.rglob("*"):
        if _is_link_or_junction(path):
            raise DockerRuntimeError("staged artifact path is unsafe")
        relative = path.relative_to(root).as_posix()
        _canonical_path(relative)
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            directories.add(relative)
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DockerRuntimeError("staged artifact node is unsupported")
        size = metadata.st_size
        if size > 64 * 1024 * 1024:
            raise DockerRuntimeError("staged artifact exceeds file size limit")
        total += size
        files.append(path)
    if len(files) > 32 or total > 256 * 1024 * 1024:
        raise DockerRuntimeError("staged artifact inventory exceeds limits")
    if directories != allowed_directories:
        raise DockerRuntimeError("staged artifact directory inventory is invalid")
    return sorted(files)


def _seal_staged_file(source: Path, destination: Path) -> Path:
    if destination.exists() or destination.is_symlink():
        raise DockerRuntimeError("sealed artifact destination already exists")
    partial = destination.with_name(f".{destination.name}.partial")
    source_descriptor = -1
    destination_descriptor = -1
    failure: BaseException | None = None
    try:
        source_descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 64 * 1024 * 1024
        ):
            raise DockerRuntimeError("staged artifact changed before sealing")
        destination_descriptor = os.open(
            partial,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        digest = sha256()
        total = _copy_descriptors(source_descriptor, destination_descriptor, digest)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
        if not _same_file_snapshot(before, after) or total != before.st_size:
            raise DockerRuntimeError("staged artifact changed while sealing")
    except (DockerRuntimeError, OSError, ValueError) as exc:
        failure = exc
    finally:
        for descriptor in (destination_descriptor, source_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
    if failure is not None:
        _unlink_partial(partial)
        raise DockerRuntimeError("staged artifact sealing failed") from failure
    if sha256_file(partial, max_bytes=64 * 1024 * 1024) != digest.hexdigest():
        _unlink_partial(partial)
        raise DockerRuntimeError("sealed artifact differs from staging")
    try:
        _make_read_only(partial)
        os.replace(partial, destination)
    except OSError as exc:
        _unlink_partial(partial)
        _unlink_partial(destination)
        raise DockerRuntimeError("sealed artifact publication failed") from exc
    return destination


def _copy_descriptors(source: int, destination: int, digest: Any) -> int:
    total = 0
    while chunk := os.read(source, 1024 * 1024):
        total += len(chunk)
        if total > 64 * 1024 * 1024:
            raise DockerRuntimeError("staged artifact exceeds file size limit")
        digest.update(chunk)
        position = 0
        while position < len(chunk):
            written = os.write(destination, chunk[position:])
            if written <= 0:
                raise DockerRuntimeError("sealed artifact write did not progress")
            position += written
    return total


def _same_file_snapshot(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _unlink_partial(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _capture_summary(
    output: Path,
    plan: ExecutionPlanV2,
    marker: bytes,
    stdout: bytes,
) -> tuple[list[dict[str, Any]], list[str]]:
    capability = plan.step["capability"]
    matches = [
        line[len(marker) :] for line in stdout.splitlines() if line.startswith(marker)
    ]
    if len(matches) != 1:
        return [], [f"{capability} summary marker is missing or duplicated"]
    try:
        payload = json.loads(
            matches[0].decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        _validate_summary_payload(plan, payload)
    except (UnicodeDecodeError, json.JSONDecodeError, DockerRuntimeError):
        return [], [f"{capability} summary is malformed"]
    name = plan_artifact_name(capability)
    path = output / f"{name}.json"
    _write_canonical_json(path, payload)
    return [_artifact(name, name, path)], []


def _validate_summary_payload(plan: ExecutionPlanV2, payload: object) -> None:
    if not isinstance(payload, dict):
        raise DockerRuntimeError("adapter summary is not an object")
    if plan.step["capability"] == "tests":
        _validate_unittest_summary(payload)
    elif plan.step["capability"] == "package_audit":
        _validate_package_summary(plan, payload)
    else:
        raise DockerRuntimeError("adapter summary capability is unsupported")


def _validate_unittest_summary(payload: Mapping[str, object]) -> None:
    keys = {
        "tests_run",
        "failures",
        "errors",
        "skipped",
        "unexpected_successes",
    }
    if set(payload) != keys:
        raise DockerRuntimeError("unittest summary shape is invalid")
    counts = {key: _required_count(payload[key]) for key in keys}
    tests = counts["tests_run"]
    if (
        tests < 1
        or counts["skipped"] >= tests
        or any(counts[key] != 0 for key in keys - {"tests_run", "skipped"})
    ):
        raise DockerRuntimeError("unittest summary outcome is invalid")


def _validate_package_summary(
    plan: ExecutionPlanV2, payload: Mapping[str, object]
) -> None:
    if set(payload) != {"wheel", "sha256", "files", "top_levels"}:
        raise DockerRuntimeError("package summary shape is invalid")
    artifact = plan.inputs["artifacts"][0]
    top_levels = payload["top_levels"]
    valid_top_levels = _valid_top_levels(top_levels)
    file_count = _required_count(payload["files"])
    if (
        payload["wheel"] != artifact["filename"]
        or payload["sha256"] != artifact["sha256"]
        or not 1 <= file_count <= 20_000
        or valid_top_levels != sorted(set(valid_top_levels))
    ):
        raise DockerRuntimeError("package summary identity is invalid")


def _required_count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DockerRuntimeError("adapter summary count is invalid")
    return value


def _valid_top_levels(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise DockerRuntimeError("package summary top levels are invalid")
    if any(
        not isinstance(item, str) or re.fullmatch(r"[A-Za-z_]\w*", item) is None
        for item in value
    ):
        raise DockerRuntimeError("package summary top levels are invalid")
    return value


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DockerRuntimeError("adapter summary has duplicate keys")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise DockerRuntimeError(f"adapter summary contains {value}")


def plan_artifact_name(capability: str) -> str:
    return {
        "tests": "unittest-summary",
        "package_audit": "package-audit-summary",
    }[capability]


def _execute_trusted_judge(
    plan: ExecutionPlanV2,
    receipt: Mapping[str, Any],
    target_root: Path,
    paths: RuntimePaths,
    scope_manifest: Mapping[str, object],
) -> tuple[DockerProcessResult, list[dict[str, Any]]]:
    started = datetime.now(UTC)
    errors: list[str] = []
    exit_code = 1
    stdout = b""
    artifact_name = plan.step["expected_artifacts"][0]
    artifact_path = paths.output / f"{artifact_name}.json"
    try:
        if plan.step["operation_id"] == "governance.architecture.authenticated.v1":
            result, exit_code = _run_architecture(
                receipt, target_root, paths, scope_manifest
            )
        elif plan.step["operation_id"] == "git.diff-check.authenticated.v1":
            result, exit_code = _run_diff_check(receipt, target_root, paths)
        else:
            raise DockerRuntimeError("trusted judge operation is unsupported")
        _write_canonical_json(artifact_path, result)
        stdout = json.dumps(result, sort_keys=True).encode("utf-8")
    except (DockerRuntimeError, OSError, ValueError) as exc:
        errors.append(_bounded_error(exc))
    completed = datetime.now(UTC)
    command = (
        receipt["runtime"]["python"]["path"],
        "trusted-operation",
        plan.step["operation_id"],
    )
    record = DockerCommandRecord(
        command=command,
        termination="EXITED",
        exit_code=exit_code,
        stdout=stdout,
        stderr=b"",
        started_at=started,
        completed_at=completed,
        errors=tuple(errors),
    )
    outcome = DockerProcessResult(
        command=command,
        termination=record.termination,
        exit_code=record.exit_code,
        stdout=record.stdout,
        stderr=record.stderr,
        started_at=record.started_at,
        completed_at=record.completed_at,
        errors=record.errors,
        stdout_truncated=record.stdout_truncated,
        stderr_truncated=record.stderr_truncated,
        records=(record,),
    )
    artifacts = (
        [_artifact(artifact_name, artifact_name, artifact_path)]
        if exit_code == 0 and not errors
        else []
    )
    return outcome, artifacts


def _run_architecture(
    receipt: Mapping[str, Any],
    target_root: Path,
    paths: RuntimePaths,
    scope_manifest: Mapping[str, object],
) -> tuple[dict[str, Any], int]:
    config = paths.root / "authenticated-supportability.yml"
    config.write_bytes(
        _git_show(
            receipt,
            target_root,
            receipt["policy"]["commit_sha"],
            receipt["policy"]["config"]["path"],
        )
    )
    changed = [str(entry["path"]) for entry in _manifest_entries(scope_manifest)]
    return run_architecture_gate(
        config,
        target_root,
        receipt["pull_request"]["base"]["commit_sha"],
        receipt["pull_request"]["head"]["commit_sha"],
        output_dir=None,
        changed_files=changed,
    )


def _run_diff_check(
    receipt: Mapping[str, Any], target_root: Path, paths: RuntimePaths
) -> tuple[dict[str, Any], int]:
    git = Path(receipt["runtime"]["git"]["path"])
    git_dir = paths.root / "diff.git"
    _host_git(git, target_root, "init", "--bare", str(git_dir))
    alternates = git_dir / "objects/info/alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str((target_root / ".git/objects").resolve()) + "\n")
    attributes = git_dir / "info/attributes"
    attributes.parent.mkdir(parents=True, exist_ok=True)
    attributes.write_text("* whitespace\n", encoding="utf-8")
    base = receipt["pull_request"]["base"]["commit_sha"]
    head = receipt["pull_request"]["head"]["commit_sha"]
    completed = subprocess.run(
        [
            str(git),
            f"--git-dir={git_dir}",
            "-c",
            "core.hooksPath=/dev/null",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--check",
            base,
            head,
            "--",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        env=_git_environment(git),
    )
    output = (completed.stdout + completed.stderr)[:65_536].decode(
        "utf-8", errors="replace"
    )
    result = {
        "operation": "git.diff-check.authenticated.v1",
        "base_sha": base,
        "head_sha": head,
        "exit_code": completed.returncode,
        "output": output,
    }
    return result, completed.returncode


def _host_git(git: Path, root: Path, *arguments: str) -> None:
    completed = subprocess.run(
        [str(git), *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        env=_git_environment(git),
    )
    if completed.returncode != 0:
        raise DockerRuntimeError("trusted Git setup command failed")


def _git_show(receipt: Mapping[str, Any], root: Path, commit: str, path: str) -> bytes:
    git = Path(receipt["runtime"]["git"]["path"])
    return _git(
        git,
        root,
        "show",
        f"{commit}:{path}",
        output_limit=4 * 1024 * 1024,
    )


def _artifact(kind: str, name: str, path: Path) -> dict[str, Any]:
    if not path.is_file() or _is_link_or_junction(path):
        raise DockerRuntimeError("expected artifact is not a regular file")
    return {
        "kind": kind,
        "name": name,
        "filename": path.name,
        "sha256": sha256_file(path, max_bytes=64 * 1024 * 1024),
        "size_bytes": path.stat().st_size,
    }


def _execution_result(
    plan: ExecutionPlanV2,
    started: datetime,
    completed: datetime,
    command: list[str],
    outcome: DockerProcessResult | None,
    records: Sequence[DockerCommandRecord],
    artifacts: list[dict[str, Any]],
    errors: list[str],
    scope_manifest: Mapping[str, object],
) -> dict[str, Any]:
    streams = _empty_stream()
    termination = "NOT_STARTED"
    exit_code = None
    if outcome is not None:
        termination = outcome.termination
        exit_code = outcome.exit_code
        stdout = _stream(outcome.stdout, outcome.stdout_truncated)
        stderr = _stream(outcome.stderr, outcome.stderr_truncated)
    else:
        stdout = deepcopy(streams)
        stderr = deepcopy(streams)
    all_errors = [
        *_bounded_errors(errors),
        *([] if outcome is None else _bounded_errors(outcome.errors)),
    ]
    passed = (
        outcome is not None
        and termination == "EXITED"
        and exit_code == 0
        and not all_errors
        and sorted(item["name"] for item in artifacts)
        == sorted(plan.step["expected_artifacts"])
    )
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "receipt_kind": "execution_result.v2",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": plan.checkout_receipt_id,
        "capability": plan.step["capability"],
        "adapter_id": plan.step["adapter_id"],
        "capability_status": "PASS" if passed else "BLOCK_TECHNICAL",
        "runtime": deepcopy(plan.runtime),
        "command": command,
        "scope": {
            "rule_id": plan.step["scope_rule_id"],
            "manifest_id": plan.inputs["scope_manifest_id"],
            "file_count": len(_manifest_entries(scope_manifest)),
        },
        "artifacts": artifacts,
        "processes": [_process_record(record) for record in records],
        "started_at": _timestamp(started),
        "completed_at": _timestamp(completed),
        "duration_seconds": round((completed - started).total_seconds(), 6),
        "timeout_seconds": plan.step["timeout_seconds"],
        "total_timeout_seconds": plan.step["total_timeout_seconds"],
        "termination": termination,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "errors": all_errors,
    }
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
    return payload


def _process_record(record: DockerCommandRecord) -> dict[str, Any]:
    return {
        "command": list(record.command),
        "termination": record.termination,
        "exit_code": record.exit_code,
        "stdout": _stream(record.stdout, record.stdout_truncated),
        "stderr": _stream(record.stderr, record.stderr_truncated),
        "started_at": _timestamp(record.started_at),
        "completed_at": _timestamp(record.completed_at),
        "duration_seconds": round(
            (record.completed_at - record.started_at).total_seconds(), 6
        ),
        "errors": _bounded_errors(record.errors),
    }


def _stream(content: bytes, truncated: bool = False) -> dict[str, Any]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": truncated,
    }


def _empty_stream() -> dict[str, Any]:
    return _stream(b"")


def _post_execution_checks(
    plan: ExecutionPlanV2,
    receipt: Mapping[str, Any] | None,
    target_root: Path,
    evaluator_root: Path,
    scope_manifest: Mapping[str, object],
) -> list[str]:
    if receipt is None:
        return []
    try:
        expected = build_scope_manifest(
            receipt=receipt,
            adapter=_plan_adapter(plan),
            target_root=target_root,
            evaluator_root=evaluator_root,
        )
    except Exception:
        return ["target or evaluator checkout changed during execution"]
    return (
        []
        if expected == scope_manifest
        else ["authenticated scope changed during execution"]
    )


def _cleanup_runtime(paths: RuntimePaths | None) -> list[str]:
    if paths is None:
        return []
    try:
        _remove_tree_no_follow(paths.root, paths.root)
    except OSError:
        return ["disposable runtime root cleanup failed"]
    return [] if not paths.root.exists() else ["disposable runtime root cleanup failed"]


def _remove_tree_no_follow(path: Path, root: Path) -> None:
    if path != root and not _inside(path, root):
        raise OSError("cleanup path escaped runtime root")
    if _is_link_or_junction(path):
        _remove_link_node(path)
        return
    with os.scandir(path) as entries:
        for entry in entries:
            child = Path(entry.path)
            if entry.is_symlink() or _is_link_or_junction(child):
                _remove_link_node(child)
            elif entry.is_dir(follow_symlinks=False):
                _remove_tree_no_follow(child, root)
            else:
                _unlink_no_follow(child)
    _chmod_no_follow(path, 0o700)
    path.rmdir()


def _remove_link_node(path: Path) -> None:
    junction = getattr(path, "is_junction", None)
    if junction and junction():
        path.rmdir()
    else:
        path.unlink()


def _unlink_no_follow(path: Path) -> None:
    try:
        path.unlink()
    except PermissionError:
        _chmod_no_follow(path, 0o600)
        path.unlink()


def _chmod_no_follow(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (NotImplementedError, TypeError):
        if _is_link_or_junction(path):
            raise OSError("cleanup refused to follow a link")
        os.chmod(path, mode)


def _write_canonical_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _manifest_entries(
    scope_manifest: Mapping[str, object],
) -> list[Mapping[str, Any]]:
    value = scope_manifest.get("entries")
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise DockerRuntimeError("scope manifest entries are invalid")
    return value


def _canonical_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
        or path.as_posix() != value
    ):
        raise DockerRuntimeError("authenticated Git path is unsafe")
    return path


def _safe_destination(root: Path, value: str) -> Path:
    path = _canonical_path(value)
    destination = root.joinpath(*path.parts).resolve(strict=False)
    if not _inside(destination, root.resolve()):
        raise DockerRuntimeError("authenticated Git path escapes workspace")
    return destination


def _make_container_writable(root: Path) -> None:
    if os.name == "nt":
        return
    root.chmod(0o777)


def _make_read_only(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o444)


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _extend_records(
    destination: list[DockerCommandRecord], source: Sequence[DockerCommandRecord]
) -> None:
    for record in source:
        if record not in destination:
            destination.append(record)


def _bounded_error(error: BaseException) -> str:
    value = str(error).strip() or type(error).__name__
    return value[:2048]


def _bounded_errors(errors: Sequence[str]) -> list[str]:
    return [str(error)[:2048] for error in errors if str(error)][:64]


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
