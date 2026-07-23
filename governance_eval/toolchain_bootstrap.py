from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import venv
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

RUFF_VERSION = "0.15.21"
MYPY_VERSION = "2.2.0"
SETUPTOOLS_VERSION = "83.0.0"
AST_SERIALIZE_VERSION = "0.6.0"
LIBRT_VERSION = "0.13.0"
MYPY_EXTENSIONS_VERSION = "1.1.0"
PATHSPEC_VERSION = "1.1.1"
TYPING_EXTENSIONS_VERSION = "4.16.0"
LOCK_NAME = "requirements-governance.lock"
_PYTHON_VERSION = (3, 12, 13)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_POSITIVE_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,120}$")
_ARTIFACT_DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
_PUBLICATION_CONTEXT_FIELDS = (
    "repository",
    "repository_id",
    "head_repository_id",
    "event_name",
    "pull_request_number",
    "base_sha",
    "head_sha",
    "workflow_ref",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "expected_artifact_name",
)
_EVALUATION_CONTEXT_FIELDS = (
    "context_kind",
    "repository",
    "repository_id",
    "head_repository_id",
    "event_name",
    "event_action",
    "pull_request_number",
    "target_base_sha",
    "target_head_sha",
    "evaluator_sha",
    "workflow_ref",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "expected_artifact_name",
)
_SHADOW_CONTEXT_FIELDS = (
    "context_kind",
    "repository",
    "repository_id",
    "head_repository_id",
    "event_name",
    "pull_request_number",
    "base_sha",
    "head_sha",
    "workflow_ref",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "expected_artifact_name",
)
_EVALUATION_ACTIONS = frozenset(
    {"opened", "reopened", "synchronize", "ready_for_review"}
)
_ARTIFACT_AUTHORITY_FIELDS = (
    "artifact_id",
    "artifact_name",
    "artifact_digest",
    "expired",
    "workflow_run_id",
    "workflow_run_attempt",
    "repository",
    "repository_id",
    "head_repository_id",
    "head_sha",
    "event_name",
    "pull_request_number",
)
_RUFF_PROBE = (
    "import importlib.metadata, json, pathlib, ruff; "
    "print(json.dumps({'version': importlib.metadata.version('ruff'), "
    "'origin': str(pathlib.Path(ruff.__file__).resolve())}, sort_keys=True))"
)
_RUFF_HASHES = frozenset(
    {
        "sha256:bab0905d2f29e0d9fbc3c373ed23db0095edaa3f71f1f4f519ec15134d9e85c8",
        "sha256:d4b8d9a2f0f12b816b50447f6eccb9f4bb01a6b82c86b50fb3b5354b458dc6d3",
    }
)
_MYPY_HASHES = frozenset(
    {
        "sha256:511320b17467402e2906130e185abffffa3d7648aff1444fc2abb61f4c8a087d",
        "sha256:b0179a3a0b833f724a65f22613607cf7ea941ab17ec34fa283f8d6dfe21d9fa9",
    }
)
_SETUPTOOLS_HASHES = frozenset(
    {
        "sha256:025bccbbf0fa05b6192bc64ae1e7b16e001fd6d6d4d5de03c97b1c1ade523bef",
        "sha256:29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3",
    }
)
_AST_SERIALIZE_HASHES = frozenset(
    {
        "sha256:113b58346f9ceb664352032770caca817d4a3c86f611c6088e6ef65ddaa70f0e",
        "sha256:dcbed41e9386059fc0261d602445ede0976c2ecec2939688bcbcb9ed0b6f28b7",
    }
)
_LIBRT_HASHES = frozenset(
    {
        "sha256:b222493da6e7b6199db9bd79502436cf5a27da3c1f7fa83c7e285444fc93fd03",
        "sha256:e54a315caf843c8d77e388cadc56ea9ded569935ee2d2347d7ea94992e5aa6fa",
    }
)
_MYPY_EXTENSIONS_HASHES = frozenset(
    {
        "sha256:1be4cccdb0f2482337c4743e60421de3a356cd97508abadd57d47403e94f5505",
    }
)
_PATHSPEC_HASHES = frozenset(
    {
        "sha256:a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189",
    }
)
_TYPING_EXTENSIONS_HASHES = frozenset(
    {
        "sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
    }
)
_APPROVED_LOCK_REQUIREMENTS = (
    (f"ruff=={RUFF_VERSION}", _RUFF_HASHES),
    (f"mypy=={MYPY_VERSION}", _MYPY_HASHES),
    (f"setuptools=={SETUPTOOLS_VERSION}", _SETUPTOOLS_HASHES),
    (f"ast-serialize=={AST_SERIALIZE_VERSION}", _AST_SERIALIZE_HASHES),
    (f"librt=={LIBRT_VERSION}", _LIBRT_HASHES),
    (f"mypy-extensions=={MYPY_EXTENSIONS_VERSION}", _MYPY_EXTENSIONS_HASHES),
    (f"pathspec=={PATHSPEC_VERSION}", _PATHSPEC_HASHES),
    (f"typing-extensions=={TYPING_EXTENSIONS_VERSION}", _TYPING_EXTENSIONS_HASHES),
)
_TOOLCHAIN_PACKAGES = (
    {"name": "ruff", "version": RUFF_VERSION},
    {"name": "mypy", "version": MYPY_VERSION},
    {"name": "setuptools", "version": SETUPTOOLS_VERSION},
    {"name": "ast-serialize", "version": AST_SERIALIZE_VERSION},
    {"name": "librt", "version": LIBRT_VERSION},
    {"name": "mypy-extensions", "version": MYPY_EXTENSIONS_VERSION},
    {"name": "pathspec", "version": PATHSPEC_VERSION},
    {"name": "typing-extensions", "version": TYPING_EXTENSIONS_VERSION},
)
_SAFE_ENV_KEYS = (
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
)


class BootstrapError(RuntimeError):
    pass


def validate_lock(lock_path: Path) -> str:
    try:
        payload = lock_path.read_bytes()
    except OSError as exc:
        raise BootstrapError(f"toolchain lock unavailable: {exc}") from exc
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BootstrapError("toolchain lock must be UTF-8") from exc
    logical_lines = _logical_requirement_lines(text)
    if len(logical_lines) != len(_APPROVED_LOCK_REQUIREMENTS):
        raise BootstrapError("toolchain lock must contain exact approved requirements")
    for logical_line, (requirement, approved_hashes) in zip(
        logical_lines, _APPROVED_LOCK_REQUIREMENTS, strict=True
    ):
        try:
            tokens = shlex.split(logical_line, posix=True)
        except ValueError as exc:
            raise BootstrapError(f"toolchain lock syntax invalid: {exc}") from exc
        if not tokens or tokens[0] != requirement:
            raise BootstrapError(f"toolchain lock must pin {requirement}")
        hash_tokens = tokens[1:]
        if len(hash_tokens) != len(approved_hashes):
            raise BootstrapError("toolchain lock hash count invalid")
        parsed_hashes = {
            token.removeprefix("--hash=")
            for token in hash_tokens
            if token.startswith("--hash=")
        }
        if parsed_hashes != approved_hashes:
            raise BootstrapError(
                "toolchain lock hashes do not match approved artifacts"
            )
    return hashlib.sha256(payload).hexdigest()


def toolchain_packages() -> list[dict[str, str]]:
    return [dict(item) for item in _TOOLCHAIN_PACKAGES]


def _logical_requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        parts.append(line[:-1].rstrip() if continued else line)
        if not continued:
            lines.append(" ".join(parts))
            parts = []
    if parts:
        raise BootstrapError("toolchain lock has an unterminated continuation")
    return lines


def sanitized_pip_environment(
    runtime_bin: Path, source: Mapping[str, str]
) -> dict[str, str]:
    environment = {key: source[key] for key in _SAFE_ENV_KEYS if source.get(key)}
    environment.update(
        {
            "PATH": str(runtime_bin),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def sanitized_git_environment(source: Mapping[str, str]) -> dict[str, str]:
    environment = {key: source[key] for key in _SAFE_ENV_KEYS if source.get(key)}
    environment.update(
        {
            "GCM_INTERACTIVE": "Never",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def pip_install_command(
    python_path: Path | PurePosixPath | PureWindowsPath,
    lock_path: Path | PurePosixPath | PureWindowsPath,
) -> tuple[str, ...]:
    return (
        str(python_path),
        "-I",
        "-m",
        "pip",
        "install",
        "--require-virtualenv",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-deps",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "--no-input",
        "--index-url",
        "https://pypi.org/simple",
        "-r",
        str(lock_path),
    )


def _run(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout_seconds: int,
    command_evidence: list[dict[str, object]],
) -> subprocess.CompletedProcess[str]:
    started_at = _utc_now()
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(environment),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        command_evidence.append(
            _command_record(
                command,
                started_at,
                timeout_seconds,
                None,
                True,
                exc.stdout,
                exc.stderr,
            )
        )
        raise BootstrapError(
            f"toolchain command timed out after {timeout_seconds}s: {command[0]}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        command_evidence.append(
            _command_record(
                command,
                started_at,
                timeout_seconds,
                exc.returncode,
                False,
                exc.stdout,
                exc.stderr,
            )
        )
        detail = (exc.stderr or exc.stdout or "no output").strip()
        raise BootstrapError(f"toolchain command failed: {detail}") from exc
    except OSError as exc:
        command_evidence.append(
            _command_record(
                command, started_at, timeout_seconds, None, False, None, None
            )
        )
        raise BootstrapError(f"toolchain command could not start: {exc}") from exc
    command_evidence.append(
        _command_record(
            command,
            started_at,
            timeout_seconds,
            completed.returncode,
            False,
            completed.stdout,
            completed.stderr,
        )
    )
    return completed


def _command_record(
    command: Sequence[str],
    started_at: str,
    timeout_seconds: int,
    exit_code: int | None,
    timed_out: bool,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
) -> dict[str, object]:
    return {
        "command": list(command),
        "started_at": started_at,
        "completed_at": _utc_now(),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "stdout_sha256": _stream_sha256(stdout),
        "stderr_sha256": _stream_sha256(stderr),
    }


def _stream_sha256(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _payload_sha256(receipt: Mapping[str, object]) -> str:
    payload = {key: value for key, value in receipt.items() if key != "payload_sha256"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _attach_payload_sha256(receipt: dict[str, object]) -> dict[str, object]:
    receipt["payload_sha256"] = _payload_sha256(receipt)
    return receipt


def validate_receipt(
    governance_root: Path,
    receipt: Mapping[str, object],
    expected_context: Mapping[str, object],
) -> None:
    expected, context_kind = _validated_context(expected_context)
    schema_name = {
        "PUBLICATION": "governance_toolchain_receipt.schema.json",
        "SUPPORTABILITY_EVALUATION": "governance_toolchain_evaluation_receipt.schema.json",
        "PHASE1_SHADOW": "governance_toolchain_shadow_receipt.schema.json",
    }[context_kind]
    _validate_schema(governance_root, schema_name, receipt)
    _validate_payload_digest(receipt, "toolchain receipt")
    _validate_context_binding(receipt, expected)
    _validate_receipt_semantics(governance_root, receipt)


def _validate_schema(
    governance_root: Path, schema_name: str, payload: Mapping[str, object]
) -> None:
    schema_path = governance_root / "schemas/v1" / schema_name
    validator_path = governance_root / "governance_eval/schema_validator.py"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = runpy.run_path(str(validator_path)).get("validate")
    if not callable(validator):
        raise BootstrapError("governance schema validator unavailable")
    validator(dict(payload), schema)


def _validate_payload_digest(payload: Mapping[str, object], label: str) -> None:
    claimed_payload_sha256 = payload.get("payload_sha256")
    actual_payload_sha256 = _payload_sha256(payload)
    if not isinstance(claimed_payload_sha256, str) or not hmac.compare_digest(
        claimed_payload_sha256, actual_payload_sha256
    ):
        raise BootstrapError(f"{label} payload digest invalid")


def _validated_publication_context(
    value: Mapping[str, object],
) -> dict[str, object]:
    context = dict(value)
    if set(context) != set(_PUBLICATION_CONTEXT_FIELDS):
        raise BootstrapError("authoritative publication context fields invalid")
    strings = (
        "repository",
        "repository_id",
        "head_repository_id",
        "event_name",
        "base_sha",
        "head_sha",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "expected_artifact_name",
    )
    if any(not isinstance(context.get(key), str) for key in strings):
        raise BootstrapError("authoritative publication context types invalid")
    if not _REPOSITORY_RE.fullmatch(str(context["repository"])):
        raise BootstrapError("authoritative repository invalid")
    for key in ("repository_id", "head_repository_id", "run_id", "run_attempt"):
        if not _POSITIVE_ID_RE.fullmatch(str(context[key])):
            raise BootstrapError(f"authoritative {key} invalid")
    _validate_sha("authoritative base SHA", str(context["base_sha"]))
    _validate_sha("authoritative head SHA", str(context["head_sha"]))
    _validate_sha("authoritative workflow SHA", str(context["workflow_sha"]))
    workflow_ref = str(context["workflow_ref"])
    if not workflow_ref or len(workflow_ref) > 500 or "\n" in workflow_ref:
        raise BootstrapError("authoritative workflow ref invalid")
    artifact_name = str(context["expected_artifact_name"])
    if not _ARTIFACT_NAME_RE.fullmatch(artifact_name):
        raise BootstrapError("authoritative artifact name invalid")
    required_artifact_name = (
        f"governance-toolchain-publication-{context['run_id']}-{context['run_attempt']}"
    )
    if artifact_name != required_artifact_name:
        raise BootstrapError("authoritative artifact name is not run-attempt bound")
    _validate_event_pr_binding(context)
    return context


def _validated_evaluation_context(
    value: Mapping[str, object],
) -> dict[str, object]:
    context = dict(value)
    if set(context) != set(_EVALUATION_CONTEXT_FIELDS):
        raise BootstrapError("authoritative evaluation context fields invalid")
    strings = tuple(
        field for field in _EVALUATION_CONTEXT_FIELDS if field != "pull_request_number"
    )
    if any(not isinstance(context.get(key), str) for key in strings):
        raise BootstrapError("authoritative evaluation context types invalid")
    _validate_context_identity(
        context,
        expected_kind="SUPPORTABILITY_EVALUATION",
        label="evaluation",
    )
    if context["event_name"] != "pull_request_target":
        raise BootstrapError("authoritative evaluation event invalid")
    if context["event_action"] not in _EVALUATION_ACTIONS:
        raise BootstrapError("authoritative evaluation action invalid")
    pull_request_number = context["pull_request_number"]
    if not isinstance(pull_request_number, int) or pull_request_number < 1:
        raise BootstrapError("supportability evaluation requires a PR number")
    for key in ("target_base_sha", "target_head_sha", "evaluator_sha", "workflow_sha"):
        _validate_sha(f"authoritative evaluation {key}", str(context[key]))
    workflow_ref = str(context["workflow_ref"])
    if (
        not workflow_ref.endswith(
            "/.github/workflows/supportability-enforcement.yml@refs/heads/main"
        )
        or "\n" in workflow_ref
        or len(workflow_ref) > 500
    ):
        raise BootstrapError("authoritative evaluation workflow ref invalid")
    if context["run_attempt"] != "1":
        raise BootstrapError("supportability evaluation requires run attempt 1")
    if not _ARTIFACT_NAME_RE.fullmatch(str(context["expected_artifact_name"])):
        raise BootstrapError("authoritative evaluation artifact name invalid")
    return context


def _validated_shadow_context(value: Mapping[str, object]) -> dict[str, object]:
    context = dict(value)
    if set(context) != set(_SHADOW_CONTEXT_FIELDS):
        raise BootstrapError("authoritative shadow context fields invalid")
    strings = tuple(
        field for field in _SHADOW_CONTEXT_FIELDS if field != "pull_request_number"
    )
    if any(not isinstance(context.get(key), str) for key in strings):
        raise BootstrapError("authoritative shadow context types invalid")
    _validate_context_identity(context, expected_kind="PHASE1_SHADOW", label="shadow")
    for key in ("base_sha", "head_sha", "workflow_sha"):
        _validate_sha(f"authoritative shadow {key}", str(context[key]))
    workflow_ref = str(context["workflow_ref"])
    marker = "/.github/workflows/governance-shadow.yml@"
    if marker not in workflow_ref or "\n" in workflow_ref or len(workflow_ref) > 500:
        raise BootstrapError("authoritative shadow workflow ref invalid")
    _validate_shadow_event(context, workflow_ref)
    if context["expected_artifact_name"] != "governance-benchmark-json":
        raise BootstrapError("authoritative shadow artifact name invalid")
    return context


def _validate_context_identity(
    context: Mapping[str, object], *, expected_kind: str, label: str
) -> None:
    if context["context_kind"] != expected_kind:
        raise BootstrapError(f"authoritative {label} context kind invalid")
    if not _REPOSITORY_RE.fullmatch(str(context["repository"])):
        raise BootstrapError(f"authoritative {label} repository invalid")
    for key in ("repository_id", "head_repository_id", "run_id", "run_attempt"):
        if not _POSITIVE_ID_RE.fullmatch(str(context[key])):
            raise BootstrapError(f"authoritative {label} {key} invalid")


def _validate_shadow_event(context: Mapping[str, object], workflow_ref: str) -> None:
    event_name = context["event_name"]
    pull_request_number = context["pull_request_number"]
    if event_name == "pull_request":
        if not isinstance(pull_request_number, int) or pull_request_number < 1:
            raise BootstrapError("pull request shadow requires a PR number")
        return
    if event_name not in {"push", "workflow_dispatch", "merge_group"}:
        raise BootstrapError("authoritative shadow event invalid")
    if pull_request_number is not None:
        raise BootstrapError("non-PR shadow forbids a PR number")
    if context["head_repository_id"] != context["repository_id"]:
        raise BootstrapError("non-PR shadow repository identity mismatch")
    if not workflow_ref.endswith("@refs/heads/main"):
        raise BootstrapError("non-PR shadow requires the main workflow ref")
    if event_name == "workflow_dispatch" and context["base_sha"] != context["head_sha"]:
        raise BootstrapError(
            "workflow dispatch shadow requires identical base and head"
        )


def _validated_context(
    value: Mapping[str, object],
) -> tuple[dict[str, object], str]:
    if set(value) == set(_PUBLICATION_CONTEXT_FIELDS):
        return _validated_publication_context(value), "PUBLICATION"
    if set(value) == set(_EVALUATION_CONTEXT_FIELDS):
        return _validated_evaluation_context(value), "SUPPORTABILITY_EVALUATION"
    if set(value) == set(_SHADOW_CONTEXT_FIELDS):
        return _validated_shadow_context(value), "PHASE1_SHADOW"
    raise BootstrapError("authoritative toolchain context fields invalid")


def _validate_event_pr_binding(context: Mapping[str, object]) -> None:
    event_name = context.get("event_name")
    pull_request_number = context.get("pull_request_number")
    if event_name != "pull_request":
        raise BootstrapError("authoritative event name invalid")
    if not isinstance(pull_request_number, int) or pull_request_number < 1:
        raise BootstrapError("pull request publication requires a PR number")


def _validate_context_binding(
    receipt: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    for key in expected:
        if receipt.get(key) != expected[key]:
            raise BootstrapError(f"toolchain receipt context mismatch: {key}")


def _validate_receipt_semantics(
    governance_root: Path, receipt: Mapping[str, object]
) -> None:
    if receipt.get("status") == "PASS":
        _validate_success_receipt(governance_root, receipt)
    elif receipt.get("status") == "FAIL":
        if receipt.get("decision") != "BLOCK_TECHNICAL" or not isinstance(
            receipt.get("error"), str
        ):
            raise BootstrapError("failed toolchain receipt decision invalid")


def _validate_success_receipt(
    governance_root: Path, receipt: Mapping[str, object]
) -> None:
    required = (
        "checkout_head_sha",
        "merge_base_sha",
        "lock_sha256",
        "governance_root",
        "workspace_root",
        "git_executable",
        "python_path",
        "ruff_module_origin",
        "ruff_executable",
    )
    if receipt.get("decision") != "TOOLCHAIN_READY" or receipt.get("error") is not None:
        raise BootstrapError("successful toolchain receipt decision invalid")
    if any(not isinstance(receipt.get(key), str) for key in required):
        raise BootstrapError("successful toolchain receipt evidence incomplete")
    identities = (
        receipt.get("head_sha"),
        receipt.get("evaluator_sha"),
        receipt.get("claimed_evaluator_sha"),
        receipt.get("checkout_head_sha"),
    )
    if len(set(identities)) != 1 or receipt.get("base_sha") != receipt.get(
        "claimed_base_sha"
    ):
        raise BootstrapError("successful toolchain receipt identity binding invalid")
    if receipt.get("python_version") != "3.12.13":
        raise BootstrapError("successful toolchain receipt Python version invalid")
    if receipt.get("packages") != toolchain_packages():
        raise BootstrapError("successful toolchain receipt package evidence invalid")
    _validate_portable_success_environment(governance_root, receipt)
    if not _valid_success_command_evidence(receipt):
        raise BootstrapError("successful toolchain receipt command evidence invalid")


def _path_identity(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _validate_portable_success_environment(
    governance_root: Path, receipt: Mapping[str, object]
) -> None:
    actual_governance = governance_root.resolve(strict=True)
    if validate_lock(actual_governance / LOCK_NAME) != receipt.get("lock_sha256"):
        raise BootstrapError("successful toolchain receipt lock digest invalid")
    _validate_recorded_path_relationships(receipt)


def _recorded_path(
    value: object, platform_system: object
) -> PurePosixPath | PureWindowsPath:
    if platform_system == "Windows":
        return PureWindowsPath(str(value))
    if platform_system in {"Linux", "Darwin"}:
        return PurePosixPath(str(value))
    raise BootstrapError("successful toolchain receipt platform invalid")


def _pure_is_within(
    path: PurePosixPath | PureWindowsPath,
    parent: PurePosixPath | PureWindowsPath,
) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_recorded_path_relationships(receipt: Mapping[str, object]) -> None:
    system = receipt.get("platform_system")
    governance = _recorded_path(receipt["governance_root"], system)
    workspace = _recorded_path(receipt["workspace_root"], system)
    runtime = _recorded_path(receipt["runtime_root"], system)
    python_path = _recorded_path(receipt["python_path"], system)
    module_origin = _recorded_path(receipt["ruff_module_origin"], system)
    ruff_executable = _recorded_path(receipt["ruff_executable"], system)
    git_executable = _recorded_path(receipt["git_executable"], system)
    paths = (
        governance,
        workspace,
        runtime,
        python_path,
        module_origin,
        ruff_executable,
        git_executable,
    )
    if any(not path.is_absolute() for path in paths):
        raise BootstrapError("successful toolchain receipt path is not absolute")
    if _pure_is_within(runtime, workspace) or _pure_is_within(runtime, governance):
        raise BootstrapError("successful toolchain receipt runtime boundary invalid")
    runtime_bin = runtime / ("Scripts" if system == "Windows" else "bin")
    expected_python = runtime_bin / ("python.exe" if system == "Windows" else "python")
    expected_ruff = runtime_bin / ("ruff.exe" if system == "Windows" else "ruff")
    if python_path != expected_python or ruff_executable != expected_ruff:
        raise BootstrapError("successful toolchain receipt runtime paths invalid")
    if not _pure_is_within(module_origin, runtime):
        raise BootstrapError("successful toolchain receipt Ruff module path invalid")
    if _pure_is_within(git_executable, governance) or _pure_is_within(
        git_executable, workspace
    ):
        raise BootstrapError("successful toolchain receipt Git boundary invalid")


def validate_live_receipt(
    governance_root: Path,
    receipt: Mapping[str, object],
    expected_context: Mapping[str, object],
) -> None:
    validate_receipt(governance_root, receipt, expected_context)
    if receipt.get("status") == "PASS":
        _validate_live_success_environment(governance_root, receipt)


def _validate_live_success_environment(
    governance_root: Path, receipt: Mapping[str, object]
) -> None:
    actual_governance = governance_root.resolve(strict=True)
    recorded_governance = Path(str(receipt["governance_root"]))
    workspace_root = Path(str(receipt["workspace_root"])).resolve(strict=True)
    runtime_root = Path(str(receipt["runtime_root"])).resolve(strict=True)
    if _path_identity(recorded_governance) != _path_identity(actual_governance):
        raise BootstrapError("live toolchain receipt governance root invalid")
    if not workspace_root.is_dir() or not runtime_root.is_dir():
        raise BootstrapError("live toolchain receipt directory invalid")
    if _is_within_any(runtime_root, (workspace_root, actual_governance)):
        raise BootstrapError("live toolchain receipt runtime boundary invalid")
    _validate_success_executables(
        receipt, actual_governance, workspace_root, runtime_root
    )
    if (
        receipt.get("platform_system") != platform.system()
        or receipt.get("platform_machine") != platform.machine()
    ):
        raise BootstrapError("live toolchain receipt platform invalid")


def create_artifact_binding(
    governance_root: Path,
    receipt_path: Path,
    receipt: Mapping[str, object],
    expected_context: Mapping[str, object],
    *,
    artifact_id: str,
    artifact_name: str,
    artifact_url: str,
    artifact_digest: str,
) -> dict[str, object]:
    expected = _validated_publication_context(expected_context)
    validate_receipt(governance_root, receipt, expected)
    receipt_bytes = receipt_path.read_bytes()
    try:
        serialized_receipt = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BootstrapError("serialized toolchain receipt invalid") from exc
    if serialized_receipt != dict(receipt):
        raise BootstrapError("serialized toolchain receipt differs from receipt")
    normalized_digest = _validate_artifact_assignment(
        expected,
        artifact_id=artifact_id,
        artifact_name=artifact_name,
        artifact_url=artifact_url,
        artifact_digest=artifact_digest,
    )
    binding: dict[str, object] = {
        **expected,
        "schema_version": "1.0",
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_url": artifact_url,
        "artifact_digest": normalized_digest,
        "receipt_file_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_payload_sha256": receipt["payload_sha256"],
    }
    _attach_payload_sha256(binding)
    _validate_schema(
        governance_root,
        "governance_toolchain_artifact_binding.schema.json",
        binding,
    )
    _validate_payload_digest(binding, "artifact binding")
    return binding


def _validate_artifact_assignment(
    expected: Mapping[str, object],
    *,
    artifact_id: str,
    artifact_name: str,
    artifact_url: str,
    artifact_digest: str,
) -> str:
    if not _POSITIVE_ID_RE.fullmatch(artifact_id):
        raise BootstrapError("assigned artifact ID invalid")
    if artifact_name != expected["expected_artifact_name"]:
        raise BootstrapError("assigned artifact name differs from expected name")
    expected_url = (
        f"https://github.com/{expected['repository']}/actions/runs/"
        f"{expected['run_id']}/artifacts/{artifact_id}"
    )
    if artifact_url != expected_url:
        raise BootstrapError("assigned artifact URL invalid")
    return _normalized_artifact_digest(artifact_digest)


def _normalized_artifact_digest(value: str) -> str:
    match = _ARTIFACT_DIGEST_RE.fullmatch(value)
    if match is None:
        raise BootstrapError("assigned artifact digest invalid")
    return f"sha256:{match.group(1)}"


def validate_artifact_binding(
    governance_root: Path,
    receipt: Mapping[str, object],
    receipt_bytes: bytes,
    binding: Mapping[str, object],
    expected_context: Mapping[str, object],
    authoritative_artifact: Mapping[str, object],
) -> None:
    expected = _validated_publication_context(expected_context)
    validate_receipt(governance_root, receipt, expected)
    _validate_schema(
        governance_root,
        "governance_toolchain_artifact_binding.schema.json",
        binding,
    )
    _validate_payload_digest(binding, "artifact binding")
    _validate_context_binding(binding, expected)
    if json.loads(receipt_bytes) != dict(receipt):
        raise BootstrapError("bound receipt bytes differ from receipt")
    if binding.get("receipt_file_sha256") != hashlib.sha256(receipt_bytes).hexdigest():
        raise BootstrapError("artifact binding receipt file digest invalid")
    if binding.get("receipt_payload_sha256") != receipt.get("payload_sha256"):
        raise BootstrapError("artifact binding receipt payload digest invalid")
    assigned_digest = _validate_artifact_assignment(
        expected,
        artifact_id=str(binding["artifact_id"]),
        artifact_name=str(binding["artifact_name"]),
        artifact_url=str(binding["artifact_url"]),
        artifact_digest=str(binding["artifact_digest"]),
    )
    if assigned_digest != binding["artifact_digest"]:
        raise BootstrapError("artifact binding assigned digest invalid")
    authority = _validated_artifact_authority(authoritative_artifact)
    _compare_artifact_authority(binding, expected, authority)


def _validated_artifact_authority(
    value: Mapping[str, object],
) -> dict[str, object]:
    authority = dict(value)
    if set(authority) != set(_ARTIFACT_AUTHORITY_FIELDS):
        raise BootstrapError("authoritative artifact metadata fields invalid")
    identifiers = (
        "artifact_id",
        "workflow_run_id",
        "workflow_run_attempt",
        "repository_id",
        "head_repository_id",
    )
    if any(
        not isinstance(authority.get(key), str)
        or not _POSITIVE_ID_RE.fullmatch(str(authority[key]))
        for key in identifiers
    ):
        raise BootstrapError("authoritative artifact identifier invalid")
    if not isinstance(
        authority.get("artifact_name"), str
    ) or not _ARTIFACT_NAME_RE.fullmatch(str(authority["artifact_name"])):
        raise BootstrapError("authoritative artifact name invalid")
    authority["artifact_digest"] = _normalized_artifact_digest(
        str(authority.get("artifact_digest", ""))
    )
    if not isinstance(authority.get("expired"), bool):
        raise BootstrapError("authoritative artifact expiry invalid")
    if not isinstance(authority.get("repository"), str) or not _REPOSITORY_RE.fullmatch(
        str(authority["repository"])
    ):
        raise BootstrapError("authoritative artifact repository invalid")
    _validate_sha("authoritative artifact head SHA", str(authority.get("head_sha", "")))
    if authority.get("event_name") != "pull_request":
        raise BootstrapError("authoritative artifact event invalid")
    pr_number = authority.get("pull_request_number")
    if not isinstance(pr_number, int) or pr_number < 1:
        raise BootstrapError("authoritative artifact PR number invalid")
    return authority


def _compare_artifact_authority(
    binding: Mapping[str, object],
    expected: Mapping[str, object],
    authority: Mapping[str, object],
) -> None:
    comparisons = {
        "artifact_id": binding.get("artifact_id"),
        "artifact_name": binding.get("artifact_name"),
        "artifact_digest": binding.get("artifact_digest"),
        "workflow_run_id": expected["run_id"],
        "workflow_run_attempt": expected["run_attempt"],
        "repository": expected["repository"],
        "repository_id": expected["repository_id"],
        "head_repository_id": expected["head_repository_id"],
        "head_sha": expected["head_sha"],
        "event_name": expected["event_name"],
        "pull_request_number": expected["pull_request_number"],
    }
    for key, expected_value in comparisons.items():
        if authority.get(key) != expected_value:
            raise BootstrapError(f"authoritative artifact mismatch: {key}")
    if authority["expired"]:
        raise BootstrapError("authoritative artifact is expired")


def _validate_success_executables(
    receipt: Mapping[str, object],
    governance_root: Path,
    workspace_root: Path,
    runtime_root: Path,
) -> None:
    python_path, runtime_bin = _runtime_paths(runtime_root)
    recorded_python = Path(str(receipt["python_path"]))
    if (
        _path_identity(recorded_python) != _path_identity(python_path)
        or not recorded_python.is_file()
    ):
        raise BootstrapError("successful toolchain receipt Python path invalid")
    module_origin = Path(str(receipt["ruff_module_origin"])).resolve(strict=True)
    if not module_origin.is_file() or not _is_within(
        module_origin, runtime_root.resolve()
    ):
        raise BootstrapError("successful toolchain receipt Ruff module invalid")
    expected_ruff = (runtime_bin / ("ruff.exe" if os.name == "nt" else "ruff")).resolve(
        strict=True
    )
    recorded_ruff = Path(str(receipt["ruff_executable"])).resolve(strict=True)
    if recorded_ruff != expected_ruff or not recorded_ruff.is_file():
        raise BootstrapError("successful toolchain receipt Ruff executable invalid")
    git_path = Path(str(receipt["git_executable"])).resolve(strict=True)
    if not git_path.is_file() or _is_within_any(
        git_path, (governance_root, workspace_root.resolve())
    ):
        raise BootstrapError("successful toolchain receipt Git executable invalid")


def _valid_success_command_evidence(receipt: Mapping[str, object]) -> bool:
    value = receipt.get("commands")
    if not isinstance(value, list) or len(value) != 11:
        return False
    if any(
        not isinstance(record, dict)
        or record.get("timed_out") is not False
        or record.get("exit_code") != 0
        or not isinstance(record.get("stdout_sha256"), str)
        or not isinstance(record.get("stderr_sha256"), str)
        for record in value
    ):
        return False
    commands = [tuple(record["command"]) for record in value]
    if commands != _expected_success_commands(receipt):
        return False
    if [record.get("timeout_seconds") for record in value] != [
        15,
        15,
        15,
        15,
        15,
        60,
        120,
        30,
        15,
        15,
        15,
    ]:
        return False
    expected_stdout = {
        0: _recorded_path(
            receipt["governance_root"], receipt["platform_system"]
        ).as_posix(),
        1: str(receipt["evaluator_sha"]),
        2: str(receipt["base_sha"]),
        3: str(receipt["merge_base_sha"]),
        4: "",
        8: json.dumps(
            {
                "origin": str(receipt["ruff_module_origin"]),
                "version": RUFF_VERSION,
            },
            sort_keys=True,
        ),
        9: f"ruff {RUFF_VERSION}",
        10: f"mypy {MYPY_VERSION} (compiled: yes)",
    }
    return all(
        value[index].get("stdout_sha256") == _stream_sha256(stdout)
        for index, stdout in expected_stdout.items()
    )


def _expected_success_commands(
    receipt: Mapping[str, object],
) -> list[tuple[str, ...]]:
    git = str(receipt["git_executable"])
    system = receipt["platform_system"]
    governance_path = _recorded_path(receipt["governance_root"], system)
    governance_root = str(governance_path)
    base_sha = str(receipt["base_sha"])
    evaluator_sha = str(receipt["evaluator_sha"])
    python_path = _recorded_path(receipt["python_path"], system)
    lock_path = governance_path / LOCK_NAME
    git_prefix = (git, "-C", governance_root)
    return [
        (*git_prefix, "rev-parse", "--show-toplevel"),
        (*git_prefix, "rev-parse", "--verify", "HEAD^{commit}"),
        (*git_prefix, "rev-parse", "--verify", f"{base_sha}^{{commit}}"),
        (*git_prefix, "merge-base", base_sha, evaluator_sha),
        (
            *git_prefix,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        (str(python_path), "-I", "-m", "ensurepip", "--upgrade", "--default-pip"),
        pip_install_command(python_path, lock_path),
        (str(python_path), "-I", "-m", "pip", "check"),
        (str(python_path), "-I", "-c", _RUFF_PROBE),
        (str(python_path), "-I", "-m", "ruff", "--version"),
        (str(python_path), "-I", "-m", "mypy", "--version"),
    ]


def _write_validated_receipt(
    governance_root: Path,
    receipt_path: Path,
    receipt: Mapping[str, object],
    expected_context: Mapping[str, object],
) -> None:
    if receipt.get("status") == "PASS":
        validate_live_receipt(governance_root, receipt, expected_context)
    else:
        validate_receipt(governance_root, receipt, expected_context)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _validate_sha(label: str, value: str) -> None:
    if not _SHA_RE.fullmatch(value):
        raise BootstrapError(f"{label} must be an exact 40-character commit")


def _evidence_buffer(
    command_evidence: list[dict[str, object]] | None,
) -> list[dict[str, object]]:
    if command_evidence is None:
        return []
    return command_evidence


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_within_any(path: Path, parents: Sequence[Path]) -> bool:
    return any(_is_within(path, parent) for parent in parents)


def _runtime_paths(runtime_root: Path) -> tuple[Path, Path]:
    if os.name == "nt":
        runtime_bin = runtime_root / "Scripts"
        return runtime_bin / "python.exe", runtime_bin
    runtime_bin = runtime_root / "bin"
    return runtime_bin / "python", runtime_bin


def _current_python_version() -> tuple[int, int, int]:
    return sys.version_info[:3]


def _validate_python_version() -> None:
    current_python_version = _current_python_version()
    if current_python_version != _PYTHON_VERSION:
        actual = ".".join(str(item) for item in current_python_version)
        expected = ".".join(str(item) for item in _PYTHON_VERSION)
        raise BootstrapError(f"toolchain requires Python {expected}; found {actual}")


def validate_checkout(
    governance_root: Path,
    workspace_root: Path,
    base_sha: str,
    evaluator_sha: str,
    source: Mapping[str, str],
    command_evidence: list[dict[str, object]],
) -> tuple[str, str, str]:
    git_command = shutil.which("git", path=source.get("PATH"))
    if git_command is None:
        raise BootstrapError("trusted Git executable unavailable")
    git_path = Path(git_command).resolve(strict=True)
    if _is_within_any(git_path, (workspace_root, governance_root)):
        raise BootstrapError(
            "Git executable resolves inside target workspace or governance checkout"
        )
    environment = sanitized_git_environment(source)
    root_result = _run(
        (str(git_path), "-C", str(governance_root), "rev-parse", "--show-toplevel"),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    )
    repository_root = Path(root_result.stdout.strip()).resolve(strict=True)
    if command_evidence:
        command_evidence[-1]["stdout_sha256"] = _stream_sha256(
            repository_root.as_posix()
        )
    if repository_root != governance_root:
        raise BootstrapError("governance root differs from Git checkout root")
    checkout_head = _run(
        (
            str(git_path),
            "-C",
            str(governance_root),
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout.strip()
    if checkout_head != evaluator_sha:
        raise BootstrapError("governance checkout HEAD differs from evaluator SHA")
    checkout_base = _run(
        (
            str(git_path),
            "-C",
            str(governance_root),
            "rev-parse",
            "--verify",
            f"{base_sha}^{{commit}}",
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout.strip()
    if checkout_base != base_sha:
        raise BootstrapError("governance checkout base commit differs from base SHA")
    merge_base = _run(
        (
            str(git_path),
            "-C",
            str(governance_root),
            "merge-base",
            base_sha,
            evaluator_sha,
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout.strip()
    _validate_sha("merge-base SHA", merge_base)
    status = _run(
        (
            str(git_path),
            "-C",
            str(governance_root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout
    if status.strip():
        raise BootstrapError(
            "governance checkout contains uncommitted or ignored files"
        )
    return checkout_head, merge_base, str(git_path)


def provision(
    *,
    governance_root: Path,
    workspace_root: Path,
    runtime_root: Path,
    base_sha: str,
    evaluator_sha: str,
    receipt_path: Path,
    expected_context: Mapping[str, object],
    command_evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    expected, context_kind = _validated_context(expected_context)
    _validate_python_version()
    _validate_sha("base SHA", base_sha)
    _validate_sha("evaluator SHA", evaluator_sha)
    _validate_provision_identity(expected, context_kind, base_sha, evaluator_sha)
    command_evidence = _evidence_buffer(command_evidence)
    governance_root = governance_root.resolve(strict=True)
    workspace_root = workspace_root.resolve(strict=True)
    lock_path = (governance_root / LOCK_NAME).resolve(strict=True)
    if not _is_within(lock_path, governance_root):
        raise BootstrapError("toolchain lock escapes governance checkout")
    runtime_root = runtime_root.resolve(strict=False)
    protected_roots = (workspace_root, governance_root)
    if _is_within_any(runtime_root, protected_roots):
        raise BootstrapError(
            "toolchain runtime must be outside target workspace and governance checkout"
        )
    if runtime_root.exists():
        raise BootstrapError("toolchain runtime already exists")
    receipt_path = receipt_path.resolve(strict=False)
    if _is_within_any(receipt_path, protected_roots):
        raise BootstrapError(
            "toolchain receipt must be outside target workspace and governance checkout"
        )
    checkout_head, merge_base, git_executable = validate_checkout(
        governance_root,
        workspace_root,
        base_sha,
        evaluator_sha,
        os.environ,
        command_evidence,
    )
    lock_sha256 = validate_lock(lock_path)
    venv.EnvBuilder(with_pip=False, clear=False, symlinks=os.name != "nt").create(
        runtime_root
    )
    python_path, runtime_bin = _runtime_paths(runtime_root)
    environment = sanitized_pip_environment(runtime_bin, os.environ)
    _run(
        (
            str(python_path),
            "-I",
            "-m",
            "ensurepip",
            "--upgrade",
            "--default-pip",
        ),
        environment=environment,
        timeout_seconds=60,
        command_evidence=command_evidence,
    )
    _run(
        pip_install_command(python_path, lock_path),
        environment=environment,
        timeout_seconds=120,
        command_evidence=command_evidence,
    )
    _run(
        (str(python_path), "-I", "-m", "pip", "check"),
        environment=environment,
        timeout_seconds=30,
        command_evidence=command_evidence,
    )
    probe = _run(
        (
            str(python_path),
            "-I",
            "-c",
            _RUFF_PROBE,
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    )
    runtime_evidence = json.loads(probe.stdout)
    if runtime_evidence.get("version") != RUFF_VERSION:
        raise BootstrapError("installed Ruff version differs from lock")
    module_origin = Path(str(runtime_evidence.get("origin", ""))).resolve(strict=True)
    if not _is_within(module_origin, runtime_root):
        raise BootstrapError("Ruff module resolved outside toolchain runtime")
    ruff_executable = runtime_bin / ("ruff.exe" if os.name == "nt" else "ruff")
    if not ruff_executable.is_file():
        raise BootstrapError("Ruff executable missing from toolchain runtime")
    version = _run(
        (str(python_path), "-I", "-m", "ruff", "--version"),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout.strip()
    if version != f"ruff {RUFF_VERSION}":
        raise BootstrapError(f"unexpected Ruff version output: {version}")
    mypy_version = _run(
        (str(python_path), "-I", "-m", "mypy", "--version"),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    ).stdout.strip()
    if not mypy_version.startswith(f"mypy {MYPY_VERSION}"):
        raise BootstrapError(f"unexpected mypy version output: {mypy_version}")
    receipt: dict[str, object] = {
        **expected,
        "schema_version": "1.0",
        "status": "PASS",
        "decision": "TOOLCHAIN_READY",
        "base_sha": base_sha,
        "claimed_base_sha": base_sha,
        "head_sha": evaluator_sha,
        "evaluator_sha": evaluator_sha,
        "claimed_evaluator_sha": evaluator_sha,
        "checkout_head_sha": checkout_head,
        "merge_base_sha": merge_base,
        "lock_sha256": lock_sha256,
        "governance_root": str(governance_root),
        "workspace_root": str(workspace_root),
        "git_executable": git_executable,
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "runtime_root": str(runtime_root),
        "python_path": str(python_path),
        "ruff_module_origin": str(module_origin),
        "ruff_executable": str(ruff_executable.resolve(strict=True)),
        "packages": toolchain_packages(),
        "commands": command_evidence,
        "error": None,
    }
    _attach_payload_sha256(receipt)
    _write_validated_receipt(governance_root, receipt_path, receipt, expected)
    return receipt


def _validate_provision_identity(
    expected: Mapping[str, object],
    context_kind: str,
    base_sha: str,
    evaluator_sha: str,
) -> None:
    if context_kind in {"PUBLICATION", "PHASE1_SHADOW"}:
        identity_matches = (
            base_sha == expected["base_sha"] and evaluator_sha == expected["head_sha"]
        )
    else:
        identity_matches = base_sha == evaluator_sha == expected["evaluator_sha"]
    if not identity_matches:
        raise BootstrapError("toolchain inputs differ from authoritative context")


def _normalized_sha(value: str) -> str:
    return value if _SHA_RE.fullmatch(value) else "0" * 40


def failure_receipt(
    args: argparse.Namespace,
    expected_context: Mapping[str, object],
    command_evidence: list[dict[str, object]],
    error: str,
) -> dict[str, object]:
    failure_detail = error[:4096] or "unknown toolchain bootstrap failure"
    receipt: dict[str, object] = {
        **expected_context,
        "schema_version": "1.0",
        "status": "FAIL",
        "decision": "BLOCK_TECHNICAL",
        "base_sha": _normalized_sha(args.base_sha),
        "claimed_base_sha": args.base_sha,
        "head_sha": _normalized_sha(args.evaluator_sha),
        "evaluator_sha": _normalized_sha(args.evaluator_sha),
        "claimed_evaluator_sha": args.evaluator_sha,
        "checkout_head_sha": None,
        "merge_base_sha": None,
        "lock_sha256": None,
        "governance_root": str(args.governance_root.resolve(strict=False)),
        "workspace_root": str(args.workspace_root.resolve(strict=False)),
        "git_executable": None,
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "runtime_root": str(args.runtime_root.resolve(strict=False)),
        "python_path": None,
        "ruff_module_origin": None,
        "ruff_executable": None,
        "packages": [],
        "commands": command_evidence,
        "error": failure_detail,
    }
    return _attach_payload_sha256(receipt)


def write_github_outputs(
    output_path: Path, receipt_path: Path, receipt: Mapping[str, object]
) -> None:
    resolved_receipt_path = receipt_path.resolve(strict=True)
    values = {
        "receipt-path": str(resolved_receipt_path),
        "receipt-file-sha256": hashlib.sha256(
            resolved_receipt_path.read_bytes()
        ).hexdigest(),
    }
    python_path = receipt.get("python_path")
    if isinstance(python_path, str):
        values["python-path"] = python_path
        values["bin-path"] = str(Path(python_path).parent)
    lock_sha256 = receipt.get("lock_sha256")
    if isinstance(lock_sha256, str):
        values["lock-sha256"] = lock_sha256
    if any("\n" in value or "\r" in value for value in values.values()):
        raise BootstrapError("GitHub output values must be single-line")
    with output_path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--governance-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--evaluator-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--head-repository-id", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--pull-request-number", default="")
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--expected-artifact-name", required=True)
    parser.add_argument(
        "--context-kind",
        choices=("PUBLICATION", "SUPPORTABILITY_EVALUATION", "PHASE1_SHADOW"),
        default="PUBLICATION",
    )
    parser.add_argument("--event-action", default="")
    parser.add_argument("--target-base-sha", default="")
    parser.add_argument("--target-head-sha", default="")
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--failure-receipt", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def _publication_context_from_args(args: argparse.Namespace) -> dict[str, object]:
    raw_pr_number = str(args.pull_request_number)
    if raw_pr_number:
        if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_pr_number):
            raise BootstrapError("pull request number invalid")
        pull_request_number: int | None = int(raw_pr_number)
    else:
        pull_request_number = None
    return _validated_publication_context(
        {
            "repository": args.repository,
            "repository_id": args.repository_id,
            "head_repository_id": args.head_repository_id,
            "event_name": args.event_name,
            "pull_request_number": pull_request_number,
            "base_sha": args.base_sha,
            "head_sha": args.evaluator_sha,
            "workflow_ref": args.workflow_ref,
            "workflow_sha": args.workflow_sha,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "expected_artifact_name": args.expected_artifact_name,
        }
    )


def _evaluation_context_from_args(args: argparse.Namespace) -> dict[str, object]:
    raw_pr_number = str(args.pull_request_number)
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_pr_number):
        raise BootstrapError("pull request number invalid")
    return _validated_evaluation_context(
        {
            "context_kind": "SUPPORTABILITY_EVALUATION",
            "repository": args.repository,
            "repository_id": args.repository_id,
            "head_repository_id": args.head_repository_id,
            "event_name": args.event_name,
            "event_action": args.event_action,
            "pull_request_number": int(raw_pr_number),
            "target_base_sha": args.target_base_sha,
            "target_head_sha": args.target_head_sha,
            "evaluator_sha": args.evaluator_sha,
            "workflow_ref": args.workflow_ref,
            "workflow_sha": args.workflow_sha,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "expected_artifact_name": args.expected_artifact_name,
        }
    )


def _shadow_context_from_args(args: argparse.Namespace) -> dict[str, object]:
    raw_pr_number = str(args.pull_request_number)
    if raw_pr_number:
        if not re.fullmatch(r"[1-9][0-9]{0,9}", raw_pr_number):
            raise BootstrapError("pull request number invalid")
        pull_request_number: int | None = int(raw_pr_number)
    else:
        pull_request_number = None
    return _validated_shadow_context(
        {
            "context_kind": "PHASE1_SHADOW",
            "repository": args.repository,
            "repository_id": args.repository_id,
            "head_repository_id": args.head_repository_id,
            "event_name": args.event_name,
            "pull_request_number": pull_request_number,
            "base_sha": args.base_sha,
            "head_sha": args.evaluator_sha,
            "workflow_ref": args.workflow_ref,
            "workflow_sha": args.workflow_sha,
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
            "expected_artifact_name": args.expected_artifact_name,
        }
    )


def _context_from_args(args: argparse.Namespace) -> dict[str, object]:
    if args.context_kind == "PUBLICATION":
        return _publication_context_from_args(args)
    if args.context_kind == "SUPPORTABILITY_EVALUATION":
        return _evaluation_context_from_args(args)
    return _shadow_context_from_args(args)


def _validated_external_path(
    governance_root: Path, workspace_root: Path, output_path: Path, label: str
) -> Path:
    resolved_governance = governance_root.resolve(strict=True)
    resolved_workspace = workspace_root.resolve(strict=True)
    resolved_output = output_path.resolve(strict=False)
    if _is_within_any(resolved_output, (resolved_workspace, resolved_governance)):
        raise BootstrapError(
            f"{label} must be outside target workspace and governance checkout"
        )
    return resolved_output


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    command_evidence: list[dict[str, object]] = []
    try:
        expected_context = _context_from_args(args)
        failure_receipt_path = _validated_external_path(
            args.governance_root,
            args.workspace_root,
            args.failure_receipt,
            "failure receipt",
        )
        if args.github_output is not None:
            _validated_external_path(
                args.governance_root,
                args.workspace_root,
                args.github_output,
                "GitHub output",
            )
    except (BootstrapError, OSError, ValueError) as exc:
        print(f"toolchain output boundary FAIL: {exc}", file=sys.stderr)
        return 1
    try:
        receipt = provision(
            governance_root=args.governance_root,
            workspace_root=args.workspace_root,
            runtime_root=args.runtime_root,
            base_sha=args.base_sha,
            evaluator_sha=args.evaluator_sha,
            receipt_path=args.receipt,
            expected_context=expected_context,
            command_evidence=command_evidence,
        )
        if args.github_output is not None:
            write_github_outputs(args.github_output, args.receipt, receipt)
    except (BootstrapError, OSError, ValueError, json.JSONDecodeError) as exc:
        try:
            receipt = failure_receipt(
                args, expected_context, command_evidence, str(exc)
            )
            governance_root = args.governance_root.resolve(strict=True)
            _write_validated_receipt(
                governance_root,
                failure_receipt_path,
                receipt,
                expected_context,
            )
            if args.github_output is not None:
                write_github_outputs(args.github_output, failure_receipt_path, receipt)
        except (
            BootstrapError,
            OSError,
            ValueError,
            json.JSONDecodeError,
        ) as receipt_exc:
            print(f"toolchain failure receipt FAIL: {receipt_exc}", file=sys.stderr)
        print(f"toolchain bootstrap FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "toolchain bootstrap PASS: "
        f"ruff={RUFF_VERSION} lock_sha256={receipt['lock_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
