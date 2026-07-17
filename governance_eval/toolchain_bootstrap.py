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
from pathlib import Path

RUFF_VERSION = "0.15.21"
LOCK_NAME = "requirements-governance.lock"
_PYTHON_VERSION = (3, 12, 13)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RUFF_HASHES = frozenset(
    {
        "sha256:bab0905d2f29e0d9fbc3c373ed23db0095edaa3f71f1f4f519ec15134d9e85c8",
        "sha256:d4b8d9a2f0f12b816b50447f6eccb9f4bb01a6b82c86b50fb3b5354b458dc6d3",
    }
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
    if len(logical_lines) != 1:
        raise BootstrapError("toolchain lock must contain exactly one requirement")
    try:
        tokens = shlex.split(logical_lines[0], posix=True)
    except ValueError as exc:
        raise BootstrapError(f"toolchain lock syntax invalid: {exc}") from exc
    if not tokens or tokens[0] != f"ruff=={RUFF_VERSION}":
        raise BootstrapError(f"toolchain lock must pin ruff=={RUFF_VERSION}")
    hash_tokens = tokens[1:]
    if len(hash_tokens) != len(_RUFF_HASHES):
        raise BootstrapError("toolchain lock hash count invalid")
    parsed_hashes = {
        token.removeprefix("--hash=")
        for token in hash_tokens
        if token.startswith("--hash=")
    }
    if parsed_hashes != _RUFF_HASHES:
        raise BootstrapError("toolchain lock hashes do not match approved artifacts")
    return hashlib.sha256(payload).hexdigest()


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


def pip_install_command(python_path: Path, lock_path: Path) -> tuple[str, ...]:
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
            _command_record(command, started_at, timeout_seconds, None, True)
        )
        raise BootstrapError(
            f"toolchain command timed out after {timeout_seconds}s: {command[0]}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        command_evidence.append(
            _command_record(command, started_at, timeout_seconds, exc.returncode, False)
        )
        detail = (exc.stderr or exc.stdout or "no output").strip()
        raise BootstrapError(f"toolchain command failed: {detail}") from exc
    except OSError as exc:
        command_evidence.append(
            _command_record(command, started_at, timeout_seconds, None, False)
        )
        raise BootstrapError(f"toolchain command could not start: {exc}") from exc
    command_evidence.append(
        _command_record(
            command, started_at, timeout_seconds, completed.returncode, False
        )
    )
    return completed


def _command_record(
    command: Sequence[str],
    started_at: str,
    timeout_seconds: int,
    exit_code: int | None,
    timed_out: bool,
) -> dict[str, object]:
    return {
        "command": list(command),
        "started_at": started_at,
        "completed_at": _utc_now(),
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit_code": exit_code,
    }


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


def validate_receipt(governance_root: Path, receipt: Mapping[str, object]) -> None:
    schema_path = (
        governance_root / "schemas/v1/governance_toolchain_receipt.schema.json"
    )
    validator_path = governance_root / "governance_eval/schema_validator.py"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = runpy.run_path(str(validator_path)).get("validate")
    if not callable(validator):
        raise BootstrapError("receipt schema validator unavailable")
    validator(dict(receipt), schema)
    claimed_payload_sha256 = receipt.get("payload_sha256")
    actual_payload_sha256 = _payload_sha256(receipt)
    if not isinstance(claimed_payload_sha256, str) or not hmac.compare_digest(
        claimed_payload_sha256, actual_payload_sha256
    ):
        raise BootstrapError("toolchain receipt payload digest invalid")
    _validate_receipt_semantics(receipt)


def _validate_receipt_semantics(receipt: Mapping[str, object]) -> None:
    if receipt.get("status") == "PASS":
        _validate_success_receipt(receipt)
    elif receipt.get("status") == "FAIL":
        if receipt.get("decision") != "BLOCK_TECHNICAL" or not isinstance(
            receipt.get("error"), str
        ):
            raise BootstrapError("failed toolchain receipt decision invalid")


def _validate_success_receipt(receipt: Mapping[str, object]) -> None:
    required = (
        "checkout_head_sha",
        "lock_sha256",
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
    if receipt.get("packages") != [{"name": "ruff", "version": RUFF_VERSION}]:
        raise BootstrapError("successful toolchain receipt package evidence invalid")
    if not _valid_success_command_evidence(
        receipt.get("commands"),
        str(receipt.get("base_sha")),
        str(receipt.get("evaluator_sha")),
    ):
        raise BootstrapError("successful toolchain receipt command evidence invalid")


def _valid_success_command_evidence(
    value: object, base_sha: str, evaluator_sha: str
) -> bool:
    if not isinstance(value, list) or len(value) != 10:
        return False
    if any(
        not isinstance(record, dict)
        or record.get("timed_out") is not False
        or record.get("exit_code") != 0
        for record in value
    ):
        return False
    commands = [tuple(record["command"]) for record in value]
    return (
        commands[0][-2:] == ("rev-parse", "--show-toplevel")
        and commands[1][-2:] == ("--verify", "HEAD^{commit}")
        and commands[2][-2:] == ("--verify", f"{base_sha}^{{commit}}")
        and commands[3][-3:] == ("--is-ancestor", base_sha, evaluator_sha)
        and "status" in commands[4]
        and commands[5][1:4] == ("-I", "-m", "ensurepip")
        and commands[6][1:5] == ("-I", "-m", "pip", "install")
        and "--require-hashes" in commands[6]
        and commands[7][-3:] == ("-m", "pip", "check")
        and commands[8][1:3] == ("-I", "-c")
        and "importlib.metadata" in commands[8][-1]
        and commands[9][-3:] == ("-m", "ruff", "--version")
    )


def _write_validated_receipt(
    governance_root: Path, receipt_path: Path, receipt: Mapping[str, object]
) -> None:
    validate_receipt(governance_root, receipt)
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
) -> str:
    git_command = shutil.which("git", path=source.get("PATH"))
    if git_command is None:
        raise BootstrapError("trusted Git executable unavailable")
    git_path = Path(git_command).resolve(strict=True)
    if _is_within(git_path, workspace_root):
        raise BootstrapError("Git executable resolves inside target workspace")
    environment = sanitized_git_environment(source)
    repository_root = Path(
        _run(
            (str(git_path), "-C", str(governance_root), "rev-parse", "--show-toplevel"),
            environment=environment,
            timeout_seconds=15,
            command_evidence=command_evidence,
        ).stdout.strip()
    ).resolve(strict=True)
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
    _run(
        (
            str(git_path),
            "-C",
            str(governance_root),
            "merge-base",
            "--is-ancestor",
            base_sha,
            evaluator_sha,
        ),
        environment=environment,
        timeout_seconds=15,
        command_evidence=command_evidence,
    )
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
    return checkout_head


def provision(
    *,
    governance_root: Path,
    workspace_root: Path,
    runtime_root: Path,
    base_sha: str,
    evaluator_sha: str,
    receipt_path: Path,
    command_evidence: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    _validate_python_version()
    _validate_sha("base SHA", base_sha)
    _validate_sha("evaluator SHA", evaluator_sha)
    command_evidence = _evidence_buffer(command_evidence)
    governance_root = governance_root.resolve(strict=True)
    workspace_root = workspace_root.resolve(strict=True)
    lock_path = (governance_root / LOCK_NAME).resolve(strict=True)
    if not _is_within(lock_path, governance_root):
        raise BootstrapError("toolchain lock escapes governance checkout")
    runtime_root = runtime_root.resolve(strict=False)
    if _is_within(runtime_root, workspace_root):
        raise BootstrapError("toolchain runtime must be outside target workspace")
    if runtime_root.exists():
        raise BootstrapError("toolchain runtime already exists")
    receipt_path = receipt_path.resolve(strict=False)
    if _is_within(receipt_path, workspace_root):
        raise BootstrapError("toolchain receipt must be outside target workspace")
    checkout_head = validate_checkout(
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
            (
                "import importlib.metadata, json, pathlib, ruff; "
                "print(json.dumps({'version': importlib.metadata.version('ruff'), "
                "'origin': str(pathlib.Path(ruff.__file__).resolve())}, sort_keys=True))"
            ),
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
    receipt: dict[str, object] = {
        "schema_version": "1.0",
        "status": "PASS",
        "decision": "TOOLCHAIN_READY",
        "base_sha": base_sha,
        "claimed_base_sha": base_sha,
        "head_sha": evaluator_sha,
        "evaluator_sha": evaluator_sha,
        "claimed_evaluator_sha": evaluator_sha,
        "checkout_head_sha": checkout_head,
        "lock_sha256": lock_sha256,
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "runtime_root": str(runtime_root),
        "python_path": str(python_path),
        "ruff_module_origin": str(module_origin),
        "ruff_executable": str(ruff_executable.resolve(strict=True)),
        "packages": [{"name": "ruff", "version": RUFF_VERSION}],
        "commands": command_evidence,
        "error": None,
    }
    _attach_payload_sha256(receipt)
    _write_validated_receipt(governance_root, receipt_path, receipt)
    return receipt


def _normalized_sha(value: str) -> str:
    return value if _SHA_RE.fullmatch(value) else "0" * 40


def failure_receipt(
    args: argparse.Namespace,
    command_evidence: list[dict[str, object]],
    error: str,
) -> dict[str, object]:
    failure_detail = error[:4096] or "unknown toolchain bootstrap failure"
    receipt: dict[str, object] = {
        "schema_version": "1.0",
        "status": "FAIL",
        "decision": "BLOCK_TECHNICAL",
        "base_sha": _normalized_sha(args.base_sha),
        "claimed_base_sha": args.base_sha,
        "head_sha": _normalized_sha(args.evaluator_sha),
        "evaluator_sha": _normalized_sha(args.evaluator_sha),
        "claimed_evaluator_sha": args.evaluator_sha,
        "checkout_head_sha": None,
        "lock_sha256": None,
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
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--failure-receipt", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def _validated_external_path(
    workspace_root: Path, output_path: Path, label: str
) -> Path:
    resolved_workspace = workspace_root.resolve(strict=True)
    resolved_output = output_path.resolve(strict=False)
    if _is_within(resolved_output, resolved_workspace):
        raise BootstrapError(f"{label} must be outside target workspace")
    return resolved_output


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    command_evidence: list[dict[str, object]] = []
    try:
        failure_receipt_path = _validated_external_path(
            args.workspace_root, args.failure_receipt, "failure receipt"
        )
        if args.github_output is not None:
            _validated_external_path(
                args.workspace_root, args.github_output, "GitHub output"
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
            command_evidence=command_evidence,
        )
        if args.github_output is not None:
            write_github_outputs(args.github_output, args.receipt, receipt)
    except (BootstrapError, OSError, ValueError, json.JSONDecodeError) as exc:
        try:
            receipt = failure_receipt(args, command_evidence, str(exc))
            governance_root = args.governance_root.resolve(strict=True)
            _write_validated_receipt(governance_root, failure_receipt_path, receipt)
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
