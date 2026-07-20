from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import BinaryIO, Callable, Literal, Sequence


_CONTAINER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")
_SAFE_ENVIRONMENT_KEYS = {
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_VALUE_0",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "HOME",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
    "TMPDIR",
}
_RUN_OPTIONS = {
    "cap-drop",
    "cpus",
    "env",
    "init",
    "memory",
    "memory-swap",
    "name",
    "network",
    "pids-limit",
    "pull",
    "read-only",
    "security-opt",
    "tmpfs",
    "user",
    "workdir",
}
_REPEATABLE_RUN_OPTIONS = {"env", "tmpfs"}
DockerRunPurpose = Literal["gate", "trusted-provisioning"]
DockerMountContract = tuple[Path, str, bool]


@dataclass(frozen=True)
class DockerCommandRecord:
    command: tuple[str, ...]
    termination: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    completed_at: datetime
    errors: tuple[str, ...]
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class DockerProcessError(RuntimeError):
    def __init__(
        self, message: str, *, records: tuple[DockerCommandRecord, ...] = ()
    ) -> None:
        super().__init__(message)
        self.records = records


@dataclass(frozen=True)
class DockerProcessResult:
    command: tuple[str, ...]
    termination: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    completed_at: datetime
    errors: tuple[str, ...]
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    records: tuple[DockerCommandRecord, ...] = ()


def run_docker_control(
    command: list[str],
    *,
    docker: Path,
    docker_host: str,
    timeout_seconds: int,
    output_limit_bytes: int,
) -> DockerProcessResult:
    _validate_command(command, docker, docker_host, "control")
    return _run_process(
        command,
        docker=docker,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )


def run_docker_container(
    command: list[str],
    *,
    docker: Path,
    docker_host: str,
    container_name: str,
    purpose: DockerRunPurpose,
    expected_mounts: Sequence[DockerMountContract] = (),
    scratch_root: Path,
    timeout_seconds: int,
    output_limit_bytes: int,
) -> DockerProcessResult:
    _validate_container_name(container_name)
    _validate_command(command, docker, docker_host, "run")
    _validate_run_contract(command, container_name, purpose, expected_mounts)
    control_root = _create_control_root(scratch_root, container_name)
    cidfile = _validate_cidfile(control_root / "container.cid")
    create_command = [
        *command[:2],
        "create",
        f"--cidfile={cidfile}",
        *command[3:],
    ]
    try:
        result = _create_and_start_container(
            create_command,
            docker=docker,
            docker_host=docker_host,
            container_name=container_name,
            cidfile=cidfile,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )
    except DockerProcessError as exc:
        cleanup_error = _cleanup_control_root(control_root, cidfile)
        if cleanup_error:
            raise DockerProcessError(
                f"{exc}; {cleanup_error}", records=exc.records
            ) from exc
        raise
    cleanup_error = _cleanup_control_root(control_root, cidfile)
    errors = (*result.errors, *((cleanup_error,) if cleanup_error else ()))
    return replace(result, completed_at=datetime.now(UTC), errors=errors)


def _create_control_root(scratch_root: Path, container_name: str) -> Path:
    root = _validated_scratch_root(scratch_root)
    control = root / f".docker-control-{container_name}"
    try:
        control.mkdir(mode=0o700)
    except OSError as exc:
        raise DockerProcessError(
            "Docker control directory could not be created"
        ) from exc
    return control


def _validated_scratch_root(path: Path) -> Path:
    lexical = Path(os.path.abspath(path))
    for candidate in (lexical, *lexical.parents):
        junction = getattr(candidate, "is_junction", None)
        if candidate.is_symlink() or bool(junction and junction()):
            raise DockerProcessError("Docker scratch root contains a link")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise DockerProcessError("Docker scratch root is unavailable") from exc
    if not resolved.is_dir():
        raise DockerProcessError("Docker scratch root is not a directory")
    return resolved


def _cleanup_control_root(root: Path, cidfile: Path) -> str:
    cid_error = _remove_cidfile(cidfile)
    try:
        root.rmdir()
    except OSError:
        return "Docker control directory cleanup failed"
    return cid_error or ""


def _create_and_start_container(
    create_command: list[str],
    *,
    docker: Path,
    docker_host: str,
    container_name: str,
    cidfile: Path,
    timeout_seconds: int,
    output_limit_bytes: int,
) -> DockerProcessResult:
    records: list[DockerCommandRecord] = []
    _require_container_absent(docker, docker_host, container_name, records)
    try:
        created = _run_process(
            create_command,
            docker=docker,
            timeout_seconds=min(timeout_seconds, 30),
            output_limit_bytes=min(output_limit_bytes, 65_536),
        )
        records.extend(created.records)
        container_id = _created_container_id(created, cidfile)
        start_command = [
            str(docker),
            f"--host={docker_host}",
            "start",
            "--attach",
            container_id,
        ]
        result = _run_process(
            start_command,
            docker=docker,
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
            stop=lambda: _kill_owned_container_id(
                docker, docker_host, container_id, records
            ),
        )
        records.extend(result.records)
    except Exception as exc:
        if isinstance(exc, DockerProcessError):
            records.extend(exc.records)
        cleanup_errors = _safe_container_cleanup(
            docker, docker_host, container_name, cidfile, records
        )
        raise DockerProcessError(
            _failure_message(exc, cleanup_errors),
            records=_ordered_records(records),
        ) from exc
    cleanup_errors = _safe_container_cleanup(
        docker, docker_host, container_name, cidfile, records
    )
    return DockerProcessResult(
        command=result.command,
        termination=result.termination,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        started_at=result.started_at,
        completed_at=result.completed_at,
        errors=(*result.errors, *cleanup_errors),
        stdout_truncated=result.stdout_truncated,
        stderr_truncated=result.stderr_truncated,
        records=_ordered_records(records),
    )


def _created_container_id(result: DockerProcessResult, cidfile: Path) -> str:
    container_id = _read_container_id(cidfile, wait=True)
    output = result.stdout.strip().decode("ascii", errors="ignore")
    if (
        result.termination != "EXITED"
        or result.exit_code != 0
        or result.errors
        or container_id is None
        or output != container_id
    ):
        raise DockerProcessError("Docker container creation failed")
    return container_id


def _safe_container_cleanup(
    docker: Path,
    host: str,
    name: str,
    cidfile: Path,
    records: list[DockerCommandRecord],
) -> list[str]:
    try:
        return _remove_and_verify(docker, host, name, cidfile, records)
    except Exception:
        return ["Docker container cleanup failed"]


def _failure_message(failure: Exception, cleanup_errors: list[str]) -> str:
    message = (
        str(failure)
        if isinstance(failure, DockerProcessError)
        else "Docker process supervision failed"
    )
    if cleanup_errors:
        return f"{message}; {'; '.join(cleanup_errors)}"
    return message


def _ordered_records(
    records: list[DockerCommandRecord],
) -> tuple[DockerCommandRecord, ...]:
    return tuple(sorted(records, key=lambda item: item.started_at))


def docker_environment(docker: Path) -> dict[str, str]:
    environment = {"PATH": str(docker.parent), "LC_ALL": "C"}
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment


def validate_bind_source(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if any(character in str(resolved) for character in (",", "\r", "\n", "\0")):
        raise DockerProcessError("Docker bind source path is unsafe")
    return resolved


def _run_process(
    command: list[str],
    *,
    docker: Path,
    timeout_seconds: int,
    output_limit_bytes: int,
    stop: Callable[[], None] | None = None,
) -> DockerProcessResult:
    _validate_limits(timeout_seconds, output_limit_bytes)
    started_at = datetime.now(UTC)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=docker_environment(docker),
        )
    except OSError as exc:
        completed_at = datetime.now(UTC)
        record = DockerCommandRecord(
            command=tuple(command),
            termination="NOT_STARTED",
            exit_code=None,
            stdout=b"",
            stderr=b"",
            started_at=started_at,
            completed_at=completed_at,
            errors=("Docker CLI failed to start",),
        )
        raise DockerProcessError(
            "Docker CLI failed to start", records=(record,)
        ) from exc
    capture = _BoundedCapture(output_limit_bytes)
    threads: list[threading.Thread] = []
    termination = "SUPERVISOR_ERROR"
    failure: Exception | None = None
    errors: list[str] = []
    try:
        threads = capture.start(process)
        termination = _wait_reason(process, capture, timeout_seconds)
    except Exception as exc:  # cleanup below is mandatory after Popen succeeds
        failure = exc
        threads = capture.threads
    finally:
        if termination != "EXITED":
            if stop is not None:
                try:
                    stop()
                except Exception as exc:
                    errors.append(f"Docker container stop failed: {exc}")
            _stop_local_process(process, errors)
        exit_code = _wait_for_exit(process, errors)
        _finish_capture(process, capture, threads, errors)
    if termination == "EXITED" and capture.exceeded.is_set():
        termination = "OUTPUT_LIMIT"
    completed_at = datetime.now(UTC)
    record = DockerCommandRecord(
        command=tuple(command),
        termination=termination,
        exit_code=exit_code,
        stdout=capture.stdout,
        stderr=capture.stderr,
        started_at=started_at,
        completed_at=completed_at,
        errors=tuple(errors),
        stdout_truncated=capture.stdout_truncated,
        stderr_truncated=capture.stderr_truncated,
    )
    if failure is not None:
        raise DockerProcessError(
            "Docker process supervision failed", records=(record,)
        ) from failure
    return DockerProcessResult(
        command=record.command,
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


def _wait_reason(
    process: subprocess.Popen[bytes], capture: _BoundedCapture, timeout: int
) -> str:
    deadline = time.monotonic() + timeout
    while process.poll() is None:
        if capture.exceeded.is_set():
            return "OUTPUT_LIMIT"
        if time.monotonic() >= deadline:
            return "TIMED_OUT"
        time.sleep(0.01)
    return "EXITED"


def _stop_local_process(process: subprocess.Popen[bytes], errors: list[str]) -> None:
    try:
        if process.poll() is not None:
            return
        process.kill()
    except (OSError, RuntimeError):
        errors.append("Docker CLI termination failed")


def _wait_for_exit(process: subprocess.Popen[bytes], errors: list[str]) -> int | None:
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _stop_local_process(process, errors)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            errors.append("Docker CLI did not exit")
            return None
    except (OSError, RuntimeError):
        errors.append("Docker CLI wait failed")
        return None


def _finish_capture(
    process: subprocess.Popen[bytes],
    capture: _BoundedCapture,
    threads: list[threading.Thread],
    errors: list[str],
) -> None:
    for thread in threads:
        try:
            thread.join(timeout=5)
        except RuntimeError:
            errors.append("Docker CLI output drain did not start")
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except (OSError, ValueError):
                errors.append("Docker CLI output pipe close failed")
    for thread in threads:
        try:
            thread.join(timeout=1)
        except RuntimeError:
            pass
    if any(_thread_alive(thread) for thread in threads):
        errors.append("Docker CLI output drain did not stop")
    errors.extend(capture.errors)


def _thread_alive(thread: threading.Thread) -> bool:
    try:
        return thread.is_alive()
    except RuntimeError:
        return False


def _kill_owned_container_id(
    docker: Path,
    host: str,
    container_id: str,
    records: list[DockerCommandRecord],
) -> None:
    result = _record_control(docker, host, ["kill", container_id], records)
    if result.termination == "EXITED" and result.exit_code == 0 and not result.errors:
        return
    state = _record_control(
        docker,
        host,
        ["container", "inspect", "--format={{.State.Running}}", container_id],
        records,
    )
    if (
        state.termination == "EXITED"
        and state.exit_code == 0
        and not state.errors
        and state.stdout.strip() == b"false"
    ):
        return
    try:
        _require_container_id_absent(docker, host, container_id, records)
    except DockerProcessError as exc:
        raise DockerProcessError("Docker container namespace kill failed") from exc


def _remove_and_verify(
    docker: Path,
    host: str,
    name: str,
    cidfile: Path,
    records: list[DockerCommandRecord] | None = None,
) -> list[str]:
    records = records if records is not None else []
    errors: list[str] = []
    try:
        container_id = _read_container_id(cidfile, wait=False)
    except DockerProcessError as exc:
        container_id = None
        errors.append(str(exc))
    if container_id is None:
        errors.extend(_missing_owner_cleanup(docker, host, name, records))
        cidfile_error = _remove_cidfile(cidfile)
        return [*errors, *([cidfile_error] if cidfile_error else [])]
    try:
        removed = _record_control(docker, host, ["rm", "-f", container_id], records)
    except DockerProcessError:
        errors.append("Docker forced container removal failed")
    else:
        if removed.termination != "EXITED" or removed.exit_code != 0 or removed.errors:
            errors.append("Docker forced container removal failed")
    try:
        _require_container_id_absent(docker, host, container_id, records)
    except DockerProcessError:
        errors.append("Docker container cleanup verification failed")
    cidfile_error = _remove_cidfile(cidfile)
    if cidfile_error:
        errors.append(cidfile_error)
    return errors


def _missing_owner_cleanup(
    docker: Path,
    host: str,
    name: str,
    records: list[DockerCommandRecord],
) -> list[str]:
    try:
        _require_container_absent(docker, host, name, records)
    except DockerProcessError:
        return ["Docker container ownership unavailable; name remains in use"]
    return []


def _require_container_id_absent(
    docker: Path,
    host: str,
    value: str,
    records: list[DockerCommandRecord],
) -> None:
    result = _record_control(
        docker,
        host,
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"id={value}",
        ],
        records,
    )
    if result.termination != "EXITED" or result.exit_code != 0 or result.errors:
        raise DockerProcessError("Docker container cleanup verification failed")
    if result.stdout.strip():
        raise DockerProcessError("Docker container cleanup failed")


def _require_container_absent(
    docker: Path,
    host: str,
    name: str,
    records: list[DockerCommandRecord],
) -> None:
    result = _record_control(
        docker,
        host,
        [
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{name}$",
        ],
        records,
    )
    if result.termination != "EXITED" or result.exit_code != 0 or result.errors:
        raise DockerProcessError("Docker container preflight failed")
    if result.stdout.strip():
        raise DockerProcessError("Docker container name is already in use")


def _control(docker: Path, host: str, arguments: list[str]) -> DockerProcessResult:
    return run_docker_control(
        [str(docker), f"--host={host}", *arguments],
        docker=docker,
        docker_host=host,
        timeout_seconds=10,
        output_limit_bytes=65_536,
    )


def _record_control(
    docker: Path,
    host: str,
    arguments: list[str],
    records: list[DockerCommandRecord],
) -> DockerProcessResult:
    try:
        result = _control(docker, host, arguments)
    except DockerProcessError as exc:
        records.extend(exc.records)
        raise
    records.extend(result.records)
    return result


def _validate_command(
    command: list[str], docker: Path, host: str, operation: str
) -> None:
    if len(command) < 3 or command[:2] != [str(docker), f"--host={host}"]:
        raise DockerProcessError("Docker command identity is invalid")
    if operation == "run" and command[2] != "run":
        raise DockerProcessError("Docker run command is invalid")
    if operation == "control":
        _validate_control_command(command[2:])


def _validate_control_command(arguments: list[str]) -> None:
    if _valid_image_inspect(arguments) or _valid_container_control(arguments):
        return
    raise DockerProcessError("Docker control command is not allowlisted")


def _valid_image_inspect(arguments: list[str]) -> bool:
    return (
        len(arguments) == 4
        and arguments[:3] == ["image", "inspect", "--format={{json .}}"]
        and _IMAGE_RE.fullmatch(arguments[3]) is not None
    )


def _valid_container_control(arguments: list[str]) -> bool:
    if len(arguments) == 2 and arguments[0] == "kill":
        return _CONTAINER_ID_RE.fullmatch(arguments[1]) is not None
    if len(arguments) == 3 and arguments[:2] == ["rm", "-f"]:
        return _CONTAINER_ID_RE.fullmatch(arguments[2]) is not None
    if len(arguments) == 4 and arguments[:3] == [
        "container",
        "inspect",
        "--format={{.State.Running}}",
    ]:
        return _CONTAINER_ID_RE.fullmatch(arguments[3]) is not None
    return _valid_container_listing(arguments)


def _valid_container_listing(arguments: list[str]) -> bool:
    prefixes = (
        ["container", "ls", "--all", "--quiet", "--filter"],
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
        ],
    )
    for prefix in prefixes:
        if len(arguments) != len(prefix) + 1 or arguments[: len(prefix)] != prefix:
            continue
        value = arguments[-1]
        if value.startswith("name=^/") and value.endswith("$"):
            return _CONTAINER_NAME_RE.fullmatch(value[7:-1]) is not None
        if value.startswith("id="):
            return _CONTAINER_ID_RE.fullmatch(value[3:]) is not None
    return False


def _validate_run_contract(
    command: list[str],
    container_name: str,
    purpose: DockerRunPurpose,
    expected_mounts: Sequence[DockerMountContract],
) -> None:
    if purpose not in {"gate", "trusted-provisioning"}:
        raise DockerProcessError("Docker run purpose is invalid")
    options, mounts, image_index = _parse_run_options(command)
    _require_run_option(options, "name", container_name)
    _require_run_option(options, "pull", "never")
    _require_run_option(options, "cap-drop", "ALL")
    _require_run_option(options, "security-opt", "no-new-privileges:true")
    if options.get("read-only") != [None] or options.get("init") != [None]:
        raise DockerProcessError("Docker run isolation flags are incomplete")
    _validate_resources(options)
    _validate_network_and_user(options, purpose)
    _validate_environment(options.get("env", []))
    _validate_tmpfs(options.get("tmpfs", []))
    parsed_mounts = [_validate_mount(mount, purpose) for mount in mounts]
    targets = [item[1] for item in parsed_mounts]
    if len(targets) != len(set(targets)):
        raise DockerProcessError("Docker mount destination is duplicated")
    expected = [
        (validate_bind_source(source), destination, readonly)
        for source, destination, readonly in expected_mounts
    ]
    if parsed_mounts != expected:
        raise DockerProcessError("Docker mount contract differs from trusted inputs")
    if image_index >= len(command) or not _IMAGE_RE.fullmatch(command[image_index]):
        raise DockerProcessError("Docker image must use an exact digest")
    if image_index == len(command) - 1:
        raise DockerProcessError("Docker container command is missing")


def _parse_run_options(
    command: list[str],
) -> tuple[dict[str, list[str | None]], list[str], int]:
    options: dict[str, list[str | None]] = {}
    mounts: list[str] = []
    index = 3
    while index < len(command):
        token = command[index]
        if token == "--mount":
            if index + 1 >= len(command):
                raise DockerProcessError("Docker mount option is incomplete")
            mounts.append(command[index + 1])
            index += 2
            continue
        if not token.startswith("--"):
            break
        name, parsed = _parse_long_run_option(token)
        if name in options and name not in _REPEATABLE_RUN_OPTIONS:
            raise DockerProcessError("Docker run option is duplicated")
        options.setdefault(name, []).append(parsed)
        index += 1
    if index == 3:
        raise DockerProcessError("Docker run option syntax is invalid")
    return options, mounts, index


def _parse_long_run_option(token: str) -> tuple[str, str | None]:
    name, separator, value = token[2:].partition("=")
    if name not in _RUN_OPTIONS:
        raise DockerProcessError("Docker run option is not allowlisted")
    if name in {"init", "read-only"}:
        if separator:
            raise DockerProcessError("Docker boolean option is malformed")
        return name, None
    if not separator or not value:
        raise DockerProcessError("Docker run option value is missing")
    return name, value


def _require_run_option(
    options: dict[str, list[str | None]], name: str, value: str
) -> None:
    if options.get(name) != [value]:
        raise DockerProcessError(f"Docker {name} policy is invalid")


def _validate_resources(options: dict[str, list[str | None]]) -> None:
    for name in ("memory", "memory-swap", "pids-limit"):
        values = options.get(name)
        if values is None or len(values) != 1 or not str(values[0]).isdigit():
            raise DockerProcessError("Docker resource policy is invalid")
    memory = int(str(options["memory"][0]))
    swap = int(str(options["memory-swap"][0]))
    pids = int(str(options["pids-limit"][0]))
    try:
        cpus = Decimal(str(options.get("cpus", [""])[0]))
    except InvalidOperation as exc:
        raise DockerProcessError("Docker resource policy is invalid") from exc
    if (
        not 64 * 1024 * 1024 <= memory <= 4 * 1024 * 1024 * 1024
        or swap != memory
        or not 8 <= pids <= 512
        or not Decimal("0.1") <= cpus <= Decimal("4")
    ):
        raise DockerProcessError("Docker resource policy is invalid")


def _validate_network_and_user(
    options: dict[str, list[str | None]], purpose: DockerRunPurpose
) -> None:
    network = options.get("network")
    if network not in (["none"], ["bridge"]):
        raise DockerProcessError("Docker network policy is invalid")
    users = options.get("user", [])
    if purpose == "gate" and network != ["none"]:
        raise DockerProcessError("Gate execution must disable network")
    if purpose == "gate" and len(users) != 1:
        raise DockerProcessError("Gate execution must use a non-root user")
    if users and not _non_root_user(str(users[0])):
        raise DockerProcessError("Docker user policy is invalid")


def _non_root_user(value: str) -> bool:
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", value)
    return match is not None


def _validate_environment(values: list[str | None]) -> None:
    keys: list[str] = []
    for raw in values:
        key, separator, value = str(raw).partition("=")
        if (
            not separator
            or key not in _SAFE_ENVIRONMENT_KEYS
            or not value
            or any(character in value for character in ("\r", "\n", "\0"))
        ):
            raise DockerProcessError("Docker environment policy is invalid")
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise DockerProcessError("Docker environment policy is duplicated")


def _validate_tmpfs(values: list[str | None]) -> None:
    for raw in values:
        match = re.fullmatch(
            r"(/[A-Za-z0-9._/-]+):rw,nosuid,nodev,noexec,size=([0-9]+)",
            str(raw),
        )
        if match is None or not 1 <= int(match.group(2)) <= 512 * 1024 * 1024:
            raise DockerProcessError("Docker tmpfs policy is invalid")


def _validate_mount(
    specification: str, purpose: DockerRunPurpose
) -> DockerMountContract:
    if any(character in specification for character in ("\r", "\n", "\0")):
        raise DockerProcessError("Docker mount policy is invalid")
    fields: dict[str, str] = {}
    readonly = False
    for field in specification.split(","):
        if field == "readonly":
            readonly = True
            continue
        key, separator, value = field.partition("=")
        key = {"source": "src", "target": "dst"}.get(key, key)
        if not separator or not value or key in fields:
            raise DockerProcessError("Docker mount policy is invalid")
        fields[key] = value
    if set(fields) != {"type", "src", "dst"} or fields["type"] != "bind":
        raise DockerProcessError("Docker mount policy is invalid")
    source = validate_bind_source(Path(fields["src"]))
    target = fields["dst"]
    lowered = f"{source}|{target}".lower()
    if (
        not target.startswith("/")
        or "docker.sock" in lowered
        or "docker_engine" in lowered
    ):
        raise DockerProcessError("Docker mount policy is invalid")
    if purpose == "trusted-provisioning":
        _validate_provisioning_mount(target, readonly)
    else:
        _validate_gate_mount(target, readonly)
    return source, target, readonly


def _validate_provisioning_mount(target: str, readonly: bool) -> None:
    if target == "/bundle":
        return
    if target == "/inputs/requirements-governance.lock" and readonly:
        return
    raise DockerProcessError("Docker provisioning mount is not allowlisted")


def _validate_gate_mount(target: str, readonly: bool) -> None:
    writable = {"/workspace", "/governance-output"}
    readonly_destinations = {
        "/input",
        "/scope",
        "/workspace/tests",
        "/opt/governance-toolchain",
        "/opt/governance-judge/governance_eval/judges/mypy_v1.ini",
        "/opt/governance-judge/governance_eval/judges/unittest_gate_v1.py",
        "/opt/governance-judge/governance_eval/judges/package_audit_v1.py",
    }
    if target in writable and not readonly:
        return
    if target in readonly_destinations and readonly:
        return
    raise DockerProcessError("Docker gate mount is not allowlisted")


def _validate_container_name(name: str) -> None:
    if not _CONTAINER_NAME_RE.fullmatch(name):
        raise DockerProcessError("Docker container name is invalid")


def _validate_cidfile(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    if (
        resolved != path
        or not resolved.parent.is_dir()
        or resolved.exists()
        or any(character in str(resolved) for character in (",", "\r", "\n", "\0"))
    ):
        raise DockerProcessError("Docker cidfile path is invalid")
    return resolved


def _read_container_id(path: Path, *, wait: bool) -> str | None:
    attempts = 50 if wait else 1
    for _attempt in range(attempts):
        if path.exists():
            break
        if wait:
            time.sleep(0.01)
    else:
        return None
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65:
        raise DockerProcessError("Docker cidfile is invalid")
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise DockerProcessError("Docker cidfile is unreadable") from exc
    if not _CONTAINER_ID_RE.fullmatch(value):
        raise DockerProcessError("Docker cidfile container id is invalid")
    return value


def _remove_cidfile(path: Path) -> str | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        path.unlink()
    except OSError:
        return "Docker cidfile cleanup failed"
    return None


def _validate_limits(timeout_seconds: int, output_limit_bytes: int) -> None:
    if not 1 <= timeout_seconds <= 600:
        raise DockerProcessError("Docker command timeout is invalid")
    if not 1 <= output_limit_bytes <= 1_048_576:
        raise DockerProcessError("Docker command output limit is invalid")


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self.remaining = limit
        self.stdout = b""
        self.stderr = b""
        self.stdout_truncated = False
        self.stderr_truncated = False
        self.errors: list[str] = []
        self.exceeded = threading.Event()
        self._lock = threading.Lock()
        self.threads: list[threading.Thread] = []

    def start(self, process: subprocess.Popen[bytes]) -> list[threading.Thread]:
        self.threads = [
            threading.Thread(target=self._drain, args=(name, pipe), daemon=True)
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr))
            if pipe is not None
        ]
        for thread in self.threads:
            thread.start()
        return self.threads

    def _drain(self, name: str, pipe: BinaryIO) -> None:
        chunks: list[bytes] = []
        try:
            while chunk := pipe.read(8192):
                with self._lock:
                    keep = min(len(chunk), self.remaining)
                    if keep:
                        chunks.append(chunk[:keep])
                    self.remaining -= keep
                    if keep != len(chunk):
                        self.exceeded.set()
                        if name == "stdout":
                            self.stdout_truncated = True
                        else:
                            self.stderr_truncated = True
        except (OSError, ValueError):
            with self._lock:
                self.errors.append(f"Docker CLI {name} capture failed")
        content = b"".join(chunks)
        with self._lock:
            if name == "stdout":
                self.stdout = content
            else:
                self.stderr = content
