from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping, Sequence


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_JUDGE_DESTINATIONS = {
    "python.mypy.v1": ("/opt/governance-judge/governance_eval/judges/mypy_v1.ini"),
    "python.unittest.v1": (
        "/opt/governance-judge/governance_eval/judges/unittest_gate_v1.py"
    ),
    "python.package-audit-isolated.v1": (
        "/opt/governance-judge/governance_eval/judges/package_audit_v1.py"
    ),
}


def validate_gate_command(command: Sequence[str], plan: Mapping[str, Any]) -> list[str]:
    try:
        _validate_start_command(command, plan)
    except (KeyError, TypeError, ValueError):
        return ["execution result v2 Docker command is not evaluator-owned"]
    return []


def validate_gate_run_command(
    command: Sequence[str], plan: Mapping[str, Any]
) -> list[str]:
    try:
        values = [_string(item) for item in command]
        if len(values) < 4 or values[2] != "run":
            raise ValueError("Docker run command is invalid")
        create = [*values[:2], "create", "--cidfile=/governance-owned.cid", *values[3:]]
        _validate_create_command(create, plan)
    except (KeyError, TypeError, ValueError):
        return ["Docker gate command is not evaluator-owned"]
    return []


def validate_gate_process_commands(
    processes: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
    capability_status: str,
) -> list[str]:
    try:
        _validate_gate_process_commands(processes, plan, capability_status)
    except (KeyError, TypeError, ValueError, binascii.Error):
        return ["execution result v2 Docker process sequence is not evaluator-owned"]
    return []


def _validate_start_command(command: Sequence[str], plan: Mapping[str, Any]) -> None:
    runtime = plan["runtime"]
    values = [_string(item) for item in command]
    expected_tail = [
        f"--host={_string(runtime['docker']['host'])}",
        "start",
        "--attach",
    ]
    if (
        not _same_host_path(values[0], _string(runtime["docker"]["path"]))
        or values[1:4] != expected_tail
        or len(values) != 5
        or not _container_id(values[4])
    ):
        raise ValueError("Docker start command differs")


def _validate_create_command(command: Sequence[str], plan: Mapping[str, Any]) -> None:
    runtime = plan["runtime"]
    step = plan["step"]
    plan_id = _string(plan["plan_id"])
    values = [_string(item) for item in command]
    if not _same_host_path(values[0], _string(runtime["docker"]["path"])) or values[
        1:3
    ] != [f"--host={_string(runtime['docker']['host'])}", "create"]:
        raise ValueError("Docker command prefix differs")
    index = 3
    index = _consume_dynamic_identity(values, index, plan_id)
    index = _consume_exact(values, index, _fixed_options(step))
    index = _consume_exact(values, index, _environment_options(step))
    index = _consume_exact(
        values, index, [f"--workdir={_string(step['working_directory'])}"]
    )
    for destination, readonly in _mount_contract(step):
        index = _consume_mount(values, index, destination, readonly)
    image = _string(runtime["image"]["reference"])
    argv = [_string(item) for item in step["argv"]]
    if values[index:] != [image, *argv]:
        raise ValueError("Docker image or gate argv differs")


def _validate_gate_process_commands(
    processes: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
    capability_status: str,
) -> None:
    commands = [[_string(item) for item in process["command"]] for process in processes]
    creates, starts = _execution_indices(commands)
    if len(creates) > 1 or len(starts) > 1:
        raise ValueError("Docker execution command is duplicated")
    for index in creates:
        _validate_create_command(commands[index], plan)
    for index in starts:
        _validate_start_command(commands[index], plan)
    _validate_execution_pair(processes, commands, creates, starts)
    if capability_status == "PASS" and (len(creates) != 1 or len(starts) != 1):
        raise ValueError("Docker PASS execution evidence is incomplete")
    owned_ids = _owned_ids(commands)
    if len(owned_ids) > 1:
        raise ValueError("Docker process sequence changes container identity")
    for command in commands:
        if not _allowlisted_process(command, plan, owned_ids):
            raise ValueError("Docker process command is not allowlisted")


def _execution_indices(
    commands: Sequence[Sequence[str]],
) -> tuple[list[int], list[int]]:
    creates = [
        index for index, command in enumerate(commands) if _operation(command, "create")
    ]
    starts = [
        index for index, command in enumerate(commands) if _operation(command, "start")
    ]
    return creates, starts


def _validate_execution_pair(
    processes: Sequence[Mapping[str, Any]],
    commands: Sequence[Sequence[str]],
    creates: list[int],
    starts: list[int],
) -> None:
    if not creates or not starts:
        return
    if creates[0] >= starts[0]:
        raise ValueError("Docker execution order is invalid")
    created_id = _created_id(processes[creates[0]])
    if created_id != commands[starts[0]][4]:
        raise ValueError("Docker created container identity differs")


def _created_id(process: Mapping[str, Any]) -> str:
    encoded = _string(process["stdout"]["captured_base64"])
    value = base64.b64decode(encoded, validate=True).strip().decode("ascii")
    if not _container_id(value):
        raise ValueError("Docker create output is invalid")
    return value


def _owned_ids(commands: Sequence[Sequence[str]]) -> set[str]:
    return {value for command in commands for value in command if _container_id(value)}


def _allowlisted_process(
    command: list[str], plan: Mapping[str, Any], owned_ids: set[str]
) -> bool:
    if len(command) < 3:
        return False
    if (
        not _same_host_path(command[0], _string(plan["runtime"]["docker"]["path"]))
        or command[1] != f"--host={_string(plan['runtime']['docker']['host'])}"
    ):
        return False
    arguments = command[2:]
    if arguments and arguments[0] in {"create", "start"}:
        return True
    image = _string(plan["runtime"]["image"]["reference"])
    if arguments == ["image", "inspect", "--format={{json .}}", image]:
        return True
    name = f"governance-{_string(plan['plan_id'])[:32]}"
    if arguments == [
        "container",
        "ls",
        "--all",
        "--quiet",
        "--filter",
        f"name=^/{name}$",
    ]:
        return True
    return _owned_control(arguments, owned_ids)


def _owned_control(arguments: list[str], owned_ids: set[str]) -> bool:
    if len(owned_ids) != 1:
        return False
    container_id = next(iter(owned_ids))
    return arguments in (
        ["kill", container_id],
        ["rm", "-f", container_id],
        ["container", "inspect", "--format={{.State.Running}}", container_id],
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            f"id={container_id}",
        ],
    )


def _operation(command: Sequence[str], operation: str) -> bool:
    return len(command) > 2 and command[2] == operation


def _container_id(value: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _consume_dynamic_identity(values: list[str], index: int, plan_id: str) -> int:
    cidfile = _at(values, index)
    if not cidfile.startswith("--cidfile=") or not _absolute_host_path(cidfile[10:]):
        raise ValueError("Docker cidfile evidence is invalid")
    name = _at(values, index + 1)
    expected = f"--name=governance-{plan_id[:32]}"
    if name != expected:
        raise ValueError("Docker container name differs from plan")
    return index + 2


def _fixed_options(step: Mapping[str, Any]) -> list[str]:
    values = [
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
    if step["mount_profile"] == "wheel-only.v1":
        values.append("--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=268435456")
    return values


def _environment_options(step: Mapping[str, Any]) -> list[str]:
    wheel_only = step["mount_profile"] == "wheel-only.v1"
    values = [
        "HOME=/tmp/home" if wheel_only else "HOME=/workspace/.home",
        "TMPDIR=/tmp",
        "PYTHONNOUSERSITE=1",
        "PYTHONDONTWRITEBYTECODE=1",
    ]
    if not wheel_only:
        pythonpath = "/opt/governance-toolchain/python"
        if step["mount_profile"] == "evaluator-toolchain.v1":
            pythonpath = f"/workspace:{pythonpath}"
        values.extend(
            [
                f"PYTHONPATH={pythonpath}",
                "GIT_EXEC_PATH=/opt/governance-toolchain/git/bin",
                "GIT_TEMPLATE_DIR=/opt/governance-toolchain/git/templates",
                "GIT_CONFIG_NOSYSTEM=1",
                "GIT_CONFIG_GLOBAL=/dev/null",
            ]
        )
    return [f"--env={value}" for value in values]


def _mount_contract(step: Mapping[str, Any]) -> list[tuple[str, bool]]:
    profile = _string(step["mount_profile"])
    adapter = _string(step["adapter_id"])
    mounts: list[tuple[str, bool]] = []
    if profile != "wheel-only.v1":
        mounts.extend([("/workspace", False), ("/opt/governance-toolchain", True)])
    judge = _JUDGE_DESTINATIONS.get(adapter)
    if judge:
        mounts.append((judge, True))
    mounts.append(("/scope", True))
    if step["capability"] in {"build", "benchmark"}:
        mounts.append(("/governance-output", False))
    if profile == "wheel-only.v1":
        mounts.append(("/input", True))
    if profile == "target-toolchain-base-tests.v1":
        mounts.append(("/workspace/tests", True))
    return mounts


def _consume_mount(
    values: list[str], index: int, destination: str, readonly: bool
) -> int:
    if _at(values, index) != "--mount":
        raise ValueError("Docker mount marker is missing")
    specification = _at(values, index + 1)
    suffix = ",readonly" if readonly else ""
    prefix = "type=bind,src="
    ending = f",dst={destination}{suffix}"
    if not specification.startswith(prefix) or not specification.endswith(ending):
        raise ValueError("Docker mount differs from plan")
    source = specification[len(prefix) : -len(ending)]
    if not _absolute_host_path(source) or "," in source:
        raise ValueError("Docker mount source evidence is invalid")
    return index + 2


def _consume_exact(values: list[str], index: int, expected: list[str]) -> int:
    if values[index : index + len(expected)] != expected:
        raise ValueError("Docker command policy differs")
    return index + len(expected)


def _absolute_host_path(value: str) -> bool:
    if not value or any(character in value for character in ("\r", "\n", "\0")):
        return False
    if value.startswith("/"):
        return not value.startswith("//")
    return _WINDOWS_ABSOLUTE.match(value) is not None and not value.startswith("\\\\")


def _same_host_path(left: str, right: str) -> bool:
    if _WINDOWS_ABSOLUTE.match(left) and _WINDOWS_ABSOLUTE.match(right):
        return left.replace("\\", "/") == right.replace("\\", "/")
    return left == right


def _at(values: list[str], index: int) -> str:
    try:
        return values[index]
    except IndexError as exc:
        raise ValueError("Docker command is truncated") from exc


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError("Docker command value is invalid")
    return value
