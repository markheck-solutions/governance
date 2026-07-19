from __future__ import annotations

import base64
import binascii
import math
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_runtime import docker_run_argv
from governance_eval.execution_plan_v2 import ExecutionPlanV2
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named


def validate_execution_result_v2(
    payload: Any, plan: ExecutionPlanV2, receipt: CheckoutReceipt
) -> dict[str, Any]:
    error = _integrity_error(payload, plan, receipt)
    errors = [] if error is None else [error]
    return {
        "schema_version": "2.0",
        "integrity_status": "INTEGRITY_INVALID" if errors else "INTEGRITY_VALID",
        "artifact_id": payload.get("artifact_id", "")
        if isinstance(payload, dict)
        else "",
        "errors": errors,
    }


def _integrity_error(
    payload: Any, plan: ExecutionPlanV2, receipt: CheckoutReceipt
) -> str | None:
    if not isinstance(payload, dict):
        return "execution result v2 must be an object"
    try:
        validate_named("execution_result_v2", payload)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        return f"execution result v2 schema invalid: {exc}"
    if payload["artifact_id"] != sha256_json({**payload, "artifact_id": ""}):
        return "execution result v2 artifact id is invalid"
    if payload["plan_id"] != plan.plan_id:
        return "execution result v2 plan id mismatch"
    if payload["checkout_receipt_id"] != receipt.receipt_id:
        return "execution result v2 checkout receipt mismatch"
    binding_error = _runtime_error(payload, plan)
    if binding_error is not None:
        return binding_error
    output_error = _output_error(payload, plan)
    if output_error is not None:
        return output_error
    outcome_error = _outcome_error(payload)
    if outcome_error is not None:
        return outcome_error
    return _timing_error(payload)


def _output_error(payload: dict[str, Any], plan: ExecutionPlanV2) -> str | None:
    for name in ("stdout", "stderr"):
        error = _stream_error(name, payload[name])
        if error is not None:
            return error
    captured = payload["stdout"]["captured_bytes"] + payload["stderr"]["captured_bytes"]
    if captured > plan.step["output_limit_bytes"]:
        return "execution result v2 combined output exceeds plan limit"
    if payload["capability_status"] == "PASS" and any(
        payload[name]["truncated"] for name in ("stdout", "stderr")
    ):
        return "execution result v2 PASS output cannot be truncated"
    return None


def _runtime_error(payload: dict[str, Any], plan: ExecutionPlanV2) -> str | None:
    runtime = payload["runtime"]
    expected = {
        "image": plan.runtime["image"],
        "policy_id": plan.runtime["policy_id"],
        "toolchain": "ruff==0.15.21",
        "toolchain_sha256": plan.runtime["toolchain_sha256"],
        "docker_path": plan.runtime["docker_path"],
        "docker_sha256": plan.runtime["docker_sha256"],
        "docker_host": plan.runtime["docker_host"],
    }
    if any(runtime[field] != value for field, value in expected.items()):
        return "execution result v2 runtime mismatch"
    if payload["timeout_seconds"] != plan.step["timeout_seconds"]:
        return "execution result v2 timeout mismatch"
    if not payload["command"]:
        return (
            None
            if payload["termination"] == "NOT_STARTED"
            else "execution result v2 command is missing"
        )
    if len(payload["command"]) < 2:
        return "execution result v2 command shape is invalid"
    if payload["command"][1] != f"--host={runtime['docker_host']}":
        return "execution result v2 Docker host mismatch"
    return _command_error(payload["command"], runtime["docker_path"], plan)


def _command_error(
    command: list[str], docker_path: str, plan: ExecutionPlanV2
) -> str | None:
    try:
        name = next(
            item.split("=", 1)[1] for item in command if item.startswith("--name=")
        )
        mount = next(
            item
            for item in command
            if item.startswith("type=bind,") and item.endswith(",dst=/workspace")
        )
        workspace = mount.removeprefix("type=bind,src=").removesuffix(",dst=/workspace")
        toolchain_mount = next(
            item
            for item in command
            if item.startswith("type=bind,")
            and item.endswith(",dst=/opt/governance-toolchain,readonly")
        )
        toolchain_root = toolchain_mount.removeprefix("type=bind,src=").removesuffix(
            ",dst=/opt/governance-toolchain,readonly"
        )
        docker_host = command[1].removeprefix("--host=")
    except (StopIteration, IndexError):
        return "execution result v2 command shape is invalid"
    expected = docker_run_argv(
        docker=Path(docker_path),
        docker_host=docker_host,
        plan=plan,
        workspace=Path(workspace),
        toolchain_root=Path(toolchain_root),
        container_name=name,
    )
    if command != expected:
        return "execution result v2 command mismatch"
    return None


def _stream_error(name: str, stream: dict[str, Any]) -> str | None:
    try:
        content = base64.b64decode(stream["captured_base64"], validate=True)
    except (binascii.Error, ValueError):
        return f"execution result v2 {name} encoding is invalid"
    if len(content) != stream["captured_bytes"]:
        return f"execution result v2 {name} length is invalid"
    if sha256(content).hexdigest() != stream["sha256"]:
        return f"execution result v2 {name} digest is invalid"
    return None


def _outcome_error(payload: dict[str, Any]) -> str | None:
    termination = payload["termination"]
    exit_code = payload["exit_code"]
    if termination == "NOT_STARTED":
        if exit_code is not None:
            return "execution result v2 not-started exit code is invalid"
    elif not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return "execution result v2 terminated exit code is invalid"
    passed = payload["capability_status"] == "PASS"
    clean_exit = (
        payload["termination"] == "EXITED"
        and payload["exit_code"] == 0
        and not payload["errors"]
    )
    if passed != clean_exit:
        return "execution result v2 outcome is inconsistent"
    return None


def _timing_error(payload: dict[str, Any]) -> str | None:
    try:
        duration = float(payload["duration_seconds"])
        started = _timestamp(payload["started_at"])
        completed = _timestamp(payload["completed_at"])
    except (OverflowError, TypeError, ValueError):
        return "execution result v2 timing is invalid"
    if not math.isfinite(duration) or duration < 0:
        return "execution result v2 duration is invalid"
    if completed < started:
        return "execution result v2 timestamps are out of order"
    elapsed = (completed - started).total_seconds()
    if abs(elapsed - duration) > 0.001:
        return "execution result v2 duration does not match timestamps"
    return None


def _timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z suffix")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
