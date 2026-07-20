from __future__ import annotations

import base64
import binascii
import math
from copy import deepcopy
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_gate_command import (
    validate_gate_command,
    validate_gate_process_commands,
)
from governance_eval.execution_plan_v2 import ExecutionPlanV2, assess_execution_plan_v2
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named

_TIMING_TOLERANCE_SECONDS = 0.001


def validate_execution_result_v2(
    payload: object,
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt | Mapping[str, object],
    *,
    capability: str,
    adapter_id: str,
    scope_manifest: Mapping[str, object],
    target_root: Path,
    evaluator_root: Path,
    toolchain_manifest: Mapping[str, object] | None = None,
    input_artifacts: Sequence[Mapping[str, object]] = (),
) -> dict[str, Any]:
    errors = _integrity_errors(
        payload,
        plan,
        receipt,
        capability=capability,
        adapter_id=adapter_id,
        scope_manifest=scope_manifest,
        target_root=target_root,
        evaluator_root=evaluator_root,
        toolchain_manifest=toolchain_manifest,
        input_artifacts=input_artifacts,
    )
    return {
        "schema_version": "2.0",
        "integrity_status": "INTEGRITY_INVALID" if errors else "INTEGRITY_VALID",
        "artifact_id": payload.get("artifact_id", "")
        if isinstance(payload, dict)
        else "",
        "errors": errors,
    }


def _integrity_errors(
    payload: object,
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt | Mapping[str, object],
    **trusted_inputs: Any,
) -> list[str]:
    plan_assessment = assess_execution_plan_v2(
        plan.to_json(), receipt, **trusted_inputs
    )
    if plan_assessment["capability_status"] != "PASS":
        return ["execution result v2 plan is not evaluator-owned"]
    if not isinstance(payload, dict):
        return ["execution result v2 must be an object"]
    schema_error = _schema_error(payload)
    if schema_error:
        return [schema_error]
    errors = _binding_errors(payload, plan)
    errors.extend(_command_errors(payload, plan))
    errors.extend(_scope_errors(payload, plan, trusted_inputs["scope_manifest"]))
    errors.extend(_stream_errors(payload, plan))
    errors.extend(_process_errors(payload, plan))
    errors.extend(_artifact_errors(payload, plan))
    errors.extend(_outcome_errors(payload, plan))
    errors.extend(_timing_errors(payload, plan))
    return errors


def _command_errors(payload: Mapping[str, Any], plan: ExecutionPlanV2) -> list[str]:
    command = payload["command"]
    if not command:
        return []
    if plan.step["execution"] == "docker":
        return validate_gate_command(command, plan.to_json())
    expected = [
        plan.runtime["python"]["path"],
        "trusted-operation",
        plan.step["operation_id"],
    ]
    return (
        []
        if command == expected
        else ["execution result v2 trusted command is not evaluator-owned"]
    )


def _schema_error(payload: dict[str, Any]) -> str:
    try:
        validate_packaged_named("execution_result_v2", payload)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        return f"execution result v2 schema is invalid: {exc}"
    return ""


def _binding_errors(payload: dict[str, Any], plan: ExecutionPlanV2) -> list[str]:
    errors: list[str] = []
    expected = {
        "plan_id": plan.plan_id,
        "checkout_receipt_id": plan.checkout_receipt_id,
        "capability": plan.step["capability"],
        "adapter_id": plan.step["adapter_id"],
        "runtime": plan.runtime,
        "timeout_seconds": plan.step["timeout_seconds"],
        "total_timeout_seconds": plan.step["total_timeout_seconds"],
    }
    for field, value in expected.items():
        if payload[field] != value:
            errors.append(f"execution result v2 {field} mismatch")
    unsigned = deepcopy(payload)
    artifact_id = unsigned.pop("artifact_id")
    if artifact_id != sha256_json({**unsigned, "artifact_id": ""}):
        errors.append("execution result v2 artifact id is invalid")
    return errors


def _scope_errors(
    payload: dict[str, Any],
    plan: ExecutionPlanV2,
    scope_manifest: Mapping[str, object],
) -> list[str]:
    entries = scope_manifest.get("entries")
    expected = {
        "rule_id": plan.step["scope_rule_id"],
        "manifest_id": plan.inputs["scope_manifest_id"],
        "file_count": len(entries) if isinstance(entries, list) else -1,
    }
    return (
        [] if payload["scope"] == expected else ["execution result v2 scope mismatch"]
    )


def _stream_errors(payload: dict[str, Any], plan: ExecutionPlanV2) -> list[str]:
    errors: list[str] = []
    for name in ("stdout", "stderr"):
        error = _stream_error(name, payload[name])
        if error:
            errors.append(error)
    captured = payload["stdout"]["captured_bytes"] + payload["stderr"]["captured_bytes"]
    if captured > plan.step["output_limit_bytes"]:
        errors.append("execution result v2 combined output exceeds plan limit")
    truncated = any(payload[name]["truncated"] for name in ("stdout", "stderr"))
    if payload["capability_status"] == "PASS" and truncated:
        errors.append("execution result v2 PASS output cannot be truncated")
    if payload["termination"] == "OUTPUT_LIMIT" and not truncated:
        errors.append("execution result v2 output-limit evidence is incomplete")
    return errors


def _stream_error(name: str, stream: Mapping[str, Any]) -> str:
    try:
        content = base64.b64decode(stream["captured_base64"], validate=True)
    except (binascii.Error, KeyError, TypeError, ValueError):
        return f"execution result v2 {name} encoding is invalid"
    if len(content) != stream["captured_bytes"]:
        return f"execution result v2 {name} length is invalid"
    if sha256(content).hexdigest() != stream["sha256"]:
        return f"execution result v2 {name} digest is invalid"
    return ""


def _process_errors(payload: dict[str, Any], plan: ExecutionPlanV2) -> list[str]:
    errors: list[str] = []
    command = payload["command"]
    processes = payload["processes"]
    matching = [record for record in processes if record["command"] == command]
    if command and len(matching) != 1:
        errors.append("execution result v2 primary command evidence is invalid")
    if len(matching) == 1:
        errors.extend(_primary_process_errors(payload, matching[0]))
    if not command and payload["termination"] != "NOT_STARTED":
        errors.append("execution result v2 command is missing")
    for index, process in enumerate(processes):
        maximum = (
            plan.step["timeout_seconds"]
            if process["command"] == command
            else plan.step["total_timeout_seconds"]
        )
        errors.extend(
            _single_process_errors(
                process,
                plan,
                index,
                maximum,
                enforce_deadline=payload["capability_status"] == "PASS",
            )
        )
    if plan.step["execution"] == "docker":
        errors.extend(
            validate_gate_process_commands(
                processes, plan.to_json(), payload["capability_status"]
            )
        )
    return errors


def _primary_process_errors(
    payload: Mapping[str, Any], process: Mapping[str, Any]
) -> list[str]:
    fields = ("termination", "exit_code", "stdout", "stderr")
    if any(payload[field] != process[field] for field in fields):
        return ["execution result v2 primary process differs from result"]
    return []


def _single_process_errors(
    process: Mapping[str, Any],
    plan: ExecutionPlanV2,
    index: int,
    maximum: int,
    *,
    enforce_deadline: bool,
) -> list[str]:
    errors: list[str] = []
    for name in ("stdout", "stderr"):
        error = _stream_error(f"process {index} {name}", process[name])
        if error:
            errors.append(error)
    captured = process["stdout"]["captured_bytes"] + process["stderr"]["captured_bytes"]
    if captured > plan.step["output_limit_bytes"]:
        errors.append(f"execution result v2 process {index} output exceeds limit")
    if _time_error(process, maximum, enforce_deadline=enforce_deadline):
        errors.append(f"execution result v2 process {index} timing is invalid")
    return errors


def _artifact_errors(payload: dict[str, Any], plan: ExecutionPlanV2) -> list[str]:
    artifacts = payload["artifacts"]
    names = [item["name"] for item in artifacts]
    filenames = [item["filename"] for item in artifacts]
    errors: list[str] = []
    if len(names) != len(set(names)) or len(filenames) != len(set(filenames)):
        errors.append("execution result v2 artifact identities are duplicated")
    expected = list(plan.step["expected_artifacts"])
    if payload["capability_status"] == "PASS" and sorted(names) != sorted(expected):
        errors.append("execution result v2 required artifacts are incomplete")
    if any(name not in expected for name in names):
        errors.append("execution result v2 contains an unexpected artifact")
    return errors


def _outcome_errors(payload: dict[str, Any], _plan: ExecutionPlanV2) -> list[str]:
    termination = payload["termination"]
    exit_code = payload["exit_code"]
    errors: list[str] = []
    if termination == "NOT_STARTED" and exit_code is not None:
        errors.append("execution result v2 not-started exit code is invalid")
    if termination != "NOT_STARTED" and (
        not isinstance(exit_code, int) or isinstance(exit_code, bool)
    ):
        errors.append("execution result v2 terminated exit code is invalid")
    clean_exit = termination == "EXITED" and exit_code == 0 and not payload["errors"]
    if (payload["capability_status"] == "PASS") != clean_exit:
        errors.append("execution result v2 outcome is inconsistent")
    return errors


def _timing_errors(payload: dict[str, Any], plan: ExecutionPlanV2) -> list[str]:
    errors: list[str] = []
    if _time_error(
        payload,
        plan.step["total_timeout_seconds"],
        enforce_deadline=payload["capability_status"] == "PASS",
    ):
        errors.append("execution result v2 timing is invalid")
    duration = float(payload["duration_seconds"])
    if (
        payload["termination"] == "TIMED_OUT"
        and duration < plan.step["timeout_seconds"]
    ):
        errors.append("execution result v2 timeout occurred before plan deadline")
    return errors


def _time_error(
    payload: Mapping[str, Any], maximum: int, *, enforce_deadline: bool
) -> bool:
    try:
        duration = float(payload["duration_seconds"])
        started = _timestamp(payload["started_at"])
        completed = _timestamp(payload["completed_at"])
    except (OverflowError, TypeError, ValueError):
        return True
    if (
        not math.isfinite(duration)
        or duration < 0
        or (enforce_deadline and duration > maximum)
    ):
        return True
    if completed < started:
        return True
    elapsed = (completed - started).total_seconds()
    return abs(elapsed - duration) > _TIMING_TOLERANCE_SECONDS


def _timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z suffix")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
