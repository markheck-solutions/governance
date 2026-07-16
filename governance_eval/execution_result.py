from __future__ import annotations

import base64
import binascii
import json
import math
from datetime import datetime
from hashlib import sha256
from importlib.resources import files
from typing import Any

from governance_eval.execution_plan import (
    ExecutionPlan,
    ExecutionPlanError,
    compile_execution_plan,
)
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError, validate

_SCHEMA_RESOURCE_PARTS = ("schema_data", "v1", "execution_result.schema.json")
_SCHEMA_SHA256 = "c3dcbe029e3f7094b8eb8966c487b649bbe08ec945d5f7b396900d2ce0dbee7f"
_TIMING_TOLERANCE_SECONDS = 0.001
_TIMEOUT_CLEANUP_GRACE_SECONDS = 1.0


def assess_execution_result(
    payload: Any, expected_plan: ExecutionPlan
) -> dict[str, Any]:
    integrity = validate_execution_result_integrity(payload, expected_plan)
    errors = integrity["errors"] or ["execution result provenance is unverified"]
    return {
        "schema_version": "1.0",
        "capability_status": "BLOCK_TECHNICAL",
        "artifact_id": payload.get("artifact_id", "")
        if isinstance(payload, dict)
        else "",
        "errors": errors,
    }


def validate_execution_result_integrity(
    payload: Any, expected_plan: ExecutionPlan
) -> dict[str, Any]:
    error = _integrity_error(payload, expected_plan)
    errors = [] if error is None else [error]
    return {
        "schema_version": "1.0",
        "integrity_status": "INTEGRITY_INVALID" if errors else "INTEGRITY_VALID",
        "artifact_id": payload.get("artifact_id", "")
        if isinstance(payload, dict)
        else "",
        "errors": errors,
    }


def _integrity_error(payload: Any, expected_plan: ExecutionPlan) -> str | None:
    expected_plan_error = _expected_plan_error(expected_plan)
    if expected_plan_error is not None:
        return expected_plan_error
    if not isinstance(payload, dict):
        return "execution result must be an object"
    try:
        _validate_execution_result_schema(payload)
    except SchemaValidationError as exc:
        return f"execution result schema invalid: {exc}"
    try:
        expected_content_hash = sha256_json({**payload, "artifact_content_hash": ""})
        identity_payload = {
            key: value
            for key, value in payload.items()
            if key not in {"artifact_id", "artifact_content_hash"}
        }
        expected_artifact_id = sha256_json(identity_payload)
    except (OverflowError, TypeError, ValueError):
        return "execution result content hash cannot be verified"
    if payload["artifact_content_hash"] != expected_content_hash:
        return "execution result content hash is invalid"
    if payload["artifact_id"] != expected_artifact_id:
        return "execution result artifact id is invalid"
    if payload["plan_id"] != expected_plan.plan_id:
        return "execution result plan id mismatch"
    binding_error = _binding_error(payload, expected_plan)
    if binding_error is not None:
        return binding_error
    output_error = _output_error(payload)
    if output_error is not None:
        return output_error
    return _execution_record_error(payload)


def _validate_execution_result_schema(payload: dict[str, Any]) -> None:
    resource = files("governance_eval").joinpath(*_SCHEMA_RESOURCE_PARTS)
    try:
        schema_bytes = resource.read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise SchemaValidationError("trusted schema is unavailable") from exc
    try:
        schema_text = schema_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchemaValidationError("trusted schema is malformed") from exc
    canonical_schema_bytes = schema_text.replace("\r\n", "\n").encode("utf-8")
    if sha256(canonical_schema_bytes).hexdigest() != _SCHEMA_SHA256:
        raise SchemaValidationError("trusted schema digest is invalid")
    try:
        schema = json.loads(schema_text)
    except json.JSONDecodeError as exc:
        raise SchemaValidationError("trusted schema is malformed") from exc
    if not isinstance(schema, dict):
        raise SchemaValidationError("trusted schema must be an object")
    validate(payload, schema)


def _binding_error(payload: dict[str, Any], expected_plan: ExecutionPlan) -> str | None:
    step = expected_plan.steps[0]
    if payload["step_id"] != step.step_id:
        return "execution result step id mismatch"
    if payload["timeout_seconds"] != step.timeout_seconds:
        return "execution result timeout mismatch"
    if payload["output_limit_bytes"] != step.output_limit_bytes:
        return "execution result output limit mismatch"
    return None


def _execution_record_error(payload: dict[str, Any]) -> str | None:
    exited = payload["termination"] == "EXITED"
    has_exit_code = payload["exit_code"] is not None
    if exited != has_exit_code:
        return "execution result termination and exit code are inconsistent"
    return _timing_error(payload)


def _timing_error(payload: dict[str, Any]) -> str | None:
    try:
        duration = float(payload["duration_seconds"])
    except (OverflowError, TypeError, ValueError):
        return "execution result duration is out of range"
    if not math.isfinite(duration):
        return "execution result duration must be finite"
    try:
        started = _parse_utc_timestamp(payload["started_at"])
        completed = _parse_utc_timestamp(payload["completed_at"])
    except (OverflowError, TypeError, ValueError):
        return "execution result timestamp is invalid"
    if completed < started:
        return "execution result timestamps are out of order"
    elapsed = (completed - started).total_seconds()
    if abs(elapsed - duration) > _TIMING_TOLERANCE_SECONDS:
        return "execution result duration does not match timestamps"
    timeout = payload["timeout_seconds"]
    if payload["termination"] == "TIMED_OUT":
        if duration + _TIMING_TOLERANCE_SECONDS < timeout:
            return "execution result timeout occurred before configured deadline"
        if (
            duration
            > timeout + _TIMEOUT_CLEANUP_GRACE_SECONDS + _TIMING_TOLERANCE_SECONDS
        ):
            return "execution result timeout cleanup exceeded bounded grace"
    elif duration > timeout + _TIMING_TOLERANCE_SECONDS:
        return "execution result duration exceeds timeout"
    return None


def _parse_utc_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _output_error(payload: dict[str, Any]) -> str | None:
    limit = payload["output_limit_bytes"]
    captured_total = sum(
        payload[stream_name]["captured_bytes"] for stream_name in ("stdout", "stderr")
    )
    if captured_total > limit:
        return "captured output exceeds combined limit"
    for stream_name in ("stdout", "stderr"):
        output = payload[stream_name]
        if output["captured_bytes"] > limit:
            return f"{stream_name} exceeds output limit"
        if output["truncated"] and captured_total < limit:
            return f"{stream_name} truncation is inconsistent"
        integrity_error = _captured_output_error(stream_name, output)
        if integrity_error is not None:
            return integrity_error
    return None


def _captured_output_error(stream_name: str, output: dict[str, Any]) -> str | None:
    try:
        content = base64.b64decode(output["captured_base64"], validate=True)
    except (binascii.Error, ValueError):
        return f"{stream_name} captured output encoding is invalid"
    if len(content) != output["captured_bytes"]:
        return f"{stream_name} captured output byte count is invalid"
    if sha256(content).hexdigest() != output["sha256"]:
        return f"{stream_name} captured output digest is invalid"
    return None


def _expected_plan_error(expected_plan: ExecutionPlan) -> str | None:
    if not isinstance(expected_plan, ExecutionPlan):
        return "expected execution plan is invalid"
    try:
        payload = expected_plan.to_json()
        plan_id = payload.pop("plan_id")
        calculated_plan_id = sha256_json(payload)
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError):
        return "expected execution plan is invalid"
    if plan_id != calculated_plan_id:
        return "expected execution plan id is invalid"
    try:
        step = expected_plan.steps[0]
        recompiled = compile_execution_plan(
            {
                "schema_version": expected_plan.schema_version,
                "repository": expected_plan.repository,
                "pull_request": expected_plan.pull_request,
                "base_sha": expected_plan.base_sha,
                "head_sha": expected_plan.head_sha,
                "evaluator_sha": expected_plan.evaluator_sha,
                "config_sha256": expected_plan.config_sha256,
                "capability": step.capability,
                "adapter_id": step.adapter_id,
            },
            target_tree_sha256=expected_plan.target_tree_sha256,
            execution_id=expected_plan.execution_id,
        )
    except (ExecutionPlanError, IndexError, KeyError, TypeError):
        return "expected execution plan is invalid"
    if recompiled != expected_plan:
        return "expected execution plan differs from evaluator-owned plan"
    return None
