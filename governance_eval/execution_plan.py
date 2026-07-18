from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from hashlib import sha256
from importlib.resources import files
from typing import Any, Mapping

from governance_eval.capability_catalog import get_capability_adapter
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError, validate

_REQUEST_FIELDS = {
    "schema_version",
    "repository",
    "pull_request",
    "base_sha",
    "head_sha",
    "evaluator_sha",
    "config_sha256",
    "capability",
    "adapter_id",
}
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PULL_REQUEST = 9_007_199_254_740_991
_SCHEMA_RESOURCE_PARTS = ("schema_data", "v1", "execution_plan.schema.json")
_SCHEMA_SHA256 = "b8a5a95a1d9dd86512f0e29225014f9d15a80a457b2ad229f0a8f1be76ce728c"


class ExecutionPlanError(ValueError):
    pass


@dataclass(frozen=True)
class ExecutionStep:
    step_id: str
    capability: str
    adapter_id: str
    runtime_id: str
    module: str
    arguments: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    output_limit_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "capability": self.capability,
            "adapter_id": self.adapter_id,
            "runtime_id": self.runtime_id,
            "module": self.module,
            "arguments": list(self.arguments),
            "working_directory": self.working_directory,
            "timeout_seconds": self.timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
        }


@dataclass(frozen=True)
class ExecutionPlan:
    schema_version: str
    plan_id: str
    repository: str
    pull_request: int
    base_sha: str
    head_sha: str
    target_tree_sha256: str
    execution_id: str
    evaluator_sha: str
    config_sha256: str
    steps: tuple[ExecutionStep, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "repository": self.repository,
            "pull_request": self.pull_request,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "target_tree_sha256": self.target_tree_sha256,
            "execution_id": self.execution_id,
            "evaluator_sha": self.evaluator_sha,
            "config_sha256": self.config_sha256,
            "steps": [step.to_json() for step in self.steps],
        }


def compile_execution_plan(
    request: Mapping[str, Any],
    *,
    target_tree_sha256: str,
    execution_id: str,
) -> ExecutionPlan:
    if not isinstance(request, Mapping):
        raise ExecutionPlanError("execution plan request must be an object")
    _validate_request(request)
    target_tree_sha256 = _validate_protected_binding(
        "target_tree_sha256", target_tree_sha256
    )
    execution_id = _validate_protected_binding("execution_id", execution_id)
    capability = request["capability"]
    adapter_id = request["adapter_id"]
    try:
        adapter = get_capability_adapter(capability, adapter_id)
    except KeyError as exc:
        raise ExecutionPlanError(
            f"unsupported capability adapter: {capability}/{adapter_id}"
        ) from exc
    step = ExecutionStep(
        step_id=adapter.capability,
        capability=adapter.capability,
        adapter_id=adapter.adapter_id,
        runtime_id=adapter.runtime_id,
        module=adapter.module,
        arguments=adapter.arguments,
        working_directory=adapter.working_directory,
        timeout_seconds=adapter.timeout_seconds,
        output_limit_bytes=adapter.output_limit_bytes,
    )
    plan = ExecutionPlan(
        schema_version=request["schema_version"],
        plan_id="",
        repository=request["repository"],
        pull_request=request["pull_request"],
        base_sha=request["base_sha"],
        head_sha=request["head_sha"],
        target_tree_sha256=target_tree_sha256,
        execution_id=execution_id,
        evaluator_sha=request["evaluator_sha"],
        config_sha256=request["config_sha256"],
        steps=(step,),
    )
    try:
        plan_id = sha256_json(_unsigned_payload(plan))
    except (OverflowError, TypeError, ValueError) as exc:
        raise ExecutionPlanError("execution plan content cannot be hashed") from exc
    return replace(plan, plan_id=plan_id)


def serialize_execution_plan(plan: ExecutionPlan) -> bytes:
    return (
        json.dumps(plan.to_json(), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def assess_execution_plan(
    payload: Any,
    expected_request: Mapping[str, Any],
    *,
    target_tree_sha256: str,
    execution_id: str,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        expected = compile_execution_plan(
            expected_request,
            target_tree_sha256=target_tree_sha256,
            execution_id=execution_id,
        ).to_json()
    except (ExecutionPlanError, KeyError, TypeError) as exc:
        errors.append(f"execution plan request invalid: {exc}")
        expected = None
    if not isinstance(payload, dict):
        errors.append("execution plan must be an object")
    else:
        try:
            _validate_execution_plan_schema(payload)
        except SchemaValidationError as exc:
            errors.append(f"execution plan schema invalid: {exc}")
        if not errors:
            unsigned = {
                key: value for key, value in payload.items() if key != "plan_id"
            }
            if payload.get("plan_id") != sha256_json(unsigned):
                errors.append("execution plan id is invalid")
            elif expected is not None:
                identity_fields = (
                    "repository",
                    "pull_request",
                    "base_sha",
                    "head_sha",
                    "target_tree_sha256",
                    "execution_id",
                    "evaluator_sha",
                    "config_sha256",
                )
                mismatch = next(
                    (
                        field
                        for field in identity_fields
                        if payload.get(field) != expected.get(field)
                    ),
                    None,
                )
                if mismatch is not None:
                    errors.append(f"execution plan identity mismatch: {mismatch}")
                elif payload != expected:
                    errors.append("execution plan differs from evaluator-owned plan")
    return {
        "schema_version": "1.0",
        "capability_status": "BLOCK_TECHNICAL" if errors else "PASS",
        "plan_id": payload.get("plan_id", "") if isinstance(payload, dict) else "",
        "errors": errors,
    }


def _validate_execution_plan_schema(payload: dict[str, Any]) -> None:
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


def _unsigned_payload(plan: ExecutionPlan) -> dict[str, Any]:
    payload = plan.to_json()
    payload.pop("plan_id")
    return payload


def _validate_request(request: Mapping[str, Any]) -> None:
    _validate_request_fields(request)
    _validate_request_identity(request)
    _validate_request_selection(request)


def _validate_request_fields(request: Mapping[str, Any]) -> None:
    missing = sorted(_REQUEST_FIELDS - set(request))
    if missing:
        raise ExecutionPlanError(f"missing execution plan request field: {missing[0]}")
    unexpected = sorted(str(key) for key in request if key not in _REQUEST_FIELDS)
    if unexpected:
        raise ExecutionPlanError(
            f"unexpected execution plan request field: {unexpected[0]}"
        )


def _validate_request_identity(request: Mapping[str, Any]) -> None:
    if request.get("schema_version") != "1.0":
        raise ExecutionPlanError("execution plan request schema_version must be '1.0'")
    repository = request.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise ExecutionPlanError("execution plan request repository must be owner/name")
    pull_request = request.get("pull_request")
    if (
        not isinstance(pull_request, int)
        or isinstance(pull_request, bool)
        or pull_request < 1
    ):
        raise ExecutionPlanError(
            "execution plan request pull_request must be a positive integer"
        )
    if pull_request > _MAX_PULL_REQUEST:
        raise ExecutionPlanError(
            f"execution plan request pull_request must not exceed {_MAX_PULL_REQUEST}"
        )
    for field in ("base_sha", "head_sha", "evaluator_sha"):
        value = request.get(field)
        if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
            raise ExecutionPlanError(
                f"execution plan request {field} must be a lowercase 40-character SHA"
            )
    config_sha256 = request.get("config_sha256")
    if not isinstance(config_sha256, str) or not _SHA256_RE.fullmatch(config_sha256):
        raise ExecutionPlanError(
            "execution plan request config_sha256 must be a lowercase SHA-256"
        )


def _validate_protected_binding(field: str, value: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ExecutionPlanError(f"execution plan {field} must be a lowercase SHA-256")
    return value


def _validate_request_selection(request: Mapping[str, Any]) -> None:
    for field in ("capability", "adapter_id"):
        value = request.get(field)
        if not isinstance(value, str) or not value:
            raise ExecutionPlanError(
                f"execution plan request {field} must be a non-empty string"
            )
