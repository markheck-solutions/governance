from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance_eval.capability_catalog import (
    CapabilityAdapter,
    get_capability_adapter,
)
from governance_eval.checkout_receipt import (
    CheckoutReceipt,
    CheckoutReceiptError,
    validate_checkout_receipt_v1,
)
from governance_eval.docker_toolchain import CERTIFIED_TOOLCHAIN_BUNDLE_ID
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.scope_manifest import (
    ScopeManifestError,
    build_scope_manifest,
    scope_paths,
    validate_scope_manifest,
)

_ARTIFACT_FIELDS = {
    "kind",
    "name",
    "filename",
    "sha256",
    "size_bytes",
    "producer_plan_id",
    "producer_artifact_id",
}


class ExecutionPlanV2Error(ValueError):
    pass


@dataclass(frozen=True)
class ExecutionPlanV2:
    schema_version: str
    receipt_kind: str
    plan_id: str
    checkout_receipt_id: str
    evaluation_role: str
    repository: dict[str, Any]
    pull_request: dict[str, Any]
    target: dict[str, Any]
    policy: dict[str, Any]
    caller_workflow: dict[str, Any]
    evaluator: dict[str, Any]
    run: dict[str, Any]
    inputs: dict[str, Any]
    runtime: dict[str, Any]
    step: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return deepcopy(self.__dict__)


def compile_execution_plan_v2(
    receipt: CheckoutReceipt | Mapping[str, object],
    *,
    capability: str,
    adapter_id: str,
    scope_manifest: Mapping[str, object],
    target_root: Path,
    evaluator_root: Path,
    toolchain_manifest: Mapping[str, object] | None = None,
    input_artifacts: Sequence[Mapping[str, object]] = (),
) -> ExecutionPlanV2:
    trusted_receipt = _trusted_receipt(receipt)
    _validate_configured_adapter(trusted_receipt, capability, adapter_id)
    adapter = _adapter(capability, adapter_id)
    try:
        scope = validate_scope_manifest(
            scope_manifest,
            receipt=trusted_receipt,
            adapter=adapter,
        )
    except ScopeManifestError as exc:
        raise ExecutionPlanV2Error(str(exc)) from exc
    _validate_trusted_scope(
        scope,
        trusted_receipt,
        adapter,
        target_root=target_root,
        evaluator_root=evaluator_root,
    )
    toolchain = _toolchain_binding(adapter, toolchain_manifest, trusted_receipt)
    artifacts = _input_artifacts(adapter, input_artifacts)
    plan = ExecutionPlanV2(
        schema_version="2.0",
        receipt_kind="execution_plan.v2",
        plan_id="",
        checkout_receipt_id=trusted_receipt["receipt_id"],
        evaluation_role=trusted_receipt["evaluation_role"],
        repository={
            "id": trusted_receipt["repository"]["id"],
            "full_name": trusted_receipt["repository"]["full_name"],
        },
        pull_request=deepcopy(trusted_receipt["pull_request"]),
        target=deepcopy(trusted_receipt["evaluation_target"]),
        policy=_plan_policy(trusted_receipt),
        caller_workflow=deepcopy(trusted_receipt["workflows"]["caller"]),
        evaluator=_evaluator_identity(trusted_receipt),
        run=deepcopy(trusted_receipt["workflows"]["run"]),
        inputs={
            "scope_manifest_id": scope["manifest_id"],
            "toolchain": toolchain,
            "artifacts": artifacts,
        },
        runtime=_runtime_identity(adapter, trusted_receipt, toolchain),
        step=_step(adapter, scope),
    )
    plan = replace(plan, plan_id=sha256_json(_unsigned(plan)))
    _validate_plan_schema(plan.to_json())
    return plan


def assess_execution_plan_v2(
    payload: object,
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
    errors: list[str] = []
    try:
        expected = compile_execution_plan_v2(
            receipt,
            capability=capability,
            adapter_id=adapter_id,
            scope_manifest=scope_manifest,
            target_root=target_root,
            evaluator_root=evaluator_root,
            toolchain_manifest=toolchain_manifest,
            input_artifacts=input_artifacts,
        ).to_json()
    except ExecutionPlanV2Error as exc:
        errors.append(str(exc))
        expected = None
    if not isinstance(payload, dict):
        errors.append("execution plan v2 must be an object")
    else:
        try:
            _validate_plan_schema(payload)
        except ExecutionPlanV2Error as exc:
            errors.append(str(exc))
        if not errors and payload != expected:
            errors.append("execution plan v2 differs from evaluator-owned plan")
    return {
        "schema_version": "2.0",
        "capability_status": "BLOCK_TECHNICAL" if errors else "PASS",
        "plan_id": payload.get("plan_id", "") if isinstance(payload, dict) else "",
        "errors": errors,
    }


def _trusted_receipt(
    receipt: CheckoutReceipt | Mapping[str, object],
) -> dict[str, Any]:
    try:
        return validate_checkout_receipt_v1(receipt)
    except CheckoutReceiptError as exc:
        raise ExecutionPlanV2Error(f"checkout receipt is invalid: {exc}") from exc


def _adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    try:
        adapter = get_capability_adapter(capability, adapter_id)
    except KeyError as exc:
        raise ExecutionPlanV2Error(
            f"unsupported capability adapter: {capability}/{adapter_id}"
        ) from exc
    _validate_adapter_contract(adapter)
    return adapter


def _validate_configured_adapter(
    receipt: Mapping[str, Any], capability: str, adapter_id: str
) -> None:
    configured = receipt["policy"]["execution_profile"]["capabilities"].get(capability)
    if configured != adapter_id:
        raise ExecutionPlanV2Error(
            "adapter is unsupported or not selected by authenticated config: "
            f"{capability}/{adapter_id}"
        )


def _plan_policy(receipt: Mapping[str, Any]) -> dict[str, Any]:
    policy = deepcopy(receipt["policy"])
    policy["execution_profile"].pop("capabilities")
    return policy


def _validate_trusted_scope(
    scope: Mapping[str, Any],
    receipt: Mapping[str, Any],
    adapter: CapabilityAdapter,
    *,
    target_root: Path,
    evaluator_root: Path,
) -> None:
    try:
        expected = build_scope_manifest(
            receipt=receipt,
            adapter=adapter,
            target_root=target_root,
            evaluator_root=evaluator_root,
        )
    except ScopeManifestError as exc:
        raise ExecutionPlanV2Error(f"trusted scope unavailable: {exc}") from exc
    if scope != expected:
        raise ExecutionPlanV2Error(
            "scope manifest differs from authenticated Git scope"
        )


def _validate_adapter_contract(adapter: CapabilityAdapter) -> None:
    has_argv = bool(adapter.argv_prefix)
    has_operation = adapter.operation_id is not None
    if has_argv == has_operation:
        raise ExecutionPlanV2Error("adapter execution contract is ambiguous")
    if adapter.execution == "docker" and not has_argv:
        raise ExecutionPlanV2Error("Docker adapter command is missing")
    if adapter.execution == "trusted_judge" and not has_operation:
        raise ExecutionPlanV2Error("trusted judge operation is missing")


def _toolchain_binding(
    adapter: CapabilityAdapter,
    manifest: Mapping[str, object] | None,
    receipt: Mapping[str, Any],
) -> dict[str, str] | None:
    required = (
        adapter.execution == "docker" and adapter.mount_profile != "wheel-only.v1"
    )
    if not required:
        if manifest is not None:
            raise ExecutionPlanV2Error("adapter does not accept a toolchain manifest")
        return None
    if not isinstance(manifest, Mapping):
        raise ExecutionPlanV2Error("adapter requires a toolchain manifest")
    expected = {
        "bundle_id": CERTIFIED_TOOLCHAIN_BUNDLE_ID,
        "manifest_sha256": receipt["runtime"]["toolchain"]["manifest_sha256"],
        "lock_sha256": receipt["runtime"]["toolchain"]["lock_sha256"],
        "image": receipt["runtime"]["container_image"]["reference"],
    }
    if dict(manifest) != expected:
        raise ExecutionPlanV2Error("toolchain manifest differs from checkout receipt")
    return expected


def _input_artifacts(
    adapter: CapabilityAdapter,
    artifacts: Sequence[Mapping[str, object]],
) -> list[dict[str, Any]]:
    if adapter.mount_profile != "wheel-only.v1":
        if artifacts:
            raise ExecutionPlanV2Error("adapter does not accept input artifacts")
        return []
    if len(artifacts) != 1:
        raise ExecutionPlanV2Error("package audit requires exactly one wheel")
    artifact = deepcopy(dict(artifacts[0]))
    _validate_wheel_artifact(artifact)
    return [artifact]


def _validate_wheel_artifact(artifact: Mapping[str, object]) -> None:
    if set(artifact) != _ARTIFACT_FIELDS:
        raise ExecutionPlanV2Error("wheel input artifact shape is invalid")
    filename = artifact.get("filename")
    if (
        artifact.get("kind") != "python-wheel"
        or artifact.get("name") != "python-wheel"
        or not isinstance(filename, str)
        or not filename.endswith(".whl")
        or any(character in filename for character in ("/", "\\", "\r", "\n", "\0"))
    ):
        raise ExecutionPlanV2Error("wheel input artifact identity is invalid")
    _validate_artifact_hashes(artifact)


def _validate_artifact_hashes(artifact: Mapping[str, object]) -> None:
    for field in ("sha256", "producer_plan_id", "producer_artifact_id"):
        value = artifact.get(field)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ExecutionPlanV2Error(f"wheel input artifact {field} is invalid")
    size = artifact.get("size_bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= 64 * 1024 * 1024
    ):
        raise ExecutionPlanV2Error("wheel input artifact size is invalid")


def _evaluator_identity(receipt: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **deepcopy(receipt["evaluator"]),
        "workflow": deepcopy(receipt["workflows"]["evaluator"]),
    }


def _runtime_identity(
    adapter: CapabilityAdapter,
    receipt: Mapping[str, Any],
    toolchain: dict[str, str] | None,
) -> dict[str, Any]:
    if adapter.execution == "trusted_judge":
        return {
            "kind": "trusted_judge",
            "runtime_id": "trusted.python-git.v1",
            "python": deepcopy(receipt["runtime"]["python"]),
            "git": deepcopy(receipt["runtime"]["git"]),
        }
    return {
        "kind": "docker",
        "runtime_id": "docker.python-toolchain.v2",
        "policy_id": "docker.lockdown.v2",
        "image": deepcopy(receipt["runtime"]["container_image"]),
        "toolchain": deepcopy(toolchain),
        "pull": "never",
        "network": "none",
        "user": "65532:65532",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "pids_limit": 128,
        "memory_bytes": 536_870_912,
        "memory_swap_bytes": 536_870_912,
        "cpus": "1.0",
        "docker": deepcopy(receipt["runtime"]["docker"]),
    }


def _step(adapter: CapabilityAdapter, scope: Mapping[str, Any]) -> dict[str, Any]:
    argv = list(adapter.argv_prefix)
    if adapter.append_authenticated_paths:
        argv.extend(scope_paths(scope))
    return {
        "capability": adapter.capability,
        "adapter_id": adapter.adapter_id,
        "execution": adapter.execution,
        "scope_rule_id": adapter.scope_rule_id,
        "mount_profile": adapter.mount_profile,
        "working_directory": adapter.working_directory,
        "argv": argv if adapter.execution == "docker" else None,
        "operation_id": adapter.operation_id,
        "timeout_seconds": adapter.timeout_seconds,
        "total_timeout_seconds": adapter.total_timeout_seconds,
        "output_limit_bytes": adapter.output_limit_bytes,
        "expected_artifacts": list(adapter.expected_artifacts),
    }


def _validate_plan_schema(payload: object) -> None:
    try:
        validate_packaged_named("execution_plan_v2", payload)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise ExecutionPlanV2Error(
            f"execution plan v2 schema is invalid: {exc}"
        ) from exc


def _unsigned(plan: ExecutionPlanV2) -> dict[str, Any]:
    payload = plan.to_json()
    payload.pop("plan_id")
    return payload
