from __future__ import annotations

import base64
import tempfile
import unittest
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from governance_eval.capability_catalog import capability_adapters
from governance_eval.execution_plan_v2 import ExecutionPlanV2, compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.docker_runtime import RuntimePaths, docker_gate_argv
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named, validate_packaged_named
from receipt_fixture import scope_manifest, strict_receipt, toolchain_binding


class ExecutionResultV2Tests(unittest.TestCase):
    def test_accepts_exact_host_owned_pass_result(self) -> None:
        result, plan, receipt, scope, toolchain = _result()

        validate_named("execution_result_v2", result)
        validate_packaged_named("execution_result_v2", result)
        assessment = _validate(result, plan, receipt, scope, toolchain)

        self.assertEqual(assessment["integrity_status"], "INTEGRITY_VALID")

    def test_rejects_rehashed_identity_runtime_scope_and_command_mutation(self) -> None:
        mutations = (
            ("plan", lambda value: value.__setitem__("plan_id", "0" * 64)),
            (
                "runtime",
                lambda value: value["runtime"].__setitem__("network", "bridge"),
            ),
            (
                "scope",
                lambda value: value["scope"].__setitem__("manifest_id", "0" * 64),
            ),
            (
                "command",
                lambda value: value["command"].append("--exit-zero"),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                result, plan, receipt, scope, toolchain = _result()
                mutate(result)
                _rehash(result)
                self.assertEqual(
                    _validate(result, plan, receipt, scope, toolchain)[
                        "integrity_status"
                    ],
                    "INTEGRITY_INVALID",
                )

    def test_rejects_output_mutation_truncation_and_flood(self) -> None:
        for name in ("digest", "truncated-pass", "combined-limit"):
            with self.subTest(name=name):
                result, plan, receipt, scope, toolchain = _result()
                if name == "digest":
                    result["stdout"]["captured_base64"] = "WA=="
                elif name == "truncated-pass":
                    result["stdout"]["truncated"] = True
                    _primary_process(result)["stdout"]["truncated"] = True
                else:
                    result["stdout"] = _stream(b"a" * 40000)
                    result["stderr"] = _stream(b"b" * 40000)
                    _primary_process(result)["stdout"] = deepcopy(result["stdout"])
                    _primary_process(result)["stderr"] = deepcopy(result["stderr"])
                _rehash(result)
                self.assertEqual(
                    _validate(result, plan, receipt, scope, toolchain)[
                        "integrity_status"
                    ],
                    "INTEGRITY_INVALID",
                )

    def test_failure_evidence_is_valid_but_cannot_claim_pass(self) -> None:
        result, plan, receipt, scope, toolchain = _result()
        result["capability_status"] = "BLOCK_TECHNICAL"
        result["termination"] = "TIMED_OUT"
        result["exit_code"] = 137
        result["completed_at"] = "2026-07-19T17:01:30Z"
        result["duration_seconds"] = 90.0
        process = _primary_process(result)
        process["termination"] = "TIMED_OUT"
        process["exit_code"] = 137
        process["completed_at"] = "2026-07-19T17:01:30Z"
        process["duration_seconds"] = 90.0
        _rehash(result)

        self.assertEqual(
            _validate(result, plan, receipt, scope, toolchain)["integrity_status"],
            "INTEGRITY_VALID",
        )

        result["capability_status"] = "PASS"
        _rehash(result)
        self.assertEqual(
            _validate(result, plan, receipt, scope, toolchain)["integrity_status"],
            "INTEGRITY_INVALID",
        )

    def test_expected_artifacts_are_exact_for_pass(self) -> None:
        build = capability_adapters()[6]
        result, plan, receipt, scope, toolchain = _result(build, artifacts=[_wheel()])
        self.assertEqual(
            _validate(result, plan, receipt, scope, toolchain)["integrity_status"],
            "INTEGRITY_VALID",
        )

        for mutation in ("missing", "extra", "duplicate"):
            with self.subTest(mutation=mutation):
                hostile = deepcopy(result)
                if mutation == "missing":
                    hostile["artifacts"] = []
                elif mutation == "extra":
                    hostile["artifacts"].append(_summary())
                else:
                    hostile["artifacts"].append(deepcopy(hostile["artifacts"][0]))
                _rehash(hostile)
                self.assertEqual(
                    _validate(hostile, plan, receipt, scope, toolchain)[
                        "integrity_status"
                    ],
                    "INTEGRITY_INVALID",
                )

    def test_mutated_plan_cannot_authorize_matching_result(self) -> None:
        result, plan, receipt, scope, toolchain = _result()
        hostile_payload = plan.to_json()
        hostile_payload["runtime"]["network"] = "bridge"
        hostile_payload["plan_id"] = sha256_json(
            {key: value for key, value in hostile_payload.items() if key != "plan_id"}
        )
        hostile_plan = ExecutionPlanV2(**hostile_payload)
        result["runtime"]["network"] = "bridge"
        result["plan_id"] = hostile_plan.plan_id
        _rehash(result)

        self.assertEqual(
            _validate(result, hostile_plan, receipt, scope, toolchain)[
                "integrity_status"
            ],
            "INTEGRITY_INVALID",
        )


def _result(adapter=None, *, artifacts=None):
    adapter = adapter or capability_adapters()[0]
    receipt = strict_receipt()
    scope = scope_manifest(receipt, adapter)
    toolchain = (
        toolchain_binding(receipt)
        if adapter.execution == "docker" and adapter.mount_profile != "wheel-only.v1"
        else None
    )
    inputs = (_input_wheel(),) if adapter.mount_profile == "wheel-only.v1" else ()
    with patch(
        "governance_eval.execution_plan_v2.build_scope_manifest",
        return_value=deepcopy(scope),
    ):
        plan = compile_execution_plan_v2(
            receipt,
            capability=adapter.capability,
            adapter_id=adapter.adapter_id,
            scope_manifest=scope,
            target_root=Path("C:/target"),
            evaluator_root=Path("C:/evaluator"),
            toolchain_manifest=toolchain,
            input_artifacts=inputs,
        )
    command, processes = _process_evidence(plan)
    payload = {
        "schema_version": "2.0",
        "receipt_kind": "execution_result.v2",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": receipt.receipt_id,
        "capability": adapter.capability,
        "adapter_id": adapter.adapter_id,
        "capability_status": "PASS",
        "runtime": deepcopy(plan.runtime),
        "command": command,
        "scope": {
            "rule_id": adapter.scope_rule_id,
            "manifest_id": scope["manifest_id"],
            "file_count": len(scope["entries"]),
        },
        "artifacts": deepcopy(artifacts or []),
        "processes": processes,
        "started_at": "2026-07-19T17:00:00Z",
        "completed_at": "2026-07-19T17:00:01Z",
        "duration_seconds": 1.0,
        "timeout_seconds": adapter.timeout_seconds,
        "total_timeout_seconds": adapter.total_timeout_seconds,
        "termination": "EXITED",
        "exit_code": 0,
        "stdout": _stream(),
        "stderr": _stream(),
        "errors": [],
    }
    _rehash(payload)
    return payload, plan, receipt, scope, toolchain


def _process_evidence(plan: ExecutionPlanV2):
    if plan.step["execution"] == "trusted_judge":
        command = [
            plan.runtime["python"]["path"],
            "trusted-operation",
            plan.step["operation_id"],
        ]
        return command, [_process(command)]
    container_id = "a" * 64
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        values = [
            root / name
            for name in (
                "workspace",
                "base-tests",
                "scope",
                "input",
                "staging",
                "output",
                "toolchain",
            )
        ]
        for value in values:
            value.mkdir()
        paths = RuntimePaths(
            root=root,
            workspace=values[0],
            base_tests=values[1],
            scope=values[2],
            input=values[3],
            staging=values[4],
            output=values[5],
        )
        run = docker_gate_argv(
            plan=plan,
            docker=Path(plan.runtime["docker"]["path"]),
            paths=paths,
            evaluator_root=Path.cwd(),
            toolchain_root=None
            if plan.step["mount_profile"] == "wheel-only.v1"
            else values[6],
            container_name=f"governance-{plan.plan_id[:32]}",
        )
        create = [
            *run[:2],
            "create",
            f"--cidfile={root / 'container.cid'}",
            *run[3:],
        ]
    start = [*run[:2], "start", "--attach", container_id]
    return start, [
        _process(create, (container_id + "\n").encode("ascii")),
        _process(start),
    ]


def _process(command, stdout: bytes = b""):
    return {
        "command": deepcopy(command),
        "termination": "EXITED",
        "exit_code": 0,
        "stdout": _stream(stdout),
        "stderr": _stream(),
        "started_at": "2026-07-19T17:00:00Z",
        "completed_at": "2026-07-19T17:00:01Z",
        "duration_seconds": 1.0,
        "errors": [],
    }


def _primary_process(payload):
    return next(
        process
        for process in payload["processes"]
        if process["command"] == payload["command"]
    )


def _validate(payload, plan, receipt, scope, toolchain):
    with patch(
        "governance_eval.execution_plan_v2.build_scope_manifest",
        return_value=deepcopy(scope),
    ):
        return validate_execution_result_v2(
            payload,
            plan,
            receipt,
            capability=plan.step["capability"],
            adapter_id=plan.step["adapter_id"],
            scope_manifest=scope,
            target_root=Path("C:/target"),
            evaluator_root=Path("C:/evaluator"),
            toolchain_manifest=toolchain,
            input_artifacts=(_input_wheel(),)
            if plan.step["mount_profile"] == "wheel-only.v1"
            else (),
        )


def _stream(content: bytes = b"") -> dict[str, object]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": False,
    }


def _wheel() -> dict[str, object]:
    return {
        "kind": "python-wheel",
        "name": "python-wheel",
        "filename": "governance_eval-0.1.0-py3-none-any.whl",
        "sha256": "1" * 64,
        "size_bytes": 1234,
    }


def _summary() -> dict[str, object]:
    return {
        "kind": "summary",
        "name": "unexpected-summary",
        "filename": "summary.json",
        "sha256": "2" * 64,
        "size_bytes": 20,
    }


def _input_wheel() -> dict[str, object]:
    return {
        **_wheel(),
        "producer_plan_id": "2" * 64,
        "producer_artifact_id": "3" * 64,
    }


def _rehash(payload: dict[str, object]) -> None:
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})


if __name__ == "__main__":
    unittest.main()
