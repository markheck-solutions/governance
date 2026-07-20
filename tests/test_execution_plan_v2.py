from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from governance_eval.capability_catalog import capability_adapters
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2Error,
    assess_execution_plan_v2,
    compile_execution_plan_v2,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named, validate_packaged_named
from receipt_fixture import scope_manifest, strict_receipt, toolchain_binding


class ExecutionPlanV2Tests(unittest.TestCase):
    def test_compiles_all_ten_evaluator_owned_adapters(self) -> None:
        receipt = strict_receipt()
        for adapter in capability_adapters():
            with self.subTest(adapter=adapter.adapter_id):
                scope = scope_manifest(receipt, adapter)
                toolchain = (
                    toolchain_binding(receipt)
                    if adapter.execution == "docker"
                    and adapter.mount_profile != "wheel-only.v1"
                    else None
                )
                artifacts = (
                    (_wheel(),) if adapter.mount_profile == "wheel-only.v1" else ()
                )
                plan = _compile(
                    receipt,
                    adapter,
                    scope,
                    toolchain=toolchain,
                    artifacts=artifacts,
                )

                validate_named("execution_plan_v2", plan.to_json())
                validate_packaged_named("execution_plan_v2", plan.to_json())
                self.assertEqual(plan.step["capability"], adapter.capability)
                self.assertEqual(plan.step["adapter_id"], adapter.adapter_id)
                self.assertEqual(plan.inputs["scope_manifest_id"], scope["manifest_id"])
                if adapter.execution == "docker":
                    self.assertIsInstance(plan.step["argv"], list)
                    self.assertIsNone(plan.step["operation_id"])
                else:
                    self.assertIsNone(plan.step["argv"])
                    self.assertEqual(plan.step["operation_id"], adapter.operation_id)

    def test_plan_copies_complete_receipt_identity(self) -> None:
        receipt = strict_receipt("CANDIDATE")
        adapter = capability_adapters()[0]
        plan = _compile(
            receipt,
            adapter,
            scope_manifest(receipt, adapter),
            toolchain=toolchain_binding(receipt),
        )

        self.assertEqual(plan.evaluation_role, "CANDIDATE")
        self.assertEqual(plan.target, receipt.evaluation_target)
        expected_policy = deepcopy(receipt.policy)
        expected_policy["execution_profile"].pop("capabilities")
        self.assertEqual(plan.policy, expected_policy)
        self.assertEqual(plan.caller_workflow, receipt.workflows["caller"])
        self.assertEqual(plan.evaluator["workflow"], receipt.workflows["evaluator"])
        self.assertEqual(plan.run, receipt.workflows["run"])

    def test_rejects_scope_toolchain_and_wheel_mutation(self) -> None:
        receipt = strict_receipt()
        lint = capability_adapters()[0]
        hostile_scope = scope_manifest(receipt, lint)
        hostile_scope["entries"][0]["path"] = "ignored.txt"
        cases = (
            (
                lint,
                hostile_scope,
                toolchain_binding(receipt),
                (),
                "Python scope",
            ),
            (
                lint,
                scope_manifest(receipt, lint),
                {**toolchain_binding(receipt), "lock_sha256": "0" * 64},
                (),
                "toolchain",
            ),
            (
                capability_adapters()[7],
                scope_manifest(receipt, capability_adapters()[7]),
                None,
                ({**_wheel(), "filename": "../escape.whl"},),
                "wheel",
            ),
        )
        for adapter, scope, toolchain, artifacts, expected in cases:
            with (
                self.subTest(expected=expected),
                self.assertRaisesRegex(ExecutionPlanV2Error, expected),
            ):
                _compile(
                    receipt, adapter, scope, toolchain=toolchain, artifacts=artifacts
                )

    def test_rejects_unknown_or_cross_paired_adapter(self) -> None:
        receipt = strict_receipt()
        adapter = capability_adapters()[0]
        scope = scope_manifest(receipt, adapter)
        for capability, adapter_id in (
            ("lint", "python.unknown.v1"),
            ("format_check", "python.ruff-check.v1"),
        ):
            with self.subTest(capability=capability, adapter_id=adapter_id):
                with self.assertRaisesRegex(ExecutionPlanV2Error, "unsupported"):
                    with patch(
                        "governance_eval.execution_plan_v2.build_scope_manifest",
                        return_value=deepcopy(scope),
                    ):
                        compile_execution_plan_v2(
                            receipt,
                            capability=capability,
                            adapter_id=adapter_id,
                            scope_manifest=scope,
                            target_root=Path("C:/target"),
                            evaluator_root=Path("C:/evaluator"),
                            toolchain_manifest=toolchain_binding(receipt),
                        )

    def test_rejects_valid_but_narrowed_authenticated_scope(self) -> None:
        receipt = strict_receipt()
        adapter = capability_adapters()[0]
        full = scope_manifest(receipt, adapter)
        full["entries"].append(
            {
                "path": "governance_eval/second.py",
                "mode": "100644",
                "blob_sha": "2" * 40,
                "size_bytes": 10,
            }
        )
        full["manifest_id"] = sha256_json(
            {key: value for key, value in full.items() if key != "manifest_id"}
        )
        narrowed = deepcopy(full)
        narrowed["entries"].pop()
        narrowed["manifest_id"] = sha256_json(
            {key: value for key, value in narrowed.items() if key != "manifest_id"}
        )

        with (
            patch(
                "governance_eval.execution_plan_v2.build_scope_manifest",
                return_value=full,
            ),
            self.assertRaisesRegex(ExecutionPlanV2Error, "authenticated Git scope"),
        ):
            compile_execution_plan_v2(
                receipt,
                capability=adapter.capability,
                adapter_id=adapter.adapter_id,
                scope_manifest=narrowed,
                target_root=Path("C:/target"),
                evaluator_root=Path("C:/evaluator"),
                toolchain_manifest=toolchain_binding(receipt),
            )

    def test_rehashed_plan_mutation_never_becomes_evaluator_owned(self) -> None:
        receipt = strict_receipt()
        adapter = capability_adapters()[0]
        scope = scope_manifest(receipt, adapter)
        toolchain = toolchain_binding(receipt)
        plan = _compile(
            receipt,
            adapter,
            scope,
            toolchain=toolchain,
        )
        for path, value in (
            (("runtime", "network"), "bridge"),
            (("step", "argv"), ["sh", "-c", "true"]),
            (("target", "tree_sha"), "0" * 40),
        ):
            with self.subTest(path=path):
                payload = deepcopy(plan.to_json())
                payload[path[0]][path[1]] = value
                payload["plan_id"] = sha256_json(
                    {key: item for key, item in payload.items() if key != "plan_id"}
                )
                with patch(
                    "governance_eval.execution_plan_v2.build_scope_manifest",
                    return_value=deepcopy(scope),
                ):
                    assessment = assess_execution_plan_v2(
                        payload,
                        receipt,
                        capability=adapter.capability,
                        adapter_id=adapter.adapter_id,
                        scope_manifest=scope,
                        target_root=Path("C:/target"),
                        evaluator_root=Path("C:/evaluator"),
                        toolchain_manifest=toolchain,
                    )
                self.assertEqual(assessment["capability_status"], "BLOCK_TECHNICAL")

    def test_returned_plan_has_no_mutable_aliases(self) -> None:
        receipt = strict_receipt()
        adapter = capability_adapters()[0]
        scope = scope_manifest(receipt, adapter)
        plan = _compile(
            receipt,
            adapter,
            scope,
            toolchain=toolchain_binding(receipt),
        )
        payload = plan.to_json()
        payload["target"]["tree_sha"] = "0" * 40
        scope["entries"].clear()
        self.assertNotEqual(plan.target["tree_sha"], "0" * 40)
        self.assertEqual(len(plan.step["argv"]), len(adapter.argv_prefix) + 1)


def _wheel() -> dict[str, object]:
    return {
        "kind": "python-wheel",
        "name": "python-wheel",
        "filename": "governance_eval-0.1.0-py3-none-any.whl",
        "sha256": "1" * 64,
        "size_bytes": 1234,
        "producer_plan_id": "2" * 64,
        "producer_artifact_id": "3" * 64,
    }


def _compile(receipt, adapter, scope, *, toolchain=None, artifacts=()):
    with patch(
        "governance_eval.execution_plan_v2.build_scope_manifest",
        return_value=deepcopy(scope),
    ):
        return compile_execution_plan_v2(
            receipt,
            capability=adapter.capability,
            adapter_id=adapter.adapter_id,
            scope_manifest=scope,
            target_root=Path("C:/target"),
            evaluator_root=Path("C:/evaluator"),
            toolchain_manifest=toolchain,
            input_artifacts=artifacts,
        )


if __name__ == "__main__":
    unittest.main()
