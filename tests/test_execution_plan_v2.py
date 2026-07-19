from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2Error,
    assess_execution_plan_v2,
    compile_execution_plan_v2,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


def _receipt() -> CheckoutReceipt:
    receipt = CheckoutReceipt(
        schema_version="1.0",
        receipt_id="",
        repository={"id": 123, "full_name": "markheck-solutions/governance"},
        pull_request={
            "number": 81,
            "url": "https://github.com/markheck-solutions/governance/pull/81",
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "base_tree_sha": "c" * 40,
            "head_tree_sha": "d" * 40,
        },
        evaluator={"commit_sha": "e" * 40, "tree_sha": "f" * 40},
        workflow={
            "workflow_ref": "markheck-solutions/governance/.github/workflows/governance.yml@refs/heads/main",
            "run_id": 999,
            "run_attempt": 1,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "observed_at": "2026-07-19T12:00:00Z",
        },
        git_path=str(Path("C:/trusted/git.exe")),
        git_sha256="3" * 64,
        docker={
            "path": str(Path("C:/trusted/docker.exe")),
            "sha256": "4" * 64,
            "host": "npipe:////./pipe/docker_engine",
        },
        config_sha256="1" * 64,
        standard_sha256="2" * 64,
    )
    payload = receipt.to_json()
    payload.pop("receipt_id")
    return CheckoutReceipt(**{**receipt.__dict__, "receipt_id": sha256_json(payload)})


class ExecutionPlanV2Tests(unittest.TestCase):
    def test_compiles_only_from_authenticated_checkout_receipt(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )

        payload = plan.to_json()
        validate_named("execution_plan_v2", payload)
        self.assertEqual(payload["checkout_receipt_id"], _receipt().receipt_id)
        self.assertEqual(payload["target"]["tree_sha"], "d" * 40)
        self.assertEqual(payload["evaluator"]["tree_sha"], "f" * 40)
        self.assertEqual(
            payload["runtime"]["image"],
            "python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d",
        )
        self.assertEqual(payload["runtime"]["policy_id"], "docker.lockdown.v1")
        self.assertEqual(
            payload["step"]["argv"],
            [
                "/opt/governance-toolchain/ruff",
                "check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                ".",
            ],
        )
        self.assertEqual(
            payload["runtime"]["toolchain_sha256"],
            "68971e86ff2a4bd44f45dc2dd28e590e785fea12dc966410ae269173ce6d64db",
        )

    def test_rejects_fabricated_or_mutated_receipt(self) -> None:
        receipt = _receipt()
        for field, value in (
            ("receipt_id", "0" * 64),
            ("config_sha256", "9" * 64),
        ):
            with self.subTest(field=field):
                hostile = CheckoutReceipt(**{**receipt.__dict__, field: value})
                with self.assertRaisesRegex(
                    ExecutionPlanV2Error, "checkout receipt integrity is invalid"
                ):
                    compile_execution_plan_v2(
                        hostile,
                        capability="lint",
                        adapter_id="python.ruff-check.v1",
                    )

    def test_rejects_self_hashed_schema_invalid_receipt(self) -> None:
        cases = (
            ({"run_id": "not-an-integer"}, "schema is invalid"),
            ({"observed_at": "not-a-date"}, "observed_at is invalid"),
        )
        for workflow_change, expected in cases:
            with self.subTest(workflow_change=workflow_change):
                receipt = _receipt()
                workflow = {**receipt.workflow, **workflow_change}
                hostile = CheckoutReceipt(
                    **{**receipt.__dict__, "workflow": workflow, "receipt_id": ""}
                )
                payload = hostile.to_json()
                payload.pop("receipt_id")
                hostile = CheckoutReceipt(
                    **{**hostile.__dict__, "receipt_id": sha256_json(payload)}
                )

                with self.assertRaisesRegex(ExecutionPlanV2Error, expected):
                    compile_execution_plan_v2(
                        hostile,
                        capability="lint",
                        adapter_id="python.ruff-check.v1",
                    )

    def test_blocks_rehashed_runtime_or_command_mutation(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )
        for path, value in (
            (("runtime", "image"), "python:latest"),
            (("runtime", "policy_id"), "docker.unlocked.v1"),
            (("step", "argv"), ["sh", "-c", "ruff check . || true"]),
        ):
            with self.subTest(path=path):
                payload = deepcopy(plan.to_json())
                payload[path[0]][path[1]] = value
                unsigned = {
                    key: item for key, item in payload.items() if key != "plan_id"
                }
                payload["plan_id"] = sha256_json(unsigned)

                result = assess_execution_plan_v2(payload, _receipt())

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")


if __name__ == "__main__":
    unittest.main()
