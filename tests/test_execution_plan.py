from __future__ import annotations

import unittest
from contextlib import chdir
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from re import escape
from tempfile import TemporaryDirectory

from governance_eval.execution_plan import (
    ExecutionPlanError,
    assess_execution_plan,
    compile_execution_plan,
    serialize_execution_plan,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


VALID_REQUEST = {
    "schema_version": "1.0",
    "repository": "markheck-solutions/governance",
    "pull_request": 44,
    "base_sha": "a" * 40,
    "head_sha": "b" * 40,
    "evaluator_sha": "c" * 40,
    "config_sha256": "d" * 64,
    "capability": "lint",
    "adapter_id": "python.ruff-check.v1",
}


class ExecutionPlanCompilationTests(unittest.TestCase):
    def test_compiles_deterministic_schema_valid_lint_plan(self) -> None:
        first = compile_execution_plan(VALID_REQUEST)
        second = compile_execution_plan(dict(reversed(VALID_REQUEST.items())))

        payload = first.to_json()
        validate_named("execution_plan", payload)
        self.assertEqual(
            payload["steps"],
            [
                {
                    "step_id": "lint",
                    "capability": "lint",
                    "adapter_id": "python.ruff-check.v1",
                    "argv": ["python", "-m", "ruff", "check", "."],
                    "working_directory": ".",
                    "timeout_seconds": 120,
                    "output_limit_bytes": 65536,
                }
            ],
        )
        self.assertEqual(
            serialize_execution_plan(first), serialize_execution_plan(second)
        )

        assessment = assess_execution_plan(payload, VALID_REQUEST)
        self.assertEqual(assessment["capability_status"], "PASS")
        self.assertEqual(assessment["errors"], [])

    def test_rejects_unsupported_adapter(self) -> None:
        request = {**VALID_REQUEST, "adapter_id": "python.unknown.v1"}

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "unsupported capability adapter: lint/python.unknown.v1",
        ):
            compile_execution_plan(request)

    def test_rejects_candidate_supplied_execution_fields(self) -> None:
        hostile_fields = {
            "command": "ruff check . || true",
            "shell": True,
            "argv": ["python", "-c", "pass"],
            "args": ["--exit-zero"],
        }

        for field, value in hostile_fields.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ExecutionPlanError,
                    f"unexpected execution plan request field: {field}",
                ):
                    compile_execution_plan({**VALID_REQUEST, field: value})

    def test_blocks_plan_mutation_even_when_attacker_rehashes_it(self) -> None:
        payload = deepcopy(compile_execution_plan(VALID_REQUEST).to_json())
        payload["steps"][0]["argv"] = ["python", "-m", "ruff", "check", "--exit-zero"]
        unsigned = {key: value for key, value in payload.items() if key != "plan_id"}
        payload["plan_id"] = sha256_json(unsigned)

        result = assess_execution_plan(payload, VALID_REQUEST)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"], ["execution plan differs from evaluator-owned plan"]
        )

    def test_blocks_plan_replay_against_new_head_or_config(self) -> None:
        payload = compile_execution_plan(VALID_REQUEST).to_json()
        replacements = {
            "head_sha": "e" * 40,
            "config_sha256": "f" * 64,
        }

        for field, value in replacements.items():
            with self.subTest(field=field):
                result = assess_execution_plan(
                    payload,
                    {**VALID_REQUEST, field: value},
                )
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(
                    result["errors"],
                    [f"execution plan identity mismatch: {field}"],
                )

    def test_uses_evaluator_owned_schema_outside_candidate_control(self) -> None:
        payload = compile_execution_plan(VALID_REQUEST).to_json()

        with TemporaryDirectory() as directory:
            candidate_root = Path(directory)
            (candidate_root / "TASK.md").write_text("candidate", encoding="utf-8")
            (candidate_root / "AGENTS.md").write_text("candidate", encoding="utf-8")
            schema_dir = candidate_root / "schemas" / "v1"
            schema_dir.mkdir(parents=True)
            (schema_dir / "execution_plan.schema.json").write_text(
                '{"type":"object","required":["attacker_controlled"]}',
                encoding="utf-8",
            )

            with chdir(candidate_root):
                result = assess_execution_plan(payload, VALID_REQUEST)

        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["errors"], [])

    def test_rejects_missing_or_malformed_plan_identity(self) -> None:
        missing_head = dict(VALID_REQUEST)
        missing_head.pop("head_sha")
        cases = (
            (missing_head, "missing execution plan request field: head_sha"),
            (
                {**VALID_REQUEST, "schema_version": "2.0"},
                "execution plan request schema_version must be '1.0'",
            ),
            (
                {**VALID_REQUEST, "repository": "not-a-repository"},
                "execution plan request repository must be owner/name",
            ),
            (
                {**VALID_REQUEST, "pull_request": 0},
                "execution plan request pull_request must be a positive integer",
            ),
            (
                {**VALID_REQUEST, "head_sha": "ABC"},
                "execution plan request head_sha must be a lowercase 40-character SHA",
            ),
            (
                {**VALID_REQUEST, "config_sha256": "0" * 63},
                "execution plan request config_sha256 must be a lowercase SHA-256",
            ),
        )

        for request, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExecutionPlanError, escape(message)):
                    compile_execution_plan(request)

    def test_rejects_non_object_request(self) -> None:
        with self.assertRaisesRegex(
            ExecutionPlanError,
            "execution plan request must be an object",
        ):
            compile_execution_plan([])  # type: ignore[arg-type]

    def test_compiled_plan_is_frozen(self) -> None:
        plan = compile_execution_plan(VALID_REQUEST)

        with self.assertRaises(FrozenInstanceError):
            plan.head_sha = "e" * 40  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
