from __future__ import annotations

import unittest
from contextlib import chdir
from copy import deepcopy
from dataclasses import FrozenInstanceError
from importlib.resources import files
from pathlib import Path
from re import escape
from tempfile import TemporaryDirectory
from typing import Any, Mapping
from unittest import mock

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
TARGET_TREE_SHA256 = "1" * 64
EXECUTION_ID = "2" * 64
MAX_PULL_REQUEST = 9_007_199_254_740_991


def compile_plan(
    request: Mapping[str, Any] = VALID_REQUEST,
    *,
    target_tree_sha256: str = TARGET_TREE_SHA256,
    execution_id: str = EXECUTION_ID,
):
    return compile_execution_plan(
        request,
        target_tree_sha256=target_tree_sha256,
        execution_id=execution_id,
    )


def assess_plan(
    payload: Any,
    expected_request: Mapping[str, Any] = VALID_REQUEST,
    *,
    target_tree_sha256: str = TARGET_TREE_SHA256,
    execution_id: str = EXECUTION_ID,
) -> dict[str, Any]:
    return assess_execution_plan(
        payload,
        expected_request,
        target_tree_sha256=target_tree_sha256,
        execution_id=execution_id,
    )


class ExecutionPlanCompilationTests(unittest.TestCase):
    def test_packaged_execution_plan_schema_matches_source(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        source_schema = (
            repository_root / "schemas" / "v1" / "execution_plan.schema.json"
        ).read_bytes()
        packaged_schema = (
            files("governance_eval")
            .joinpath("schema_data/v1/execution_plan.schema.json")
            .read_bytes()
        )

        self.assertEqual(packaged_schema, source_schema)

    def test_schema_digest_is_eol_stable_and_rejects_semantic_tampering(
        self,
    ) -> None:
        import governance_eval.execution_plan as execution_plan

        payload = compile_plan().to_json()
        repository_root = Path(__file__).resolve().parents[1]
        source_schema = (
            repository_root / "schemas" / "v1" / "execution_plan.schema.json"
        ).read_bytes()
        canonical_schema = source_schema.replace(b"\r\n", b"\n")

        with TemporaryDirectory() as temporary_directory:
            resource_root = Path(temporary_directory)
            resource_path = resource_root.joinpath(
                "schema_data", "v1", "execution_plan.schema.json"
            )
            resource_path.parent.mkdir(parents=True)

            resource_path.write_bytes(canonical_schema.replace(b"\n", b"\r\n"))
            with mock.patch.object(execution_plan, "files", return_value=resource_root):
                crlf_result = assess_plan(payload)

            tampered_schema = canonical_schema.replace(
                b'"minimum": 1', b'"minimum": 2', 1
            )
            self.assertNotEqual(tampered_schema, canonical_schema)
            resource_path.write_bytes(tampered_schema)
            with mock.patch.object(execution_plan, "files", return_value=resource_root):
                tampered_result = assess_plan(payload)

        self.assertEqual(crlf_result["capability_status"], "PASS")
        self.assertEqual(tampered_result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            tampered_result["errors"],
            ["execution plan schema invalid: trusted schema digest is invalid"],
        )

    def test_requires_target_tree_digest(self) -> None:
        with self.assertRaises(TypeError):
            compile_execution_plan(VALID_REQUEST, execution_id=EXECUTION_ID)

    def test_requires_execution_identity(self) -> None:
        with self.assertRaises(TypeError):
            compile_execution_plan(
                VALID_REQUEST,
                target_tree_sha256=TARGET_TREE_SHA256,
            )

    def test_compiles_deterministic_schema_valid_lint_plan(self) -> None:
        first = compile_plan()
        second = compile_plan(dict(reversed(VALID_REQUEST.items())))

        payload = first.to_json()
        validate_named("execution_plan", payload)
        self.assertEqual(payload["target_tree_sha256"], TARGET_TREE_SHA256)
        self.assertEqual(payload["execution_id"], EXECUTION_ID)
        self.assertEqual(
            payload["steps"],
            [
                {
                    "step_id": "lint",
                    "capability": "lint",
                    "adapter_id": "python.ruff-check.v1",
                    "runtime_id": "evaluator.python-isolated.v1",
                    "module": "ruff",
                    "arguments": [
                        "check",
                        "--isolated",
                        "--no-cache",
                        "--no-respect-gitignore",
                        "--exclude=",
                        ".",
                    ],
                    "working_directory": ".",
                    "timeout_seconds": 120,
                    "output_limit_bytes": 65536,
                }
            ],
        )
        self.assertEqual(
            serialize_execution_plan(first), serialize_execution_plan(second)
        )

        assessment = assess_plan(payload)
        self.assertEqual(assessment["capability_status"], "PASS")
        self.assertEqual(assessment["errors"], [])

    def test_lint_plan_requires_isolated_evaluator_runtime(self) -> None:
        step = compile_plan().steps[0]

        self.assertEqual(step.runtime_id, "evaluator.python-isolated.v1")
        self.assertEqual(step.module, "ruff")
        self.assertEqual(
            step.arguments,
            (
                "check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                "--exclude=",
                ".",
            ),
        )

    def test_rejects_unsupported_adapter(self) -> None:
        request = {**VALID_REQUEST, "adapter_id": "python.unknown.v1"}

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "unsupported capability adapter: lint/python.unknown.v1",
        ):
            compile_plan(request)

    def test_v1_rejects_v2_only_adapter(self) -> None:
        request = {
            **VALID_REQUEST,
            "capability": "format_check",
            "adapter_id": "python.ruff-format-check.v1",
        }

        with self.assertRaisesRegex(
            ExecutionPlanError,
            "unsupported capability adapter: format_check/python.ruff-format-check.v1",
        ):
            compile_plan(request)

    def test_rejects_candidate_supplied_execution_fields(self) -> None:
        hostile_fields = {
            "command": "ruff check . || true",
            "shell": True,
            "argv": ["python", "-c", "pass"],
            "args": ["--exit-zero"],
            "executable": "python",
            "runtime_id": "candidate.python.v1",
            "module": "candidate_ruff",
            "arguments": ["--exit-zero"],
            "target_tree_sha256": "0" * 64,
            "execution_id": "0" * 64,
        }

        for field, value in hostile_fields.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ExecutionPlanError,
                    f"unexpected execution plan request field: {field}",
                ):
                    compile_plan({**VALID_REQUEST, field: value})

    def test_blocks_plan_mutation_even_when_attacker_rehashes_it(self) -> None:
        payload = deepcopy(compile_plan().to_json())
        payload["steps"][0]["arguments"] = [
            "check",
            "--exit-zero",
        ]
        unsigned = {key: value for key, value in payload.items() if key != "plan_id"}
        payload["plan_id"] = sha256_json(unsigned)

        result = assess_plan(payload)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"], ["execution plan differs from evaluator-owned plan"]
        )

    def test_blocks_plan_replay_against_new_request_identity(self) -> None:
        payload = compile_plan().to_json()
        replacements = {
            "head_sha": "e" * 40,
            "config_sha256": "f" * 64,
        }

        for field, value in replacements.items():
            with self.subTest(field=field):
                result = assess_plan(payload, {**VALID_REQUEST, field: value})

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(
                    result["errors"],
                    [f"execution plan identity mismatch: {field}"],
                )

    def test_assessment_blocks_oversized_expected_pull_request_without_exception(
        self,
    ) -> None:
        payload = compile_plan().to_json()

        result = assess_plan(
            payload,
            {**VALID_REQUEST, "pull_request": 10**5000},
        )

        self.assertEqual(
            result,
            {
                "schema_version": "1.0",
                "capability_status": "BLOCK_TECHNICAL",
                "plan_id": payload["plan_id"],
                "errors": [
                    "execution plan request invalid: execution plan request "
                    "pull_request must not exceed 9007199254740991"
                ],
            },
        )

    def test_blocks_oversized_hostile_payload_before_hashing(self) -> None:
        payload = compile_plan().to_json()
        payload["pull_request"] = 10**5000

        result = assess_plan(payload)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            [
                "execution plan schema invalid: $.pull_request: value above "
                "9007199254740991"
            ],
        )

    def test_normalizes_execution_plan_hash_failures(self) -> None:
        import governance_eval.execution_plan as execution_plan

        for exception in (
            ValueError("value failure"),
            OverflowError("overflow failure"),
            TypeError("type failure"),
        ):
            with self.subTest(exception=type(exception).__name__):
                with (
                    mock.patch.object(
                        execution_plan,
                        "sha256_json",
                        side_effect=exception,
                    ),
                    self.assertRaisesRegex(
                        ExecutionPlanError,
                        "execution plan content cannot be hashed",
                    ),
                ):
                    compile_plan()

    def test_accepts_maximum_internal_pull_request(self) -> None:
        request = {**VALID_REQUEST, "pull_request": MAX_PULL_REQUEST}

        plan = compile_plan(request)
        payload = plan.to_json()

        validate_named("execution_plan", payload)
        self.assertEqual(payload["pull_request"], MAX_PULL_REQUEST)
        self.assertEqual(assess_plan(payload, request)["capability_status"], "PASS")

    def test_blocks_plan_replay_against_new_protected_binding(self) -> None:
        payload = compile_plan().to_json()
        replacements = {
            "target_tree_sha256": "e" * 64,
            "execution_id": "f" * 64,
        }

        for field, value in replacements.items():
            with self.subTest(field=field):
                kwargs = {field: value}
                result = assess_plan(payload, **kwargs)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(
                    result["errors"],
                    [f"execution plan identity mismatch: {field}"],
                )

    def test_blocks_rehashed_target_tree_substitution(self) -> None:
        payload = deepcopy(compile_plan().to_json())
        payload["target_tree_sha256"] = "e" * 64
        unsigned = {key: value for key, value in payload.items() if key != "plan_id"}
        payload["plan_id"] = sha256_json(unsigned)

        result = assess_plan(payload)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution plan identity mismatch: target_tree_sha256"],
        )

    def test_uses_evaluator_owned_schema_outside_candidate_control(self) -> None:
        payload = compile_plan().to_json()

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
                result = assess_plan(payload)

        self.assertEqual(result["capability_status"], "PASS")
        self.assertEqual(result["errors"], [])

    def test_uses_packaged_schema_without_repository_source_tree(self) -> None:
        import governance_eval.execution_plan as execution_plan

        payload = compile_plan().to_json()

        with (
            TemporaryDirectory() as directory,
            mock.patch.object(
                execution_plan,
                "_EVALUATOR_ROOT",
                Path(directory),
                create=True,
            ),
        ):
            result = assess_plan(payload)

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
                    compile_plan(request)

    def test_rejects_malformed_protected_bindings(self) -> None:
        cases = (
            (
                {"target_tree_sha256": "0" * 63},
                "execution plan target_tree_sha256 must be a lowercase SHA-256",
            ),
            (
                {"execution_id": "0" * 63},
                "execution plan execution_id must be a lowercase SHA-256",
            ),
        )

        for kwargs, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ExecutionPlanError, escape(message)):
                    compile_plan(**kwargs)

    def test_rejects_non_object_request(self) -> None:
        with self.assertRaisesRegex(
            ExecutionPlanError,
            "execution plan request must be an object",
        ):
            compile_execution_plan(
                [],  # type: ignore[arg-type]
                target_tree_sha256=TARGET_TREE_SHA256,
                execution_id=EXECUTION_ID,
            )

    def test_compiled_plan_is_frozen(self) -> None:
        plan = compile_plan()

        with self.assertRaises(FrozenInstanceError):
            plan.head_sha = "e" * 40  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
