from __future__ import annotations

import base64
import unittest
from contextlib import chdir
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from governance_eval.execution_plan import ExecutionPlan, compile_execution_plan
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named

VALID_REQUEST = {
    "schema_version": "1.0",
    "repository": "markheck-solutions/governance",
    "pull_request": 45,
    "base_sha": "a" * 40,
    "head_sha": "b" * 40,
    "evaluator_sha": "c" * 40,
    "config_sha256": "d" * 64,
    "capability": "lint",
    "adapter_id": "python.ruff-check.v1",
}
TARGET_TREE_SHA256 = "1" * 64
EXECUTION_ID = "2" * 64

EMPTY_SHA256 = sha256(b"").hexdigest()


def seal_result_payload(payload: dict[str, object]) -> None:
    payload["artifact_id"] = sha256_json(
        {
            key: value
            for key, value in payload.items()
            if key not in {"artifact_id", "artifact_content_hash"}
        }
    )
    payload["artifact_content_hash"] = sha256_json(
        {**payload, "artifact_content_hash": ""}
    )


def set_captured_output(
    payload: dict[str, object], stream: str, content: bytes, *, truncated: bool = False
) -> None:
    output = payload[stream]
    assert isinstance(output, dict)
    output.update(
        {
            "sha256": sha256(content).hexdigest(),
            "captured_bytes": len(content),
            "captured_base64": base64.b64encode(content).decode("ascii"),
            "truncated": truncated,
        }
    )


def valid_result_payload() -> tuple[ExecutionPlan, dict[str, object]]:
    plan = compile_execution_plan(
        VALID_REQUEST,
        target_tree_sha256=TARGET_TREE_SHA256,
        execution_id=EXECUTION_ID,
    )
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "artifact_id": "",
        "artifact_content_hash": "",
        "plan_id": plan.plan_id,
        "step_id": plan.steps[0].step_id,
        "attempt": 1,
        "started_at": "2026-07-15T15:00:00Z",
        "completed_at": "2026-07-15T15:00:01Z",
        "duration_seconds": 1.0,
        "timeout_seconds": plan.steps[0].timeout_seconds,
        "termination": "EXITED",
        "exit_code": 0,
        "output_limit_bytes": plan.steps[0].output_limit_bytes,
        "stdout": {
            "sha256": EMPTY_SHA256,
            "captured_bytes": 0,
            "captured_base64": "",
            "truncated": False,
        },
        "stderr": {
            "sha256": EMPTY_SHA256,
            "captured_bytes": 0,
            "captured_base64": "",
            "truncated": False,
        },
    }
    seal_result_payload(payload)
    return plan, payload


class ExecutionResultAssessmentTests(unittest.TestCase):
    def test_packaged_execution_result_schema_matches_source(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        source_schema = (
            repository_root / "schemas" / "v1" / "execution_result.schema.json"
        ).read_bytes()
        packaged_schema = (
            files("governance_eval")
            .joinpath("schema_data/v1/execution_result.schema.json")
            .read_bytes()
        )

        self.assertEqual(packaged_schema, source_schema)

    def test_schema_digest_is_eol_stable_and_rejects_semantic_tampering(
        self,
    ) -> None:
        import governance_eval.execution_result as execution_result

        plan, payload = valid_result_payload()
        repository_root = Path(__file__).resolve().parents[1]
        source_schema = (
            repository_root / "schemas" / "v1" / "execution_result.schema.json"
        ).read_bytes()
        canonical_schema = source_schema.replace(b"\r\n", b"\n")

        with TemporaryDirectory() as temporary_directory:
            resource_root = Path(temporary_directory)
            resource_path = resource_root.joinpath(
                "schema_data", "v1", "execution_result.schema.json"
            )
            resource_path.parent.mkdir(parents=True)

            resource_path.write_bytes(canonical_schema.replace(b"\n", b"\r\n"))
            with mock.patch.object(
                execution_result, "files", return_value=resource_root
            ):
                crlf_result = execution_result.validate_execution_result_integrity(
                    payload, plan
                )

            tampered_schema = canonical_schema.replace(
                b'"minimum": 1', b'"minimum": 2', 1
            )
            self.assertNotEqual(tampered_schema, canonical_schema)
            resource_path.write_bytes(tampered_schema)
            with mock.patch.object(
                execution_result, "files", return_value=resource_root
            ):
                tampered_result = execution_result.validate_execution_result_integrity(
                    payload, plan
                )

        self.assertEqual(crlf_result["integrity_status"], "INTEGRITY_VALID")
        self.assertEqual(tampered_result["integrity_status"], "INTEGRITY_INVALID")
        self.assertEqual(
            tampered_result["errors"],
            ["execution result schema invalid: trusted schema digest is invalid"],
        )

    def test_self_hashed_zero_exit_result_cannot_authorize_pass(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        plan, payload = valid_result_payload()

        self.assertEqual(
            assess_execution_result(payload, plan),
            {
                "schema_version": "1.0",
                "capability_status": "BLOCK_TECHNICAL",
                "artifact_id": payload["artifact_id"],
                "errors": ["execution result provenance is unverified"],
            },
        )

    def test_classifies_exact_self_hashed_zero_exit_result_as_integrity_valid(
        self,
    ) -> None:
        from governance_eval.execution_result import (
            validate_execution_result_integrity,
        )

        plan, payload = valid_result_payload()

        self.assertEqual(
            validate_execution_result_integrity(payload, plan),
            {
                "schema_version": "1.0",
                "integrity_status": "INTEGRITY_VALID",
                "artifact_id": payload["artifact_id"],
                "errors": [],
            },
        )

    def test_uses_packaged_schema_outside_repository_working_directory(self) -> None:
        from governance_eval.execution_result import (
            validate_execution_result_integrity,
        )

        plan, payload = valid_result_payload()

        with TemporaryDirectory() as temporary_directory, chdir(temporary_directory):
            result = validate_execution_result_integrity(payload, plan)

        self.assertEqual(result["integrity_status"], "INTEGRITY_VALID")

    def test_positive_nonzero_exit_is_integrity_valid_but_unauthorized(self) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        for exit_code in (1, 2, 2**31):
            with self.subTest(exit_code=exit_code):
                plan, payload = valid_result_payload()
                payload["exit_code"] = exit_code
                seal_result_payload(payload)

                self.assertEqual(
                    validate_execution_result_integrity(payload, plan)[
                        "integrity_status"
                    ],
                    "INTEGRITY_VALID",
                )
                self.assertEqual(
                    assess_execution_result(payload, plan),
                    {
                        "schema_version": "1.0",
                        "capability_status": "BLOCK_TECHNICAL",
                        "artifact_id": payload["artifact_id"],
                        "errors": ["execution result provenance is unverified"],
                    },
                )

    def test_negative_nonzero_exit_is_integrity_valid_but_unauthorized(self) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        for exit_code in (-1, -2, -(2**31)):
            with self.subTest(exit_code=exit_code):
                plan, payload = valid_result_payload()
                payload["exit_code"] = exit_code
                seal_result_payload(payload)

                self.assertEqual(
                    validate_execution_result_integrity(payload, plan)[
                        "integrity_status"
                    ],
                    "INTEGRITY_VALID",
                )
                self.assertEqual(
                    assess_execution_result(payload, plan),
                    {
                        "schema_version": "1.0",
                        "capability_status": "BLOCK_TECHNICAL",
                        "artifact_id": payload["artifact_id"],
                        "errors": ["execution result provenance is unverified"],
                    },
                )

    def test_schema_valid_huge_integer_never_raises_and_is_deterministic(
        self,
    ) -> None:
        from governance_eval.execution_result import assess_execution_result

        for field in ("attempt", "exit_code"):
            with self.subTest(field=field):
                plan, payload = valid_result_payload()
                payload[field] = 10**5000
                before = deepcopy(payload)

                validate_named("execution_result", payload)
                first = assess_execution_result(payload, plan)
                second = assess_execution_result(deepcopy(payload), plan)

                self.assertEqual(
                    first,
                    {
                        "schema_version": "1.0",
                        "capability_status": "BLOCK_TECHNICAL",
                        "artifact_id": payload["artifact_id"],
                        "errors": ["execution result content hash cannot be verified"],
                    },
                )
                self.assertEqual(second, first)
                self.assertEqual(payload, before)

    def test_blocks_result_replay_against_another_head_or_execution(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        _, payload = valid_result_payload()
        replayed_plans = {
            "head_sha": compile_execution_plan(
                {**VALID_REQUEST, "head_sha": "9" * 40},
                target_tree_sha256=TARGET_TREE_SHA256,
                execution_id=EXECUTION_ID,
            ),
            "execution_id": compile_execution_plan(
                VALID_REQUEST,
                target_tree_sha256=TARGET_TREE_SHA256,
                execution_id="8" * 64,
            ),
        }

        for field, replayed_plan in replayed_plans.items():
            with self.subTest(field=field):
                self.assertEqual(
                    assess_execution_result(payload, replayed_plan),
                    {
                        "schema_version": "1.0",
                        "capability_status": "BLOCK_TECHNICAL",
                        "artifact_id": payload["artifact_id"],
                        "errors": ["execution result plan id mismatch"],
                    },
                )

    def test_blocks_forged_expected_plan_even_when_result_matches(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        plan, payload = valid_result_payload()
        forged_plan = replace(plan, plan_id="0" * 64)
        payload["plan_id"] = forged_plan.plan_id
        seal_result_payload(payload)

        self.assertEqual(
            assess_execution_result(payload, forged_plan),
            {
                "schema_version": "1.0",
                "capability_status": "BLOCK_TECHNICAL",
                "artifact_id": payload["artifact_id"],
                "errors": ["expected execution plan id is invalid"],
            },
        )

    def test_blocks_expected_plan_with_rehashed_candidate_arguments(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        plan, payload = valid_result_payload()
        forged_step = replace(plan.steps[0], arguments=("check", "--exit-zero"))
        forged_plan = replace(plan, plan_id="", steps=(forged_step,))
        unsigned = forged_plan.to_json()
        unsigned.pop("plan_id")
        forged_plan = replace(forged_plan, plan_id=sha256_json(unsigned))
        payload["plan_id"] = forged_plan.plan_id
        seal_result_payload(payload)

        self.assertEqual(
            assess_execution_result(payload, forged_plan),
            {
                "schema_version": "1.0",
                "capability_status": "BLOCK_TECHNICAL",
                "artifact_id": payload["artifact_id"],
                "errors": ["expected execution plan differs from evaluator-owned plan"],
            },
        )

    def test_blocks_result_that_changes_plan_bounded_controls(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        cases = {
            "step_id": ("format", "execution result step id mismatch"),
            "timeout_seconds": (119, "execution result timeout mismatch"),
            "output_limit_bytes": (65535, "execution result output limit mismatch"),
        }

        for field, (value, expected_error) in cases.items():
            with self.subTest(field=field):
                plan, payload = valid_result_payload()
                payload[field] = value
                seal_result_payload(payload)

                result = assess_execution_result(payload, plan)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["errors"], [expected_error])

    def test_fails_closed_for_missing_malformed_or_forged_result(self) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        plan, missing_field = valid_result_payload()
        del missing_field["exit_code"]

        _, forged_content_hash = valid_result_payload()
        forged_content_hash["artifact_content_hash"] = "0" * 64

        _, forged_artifact_id = valid_result_payload()
        forged_artifact_id["artifact_id"] = "0" * 64
        forged_artifact_id["artifact_content_hash"] = sha256_json(
            {**forged_artifact_id, "artifact_content_hash": ""}
        )

        cases: list[tuple[object, str]] = [
            (
                None,
                "execution result must be an object",
            ),
            (
                missing_field,
                "execution result schema invalid: $: missing required key 'exit_code'",
            ),
            (
                forged_content_hash,
                "execution result content hash is invalid",
            ),
            (
                forged_artifact_id,
                "execution result artifact id is invalid",
            ),
        ]
        for invalid_exit_code, type_name in (
            (False, "bool"),
            (0.0, "float"),
            ("0", "str"),
        ):
            _, wrong_type = valid_result_payload()
            wrong_type["exit_code"] = invalid_exit_code
            seal_result_payload(wrong_type)
            cases.append(
                (
                    wrong_type,
                    "execution result schema invalid: $.exit_code: expected "
                    f"['integer', 'null'], got {type_name}",
                )
            )

        for payload, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                result = assess_execution_result(payload, plan)
                integrity = validate_execution_result_integrity(payload, plan)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["errors"], [expected_error])
                self.assertEqual(integrity["integrity_status"], "INTEGRITY_INVALID")
                self.assertEqual(integrity["errors"], [expected_error])

    def test_blocks_inconsistent_execution_state(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        plan, payload = valid_result_payload()
        payload["exit_code"] = None
        seal_result_payload(payload)

        result = assess_execution_result(payload, plan)

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution result termination and exit code are inconsistent"],
        )

    def test_nonexit_result_with_consistent_timing_is_valid_but_unauthorized(
        self,
    ) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        for termination in ("TIMED_OUT", "SPAWN_FAILED"):
            with self.subTest(termination=termination):
                plan, payload = valid_result_payload()
                payload["termination"] = termination
                payload["exit_code"] = None
                if termination == "TIMED_OUT":
                    payload["completed_at"] = "2026-07-15T15:02:00Z"
                    payload["duration_seconds"] = 120.0
                seal_result_payload(payload)

                self.assertEqual(
                    validate_execution_result_integrity(payload, plan)[
                        "integrity_status"
                    ],
                    "INTEGRITY_VALID",
                )
                self.assertEqual(
                    assess_execution_result(payload, plan)["errors"],
                    ["execution result provenance is unverified"],
                )

    def test_blocks_timeout_claimed_before_configured_deadline(self) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        plan, payload = valid_result_payload()
        payload["termination"] = "TIMED_OUT"
        payload["exit_code"] = None
        seal_result_payload(payload)

        integrity = validate_execution_result_integrity(payload, plan)
        result = assess_execution_result(payload, plan)

        self.assertEqual(integrity["integrity_status"], "INTEGRITY_INVALID")
        self.assertEqual(
            integrity["errors"],
            ["execution result timeout occurred before configured deadline"],
        )
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution result timeout occurred before configured deadline"],
        )

    def test_accepts_timeout_with_cleanup_overhead_but_does_not_authorize(
        self,
    ) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        plan, payload = valid_result_payload()
        payload.update(
            {
                "completed_at": "2026-07-15T15:02:00.050Z",
                "duration_seconds": 120.05,
                "termination": "TIMED_OUT",
                "exit_code": None,
            }
        )
        seal_result_payload(payload)

        integrity = validate_execution_result_integrity(payload, plan)
        result = assess_execution_result(payload, plan)

        self.assertEqual(integrity["integrity_status"], "INTEGRITY_VALID")
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution result provenance is unverified"],
        )

    def test_blocks_timeout_cleanup_beyond_bounded_grace(self) -> None:
        from governance_eval.execution_result import (
            assess_execution_result,
            validate_execution_result_integrity,
        )

        plan, payload = valid_result_payload()
        payload.update(
            {
                "completed_at": "2026-07-15T15:02:01.002Z",
                "duration_seconds": 121.002,
                "termination": "TIMED_OUT",
                "exit_code": None,
            }
        )
        seal_result_payload(payload)

        integrity = validate_execution_result_integrity(payload, plan)
        result = assess_execution_result(payload, plan)

        self.assertEqual(integrity["integrity_status"], "INTEGRITY_INVALID")
        self.assertEqual(
            integrity["errors"],
            ["execution result timeout cleanup exceeded bounded grace"],
        )
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution result timeout cleanup exceeded bounded grace"],
        )

    def test_blocks_invalid_or_unbounded_captured_output(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        cases: list[tuple[str, dict[str, object], str]] = []

        plan, invalid_base64 = valid_result_payload()
        stdout = invalid_base64["stdout"]
        assert isinstance(stdout, dict)
        stdout["captured_base64"] = "!!!"
        seal_result_payload(invalid_base64)
        cases.append(
            (
                "invalid_base64",
                invalid_base64,
                "stdout captured output encoding is invalid",
            )
        )

        _, wrong_count = valid_result_payload()
        set_captured_output(wrong_count, "stdout", b"abc")
        wrong_count_stdout = wrong_count["stdout"]
        assert isinstance(wrong_count_stdout, dict)
        wrong_count_stdout["captured_bytes"] = 2
        seal_result_payload(wrong_count)
        cases.append(
            ("wrong_count", wrong_count, "stdout captured output byte count is invalid")
        )

        _, wrong_digest = valid_result_payload()
        set_captured_output(wrong_digest, "stdout", b"abc")
        wrong_digest_stdout = wrong_digest["stdout"]
        assert isinstance(wrong_digest_stdout, dict)
        wrong_digest_stdout["sha256"] = "0" * 64
        seal_result_payload(wrong_digest)
        cases.append(
            ("wrong_digest", wrong_digest, "stdout captured output digest is invalid")
        )

        _, combined_limit = valid_result_payload()
        set_captured_output(combined_limit, "stdout", b"a" * 40000, truncated=True)
        set_captured_output(combined_limit, "stderr", b"b" * 30000)
        seal_result_payload(combined_limit)
        cases.append(
            ("combined_limit", combined_limit, "captured output exceeds combined limit")
        )

        _, inconsistent_truncation = valid_result_payload()
        set_captured_output(inconsistent_truncation, "stdout", b"a", truncated=True)
        seal_result_payload(inconsistent_truncation)
        cases.append(
            ("truncation", inconsistent_truncation, "stdout truncation is inconsistent")
        )

        for name, payload, expected_error in cases:
            with self.subTest(name=name):
                result = assess_execution_result(payload, plan)
                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["errors"], [expected_error])

    def test_blocks_invalid_or_unbounded_timing(self) -> None:
        from governance_eval.execution_result import assess_execution_result

        cases = (
            (
                {
                    "started_at": "2026-07-15T15:00:01Z",
                    "completed_at": "2026-07-15T15:00:00Z",
                },
                "execution result timestamps are out of order",
            ),
            (
                {"duration_seconds": 2.0},
                "execution result duration does not match timestamps",
            ),
            (
                {
                    "completed_at": "2026-07-15T15:02:01Z",
                    "duration_seconds": 121.0,
                },
                "execution result duration exceeds timeout",
            ),
            (
                {"duration_seconds": float("inf")},
                "execution result duration must be finite",
            ),
        )

        for replacements, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                plan, payload = valid_result_payload()
                payload.update(replacements)
                seal_result_payload(payload)

                result = assess_execution_result(payload, plan)

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["errors"], [expected_error])


if __name__ == "__main__":
    unittest.main()
