from __future__ import annotations

import unittest
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named


_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED = {
    "execution_plan": "4854719c664820b55020d4e3c46b68b8f63b1115761adc5e00df9ff87212963b",
    "execution_result": "c3dcbe029e3f7094b8eb8966c487b649bbe08ec945d5f7b396900d2ce0dbee7f",
}


class HistoricalExecutionSchemaTests(unittest.TestCase):
    def test_v1_schemas_are_byte_identical_pinned_and_validation_only(self) -> None:
        for name, expected in _EXPECTED.items():
            with self.subTest(name=name):
                source = _ROOT / "schemas/v1" / f"{name}.schema.json"
                packaged = (
                    _ROOT / "governance_eval/schema_data/v1" / f"{name}.schema.json"
                )
                self.assertEqual(source.read_bytes(), packaged.read_bytes())
                self.assertEqual(sha256(source.read_bytes()).hexdigest(), expected)
                self.assertFalse((_ROOT / "governance_eval" / f"{name}.py").exists())

    def test_frozen_valid_v1_artifacts_still_validate(self) -> None:
        validate_packaged_named("execution_plan", _plan())
        validate_packaged_named("execution_result", _result())

    def test_malformed_or_extended_v1_artifacts_are_rejected(self) -> None:
        for name, payload in (
            ("execution_plan", _plan()),
            ("execution_result", _result()),
        ):
            with self.subTest(name=name):
                hostile = deepcopy(payload)
                hostile["unexpected"] = True
                with self.assertRaises(SchemaValidationError):
                    validate_packaged_named(name, hostile)


def _plan() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "plan_id": "a" * 64,
        "repository": "example/target",
        "pull_request": 1,
        "base_sha": "b" * 40,
        "head_sha": "c" * 40,
        "target_tree_sha256": "d" * 64,
        "execution_id": "e" * 64,
        "evaluator_sha": "f" * 40,
        "config_sha256": "0" * 64,
        "steps": [
            {
                "step_id": "lint",
                "capability": "lint",
                "adapter_id": "python.ruff-check.v1",
                "runtime_id": "evaluator.python-isolated.v1",
                "module": "ruff",
                "arguments": ["check", "."],
                "working_directory": ".",
                "timeout_seconds": 120,
                "output_limit_bytes": 65536,
            }
        ],
    }


def _result() -> dict[str, object]:
    stream = {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "captured_bytes": 0,
        "captured_base64": "",
        "truncated": False,
    }
    return {
        "schema_version": "1.0",
        "artifact_id": "a" * 64,
        "artifact_content_hash": "b" * 64,
        "plan_id": "c" * 64,
        "step_id": "lint",
        "attempt": 1,
        "started_at": "2026-07-19T17:00:00Z",
        "completed_at": "2026-07-19T17:00:01Z",
        "duration_seconds": 1,
        "timeout_seconds": 120,
        "termination": "EXITED",
        "exit_code": 0,
        "output_limit_bytes": 65536,
        "stdout": stream,
        "stderr": stream,
    }


if __name__ == "__main__":
    unittest.main()
