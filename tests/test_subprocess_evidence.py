from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named
from governance_eval.subprocess_evidence import (
    run_recorded_subprocess,
    validate_subprocess_evidence_integrity,
)


IDENTITY = {
    "repository": "markheck-solutions/governance",
    "pull_request": 64,
    "base_sha": "a" * 40,
    "head_sha": "b" * 40,
    "evaluator_sha": "c" * 40,
    "caller_workflow_sha": "a" * 40,
}


class SubprocessEvidenceTests(unittest.TestCase):
    def test_success_is_schema_valid_hash_bound_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "evidence.json"
            command = [sys.executable, "-c", "print('caller')"]

            evidence, stdout = run_recorded_subprocess(
                command,
                output_path=output_path,
                timeout_seconds=5,
                **IDENTITY,
            )

            self.assertEqual(evidence["decision"], "PASS")
            self.assertEqual(evidence["termination"], "EXITED")
            self.assertEqual(evidence["exit_code"], 0)
            self.assertFalse(evidence["timed_out"])
            self.assertEqual(evidence["command"], command)
            self.assertEqual(stdout.rstrip(b"\r\n"), b"caller")
            self.assertEqual(
                evidence["artifact_content_hash"],
                sha256_json({**evidence, "artifact_content_hash": ""}),
            )
            persisted = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, evidence)
            validate_named("subprocess_evidence", persisted)

    def test_nonzero_and_timeout_are_retained_as_blocking_evidence(self) -> None:
        cases = (
            (
                [sys.executable, "-c", "raise SystemExit(7)"],
                5,
                "EXITED",
                7,
                False,
            ),
            (
                [sys.executable, "-c", "import time; time.sleep(2)"],
                1,
                "TIMED_OUT",
                None,
                True,
            ),
        )
        for command, timeout, termination, exit_code, timed_out in cases:
            with (
                self.subTest(termination=termination),
                tempfile.TemporaryDirectory() as tmp,
            ):
                output_path = Path(tmp) / "evidence.json"
                evidence, _ = run_recorded_subprocess(
                    command,
                    output_path=output_path,
                    timeout_seconds=timeout,
                    **IDENTITY,
                )

                self.assertEqual(evidence["decision"], "BLOCK_TECHNICAL")
                self.assertEqual(evidence["termination"], termination)
                self.assertEqual(evidence["exit_code"], exit_code)
                self.assertEqual(evidence["timed_out"], timed_out)
                self.assertTrue(evidence["errors"])
                self.assertTrue(output_path.is_file())
                validate_named("subprocess_evidence", evidence)

    def test_integrity_rejects_command_or_timeout_state_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence, _ = run_recorded_subprocess(
                [sys.executable, "-c", "print('caller')"],
                output_path=Path(tmp) / "evidence.json",
                timeout_seconds=5,
                **IDENTITY,
            )

        invalid = dict(evidence)
        invalid["command"] = []
        with self.assertRaises(ValueError):
            validate_subprocess_evidence_integrity(invalid)

        invalid = dict(evidence)
        invalid["timed_out"] = True
        with self.assertRaises(ValueError):
            validate_subprocess_evidence_integrity(invalid)


if __name__ == "__main__":
    unittest.main()
