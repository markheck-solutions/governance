from __future__ import annotations

import base64
import copy
import json
import sys
import tempfile
import unittest
from hashlib import sha256
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
            self.assertEqual(evidence["stdout"]["total_bytes"], len(stdout))
            self.assertEqual(
                evidence["stdout"]["full_sha256"], sha256(stdout).hexdigest()
            )
            self.assertFalse(evidence["stdout"]["truncated"])
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
                validate_subprocess_evidence_integrity(evidence)

    def test_spawn_failure_replaces_preexisting_file_with_blocking_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "evidence.json"
            output_path.write_text('{"forged":true}\n', encoding="utf-8")
            command = [str(Path(tmp) / "missing-executable")]

            evidence, stdout = run_recorded_subprocess(
                command,
                output_path=output_path,
                timeout_seconds=5,
                **IDENTITY,
            )

            self.assertEqual(evidence["decision"], "BLOCK_TECHNICAL")
            self.assertEqual(evidence["termination"], "SPAWN_FAILED")
            self.assertIsNone(evidence["exit_code"])
            self.assertFalse(evidence["timed_out"])
            self.assertEqual(stdout, b"")
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")), evidence
            )
            validate_subprocess_evidence_integrity(evidence)

    def test_combined_output_is_streamed_hashed_bounded_and_fail_closed(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import sys; "
                "sys.stdout.buffer.write(b'o' * 12); "
                "sys.stderr.buffer.write(b'e' * 12)"
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            evidence, stdout = run_recorded_subprocess(
                command,
                output_path=Path(tmp) / "evidence.json",
                timeout_seconds=5,
                output_limit_bytes=16,
                **IDENTITY,
            )

        self.assertEqual(evidence["decision"], "BLOCK_TECHNICAL")
        self.assertEqual(stdout, b"o" * 12)
        self.assertEqual(evidence["stdout"]["total_bytes"], 12)
        self.assertEqual(evidence["stderr"]["total_bytes"], 12)
        self.assertEqual(evidence["stdout"]["captured_bytes"], 12)
        self.assertEqual(evidence["stderr"]["captured_bytes"], 4)
        self.assertEqual(
            evidence["stdout"]["full_sha256"], sha256(b"o" * 12).hexdigest()
        )
        self.assertEqual(
            evidence["stderr"]["full_sha256"], sha256(b"e" * 12).hexdigest()
        )
        self.assertEqual(
            base64.b64decode(evidence["stderr"]["captured_base64"]), b"e" * 4
        )
        self.assertFalse(evidence["stdout"]["truncated"])
        self.assertTrue(evidence["stderr"]["truncated"])
        self.assertIn(
            "subprocess output exceeded 16 byte capture limit", evidence["errors"]
        )
        validate_subprocess_evidence_integrity(evidence)

    def test_integrity_rejects_semantic_and_output_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence, _ = run_recorded_subprocess(
                [sys.executable, "-c", "print('caller')"],
                output_path=Path(tmp) / "evidence.json",
                timeout_seconds=5,
                **IDENTITY,
            )

        invalid_cases = []
        invalid = copy.deepcopy(evidence)
        invalid["command"] = []
        invalid_cases.append(invalid)
        invalid = copy.deepcopy(evidence)
        invalid["timed_out"] = True
        invalid_cases.append(invalid)
        invalid = copy.deepcopy(evidence)
        invalid["stdout"]["captured_base64"] = base64.b64encode(b"forged").decode()
        invalid_cases.append(invalid)
        invalid = copy.deepcopy(evidence)
        invalid["stdout"]["total_bytes"] = 0
        invalid_cases.append(invalid)
        invalid = copy.deepcopy(evidence)
        invalid["stdout"]["full_sha256"] = "0" * 64
        invalid_cases.append(invalid)

        for invalid in invalid_cases:
            with self.subTest(field=next(iter(invalid))):
                invalid["artifact_content_hash"] = sha256_json(
                    {**invalid, "artifact_content_hash": ""}
                )
                with self.assertRaises(ValueError):
                    validate_subprocess_evidence_integrity(invalid)


if __name__ == "__main__":
    unittest.main()
