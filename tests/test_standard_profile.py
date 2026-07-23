from __future__ import annotations

import base64
import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from governance_eval.capability_catalog import STANDARD_PROFILE_ADAPTERS
from governance_eval.docker_runtime import _profile_payload
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.standard_profile import (
    PROFILE_MARKER,
    _fixed_commands,
    _import_cycle_errors,
    _integrity_result,
    _source_snapshot,
)
from governance_eval.unittest_runner import _accepted
from test_execution_plan_v2 import _receipt


def _stream(content: bytes) -> dict[str, object]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": False,
    }


class StandardProfileTests(unittest.TestCase):
    def test_unittest_rejects_zero_and_skipped_only(self) -> None:
        self.assertFalse(
            _accepted(
                {
                    "tests_run": 0,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "successful": True,
                }
            )
        )
        self.assertFalse(
            _accepted(
                {
                    "tests_run": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 2,
                    "successful": True,
                }
            )
        )
        self.assertTrue(
            _accepted(
                {
                    "tests_run": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 1,
                    "successful": True,
                }
            )
        )

    def test_commands_are_fixed_and_offline(self) -> None:
        commands = _fixed_commands(
            Path("/workspace"),
            Path("/workspace/.governance-output/build-source"),
            ["src/example.py", "tests/test_example.py"],
            Path("/workspace/.governance-output"),
        )
        by_capability = {item[0]: item[3] for item in commands}
        self.assertIn("lint.mccabe.max-complexity=10", by_capability["complexity"])
        self.assertIn("--strict", by_capability["typecheck"])
        self.assertIn("--no-incremental", by_capability["typecheck"])
        self.assertIn("--cache-dir=/dev/null", by_capability["typecheck"])
        for option in ("--no-deps", "--no-index", "--no-build-isolation"):
            self.assertIn(option, by_capability["build"])
        self.assertFalse(
            any("sh" == argument for command in commands for argument in command[3])
        )

    def test_architecture_cycle_and_source_mutation_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("import two\n", encoding="utf-8")
            (root / "two.py").write_text("import one\n", encoding="utf-8")
            self.assertEqual(
                _import_cycle_errors(root, ["one.py", "two.py"]),
                ["import cycle: one -> two"],
            )
            initial = _source_snapshot(root)
            (root / "created.py").write_text("value = 1\n", encoding="utf-8")
            result = _integrity_result(root, initial)
            self.assertEqual(result["status"], "BLOCK_TECHNICAL")
            self.assertEqual(result["evidence"]["changed_files"], ["created.py"])

    def test_profile_marker_requires_exact_typed_capabilities(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.standard-profile.v1",
        )
        capabilities = [
            {
                "capability": capability,
                "adapter_id": adapter_id,
                "assurance_class": assurance,
                "status": "PASS",
                "evidence": {},
            }
            for capability, adapter_id, assurance in STANDARD_PROFILE_ADAPTERS
        ]
        payload = {
            "schema_version": "1.0",
            "profile": "python.standard.v1",
            "status": "PASS",
            "capabilities": capabilities,
        }
        raw = (
            PROFILE_MARKER + json.dumps(payload, separators=(",", ":")) + "\n"
        ).encode()
        outcome = {"stdout": _stream(raw)}
        self.assertEqual(_profile_payload(plan, outcome), capabilities)

        capabilities[0] = {**capabilities[0], "assurance_class": "COOPERATIVE_DYNAMIC"}
        hostile = (
            PROFILE_MARKER + json.dumps(payload, separators=(",", ":")) + "\n"
        ).encode()
        self.assertIsNone(_profile_payload(plan, {"stdout": _stream(hostile)}))


if __name__ == "__main__":
    unittest.main()
