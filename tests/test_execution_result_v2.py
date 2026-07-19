from __future__ import annotations

import base64
import unittest
from copy import deepcopy
from hashlib import sha256

from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.hashing import sha256_json
from test_execution_plan_v2 import _receipt


def _stream(content: bytes = b"") -> dict[str, object]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": False,
    }


def _result() -> tuple[dict[str, object], object, object]:
    receipt = _receipt()
    plan = compile_execution_plan_v2(
        receipt, capability="lint", adapter_id="python.ruff-check.v1"
    )
    command = [
        plan.runtime["docker_path"],
        f"--host={plan.runtime['docker_host']}",
        "run",
        "--rm",
        "--name=governance-123",
        "--read-only",
        "--network=none",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=128",
        "--memory=536870912",
        "--cpus=1.0",
        "--env=HOME=/workspace/.home",
        "--env=TMPDIR=/workspace/.tmp",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--workdir=/workspace",
        "--mount",
        "type=bind,src=C:\\temp\\governance-target-1\\workspace,dst=/workspace",
        "--mount",
        "type=bind,src=C:\\temp\\sealed-toolchain,dst=/opt/governance-toolchain,readonly",
        plan.runtime["image"],
        *plan.step["argv"],
    ]
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": receipt.receipt_id,
        "capability_status": "PASS",
        "runtime": {
            "image": plan.runtime["image"],
            "policy_id": plan.runtime["policy_id"],
            "docker_path": plan.runtime["docker_path"],
            "docker_sha256": plan.runtime["docker_sha256"],
            "docker_host": plan.runtime["docker_host"],
            "toolchain": "ruff==0.15.21",
            "toolchain_sha256": plan.runtime["toolchain_sha256"],
        },
        "command": command,
        "started_at": "2026-07-19T12:00:00Z",
        "completed_at": "2026-07-19T12:00:01Z",
        "duration_seconds": 1.0,
        "timeout_seconds": 120,
        "termination": "EXITED",
        "exit_code": 0,
        "stdout": _stream(),
        "stderr": _stream(),
        "errors": [],
    }
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
    return payload, plan, receipt


class ExecutionResultV2Tests(unittest.TestCase):
    def test_accepts_exact_host_result(self) -> None:
        payload, plan, receipt = _result()

        assessment = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(assessment["integrity_status"], "INTEGRITY_VALID")

    def test_rejects_rehashed_command_runtime_and_output_mutation(self) -> None:
        for mutation in ("command", "image", "output"):
            with self.subTest(mutation=mutation):
                payload, plan, receipt = _result()
                hostile = deepcopy(payload)
                if mutation == "command":
                    hostile["command"][-1] = "--exit-zero"
                elif mutation == "image":
                    hostile["runtime"]["image"] = "python@sha256:" + "0" * 64
                else:
                    hostile["stdout"]["captured_base64"] = "WA=="
                hostile["artifact_id"] = sha256_json({**hostile, "artifact_id": ""})

                assessment = validate_execution_result_v2(hostile, plan, receipt)

                self.assertEqual(assessment["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_combined_over_limit_and_truncated_pass(self) -> None:
        payload, plan, receipt = _result()
        payload["stdout"] = _stream(b"a" * 40000)
        payload["stderr"] = _stream(b"b" * 40000)
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )

    def test_rejects_short_command_and_invalid_timing(self) -> None:
        mutations = (
            ("short command", {"command": ["docker"]}),
            ("reversed time", {"completed_at": "2026-07-19T11:59:59Z"}),
            ("bad duration", {"duration_seconds": 9.0}),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                payload, plan, receipt = _result()
                payload.update(mutation)
                payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

                result = validate_execution_result_v2(payload, plan, receipt)

                self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_exited_result_without_exit_code(self) -> None:
        payload, plan, receipt = _result()
        payload["capability_status"] = "BLOCK_TECHNICAL"
        payload["exit_code"] = None
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        result = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

        payload, plan, receipt = _result()
        payload["stdout"]["truncated"] = True
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )


if __name__ == "__main__":
    unittest.main()
