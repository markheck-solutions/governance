from __future__ import annotations

import io
import subprocess
import unittest
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from governance_eval.docker_runtime import (
    docker_run_argv,
    execute_ruff_docker,
    runtime_root_path,
)
import governance_eval.docker_runtime as docker_runtime
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.schemas import validate_named
from test_execution_plan_v2 import _receipt


class DockerRuntimePolicyTests(unittest.TestCase):
    def test_subprocess_environments_drop_host_injection_variables(self) -> None:
        executable = Path("C:/trusted/tool.exe")
        with mock.patch.dict(
            os.environ,
            {
                "DOCKER_HOST": "tcp://attacker.invalid:2375",
                "DOCKER_CONTEXT": "attacker",
                "DOCKER_CONFIG": "C:/attacker",
                "GIT_DIR": "C:/attacker/.git",
                "GIT_WORK_TREE": "C:/attacker/worktree",
            },
        ):
            docker_environment = docker_runtime._docker_environment(executable)
            git_environment = docker_runtime._git_environment(executable)

        self.assertNotIn("DOCKER_HOST", docker_environment)
        self.assertNotIn("DOCKER_CONTEXT", docker_environment)
        self.assertNotIn("DOCKER_CONFIG", docker_environment)
        self.assertNotIn("GIT_DIR", git_environment)
        self.assertNotIn("GIT_WORK_TREE", git_environment)

    def test_run_command_has_exact_lockdown_and_only_disposable_mounts(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )
        workspace = Path("C:/temp/disposable-target")
        docker = Path("C:/Program Files/Docker/docker.exe")
        toolchain_root = Path("C:/temp/sealed-toolchain")

        argv = docker_run_argv(
            docker=docker,
            docker_host="npipe:////./pipe/docker_engine",
            plan=plan,
            workspace=workspace,
            toolchain_root=toolchain_root,
            container_name="governance-test-container",
        )

        self.assertEqual(argv[0], str(docker))
        self.assertEqual(argv[1], "--host=npipe:////./pipe/docker_engine")
        for required in (
            "--read-only",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=128",
            "--memory=536870912",
            "--cpus=1.0",
            "--user=65532:65532",
        ):
            self.assertIn(required, argv)
        self.assertIn(
            f"type=bind,src={workspace},dst=/workspace",
            argv,
        )
        self.assertIn(
            f"type=bind,src={toolchain_root},dst=/opt/governance-toolchain,readonly",
            argv,
        )
        self.assertNotIn("-v", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("sh", argv)
        self.assertNotIn("bash", argv)
        self.assertEqual(argv[-6:], plan.step["argv"])

    def test_missing_docker_emits_schema_valid_block(self) -> None:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )

        result = execute_ruff_docker(
            plan=plan,
            receipt=receipt,
            target_root=Path("C:/not-used"),
            evaluator_root=Path("C:/not-used"),
            toolchain_binary=Path("C:/not-used/ruff"),
        )

        validate_named("execution_result_v2", result)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["termination"], "NOT_STARTED")
        self.assertEqual(result["errors"], ["Docker CLI path is invalid"])
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_rehashed_mutated_plan_blocks_before_docker_resolution(self) -> None:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )
        runtime = {**plan.runtime, "network": "bridge"}
        hostile = replace(plan, runtime=runtime, plan_id="")
        payload = hostile.to_json()
        payload.pop("plan_id")
        from governance_eval.hashing import sha256_json

        hostile = replace(hostile, plan_id=sha256_json(payload))

        with mock.patch(
            "governance_eval.docker_runtime._trusted_docker"
        ) as docker_resolution:
            result = execute_ruff_docker(
                plan=hostile,
                receipt=receipt,
                target_root=Path("C:/not-used"),
                evaluator_root=Path("C:/not-used"),
                toolchain_binary=Path("C:/not-used/ruff"),
            )

        docker_resolution.assert_not_called()
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution plan differs from evaluator-owned plan"],
        )

    def test_non_exited_zero_code_cannot_pass(self) -> None:
        result, plan, receipt = self._host_result(
            termination="TIMED_OUT", exit_code=0, duration=120, errors=[]
        )

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_cleanup_error_preserves_launched_outcome(self) -> None:
        result, plan, receipt = self._host_result(
            termination="EXITED",
            exit_code=0,
            duration=1,
            errors=["Docker container cleanup failed"],
        )

        self.assertEqual(result["termination"], "EXITED")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["errors"], ["Docker container cleanup failed"])
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_run_boundary_captures_cleanup_timeout(self) -> None:
        process = mock.Mock()
        process.stdout = io.BytesIO(b"captured stdout")
        process.stderr = io.BytesIO(b"")
        process.poll.return_value = 0
        process.wait.return_value = 0
        with (
            mock.patch("subprocess.Popen", return_value=process),
            mock.patch(
                "governance_eval.docker_runtime._command",
                side_effect=(
                    subprocess.TimeoutExpired("docker inspect", 10),
                    SimpleNamespace(returncode=0),
                ),
            ),
        ):
            outcome = docker_runtime._run_bounded(
                ["docker", "run"],
                docker=Path("C:/trusted/docker.exe"),
                docker_host="npipe:////./pipe/docker_engine",
                container_name="governance-test-container",
                timeout_seconds=120,
                output_limit=65536,
            )

        self.assertEqual(outcome["termination"], "EXITED")
        self.assertEqual(outcome["exit_code"], 0)
        self.assertEqual(outcome["errors"], ["Docker container cleanup failed"])
        self.assertGreater(outcome["stdout"]["captured_bytes"], 0)

    def _host_result(
        self,
        *,
        termination: str,
        exit_code: int,
        duration: int,
        errors: list[str],
    ) -> tuple[dict[str, object], object, object]:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )
        started = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        runtime_root = runtime_root_path(plan)
        workspace = runtime_root / "workspace"
        toolchain = runtime_root / "toolchain"
        command = docker_run_argv(
            docker=Path(plan.runtime["docker_path"]),
            docker_host=plan.runtime["docker_host"],
            plan=plan,
            workspace=workspace,
            toolchain_root=toolchain,
            container_name="governance-test-container",
        )
        outcome = {
            "termination": termination,
            "exit_code": exit_code,
            "stdout": docker_runtime._empty_stream(),
            "stderr": docker_runtime._empty_stream(),
            "started_at": started,
            "completed_at": started + timedelta(seconds=duration),
        }
        result = docker_runtime._result(
            plan,
            receipt,
            None,
            plan.runtime["docker_host"],
            command,
            started,
            outcome=outcome,
            errors=errors,
        )
        return result, plan, receipt


if __name__ == "__main__":
    unittest.main()
