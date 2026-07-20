from __future__ import annotations

import os
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

import governance_eval.docker_runtime as docker_runtime
from governance_eval.capability_catalog import capability_adapters
from governance_eval.docker_runtime import RuntimePaths, docker_gate_argv
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from receipt_fixture import scope_manifest, strict_receipt, toolchain_binding


class DockerRuntimePolicyTests(unittest.TestCase):
    def test_subprocess_environments_drop_host_git_injection(self) -> None:
        executable = Path("C:/trusted/git.exe")
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": "C:/attacker/.git",
                "GIT_WORK_TREE": "C:/attacker/worktree",
                "GIT_CONFIG_GLOBAL": "C:/attacker/config",
            },
        ):
            environment = docker_runtime._git_environment(executable)

        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_WORK_TREE", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_all_docker_adapters_use_only_exact_disposable_mounts(self) -> None:
        for adapter in capability_adapters():
            if adapter.execution != "docker":
                continue
            with self.subTest(adapter=adapter.adapter_id):
                plan, paths, evaluator, toolchain, cleanup = _plan_paths(adapter)
                with cleanup:
                    argv = docker_gate_argv(
                        plan=plan,
                        docker=Path(plan.runtime["docker"]["path"]),
                        paths=paths,
                        evaluator_root=evaluator,
                        toolchain_root=toolchain,
                        container_name=f"governance-{plan.plan_id[:32]}",
                    )

                joined = "\n".join(argv)
                for required in (
                    "--read-only",
                    "--network=none",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges:true",
                    "--pids-limit=128",
                    "--memory=536870912",
                    "--user=65532:65532",
                ):
                    self.assertIn(required, argv)
                self.assertNotIn("docker.sock", joined.lower())
                self.assertNotIn("docker_engine,dst", joined.lower())
                self.assertNotIn("--privileged", argv)
                self.assertNotIn("--rm", argv)
                self.assertEqual(argv[-len(plan.step["argv"]) :], plan.step["argv"])
                if adapter.capability in {"build", "benchmark"}:
                    self.assertIn(f"src={paths.staging},dst=/governance-output", joined)
                    self.assertNotIn(
                        f"src={paths.output},dst=/governance-output", joined
                    )
                else:
                    self.assertNotIn("dst=/governance-output", joined)
                if adapter.capability == "tests":
                    self.assertIn(
                        f"src={paths.base_tests},dst=/workspace/tests,readonly",
                        joined,
                    )

    def test_package_audit_has_no_workspace_or_toolchain_mount(self) -> None:
        adapter = capability_adapters()[7]
        plan, paths, evaluator, toolchain, cleanup = _plan_paths(adapter)
        with cleanup:
            argv = docker_gate_argv(
                plan=plan,
                docker=Path(plan.runtime["docker"]["path"]),
                paths=paths,
                evaluator_root=evaluator,
                toolchain_root=toolchain,
                container_name=f"governance-{plan.plan_id[:32]}",
            )
        joined = "\n".join(argv)
        self.assertNotIn("dst=/workspace", joined)
        self.assertNotIn("dst=/opt/governance-toolchain", joined)
        self.assertIn(f"src={paths.input},dst=/input,readonly", joined)

    def test_materialized_git_paths_reject_platform_escapes(self) -> None:
        for path in (
            r"..\escaped.py",
            r"C:\attacker\owned.py",
            "../escaped.py",
            "/absolute.py",
        ):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    docker_runtime.DockerRuntimeError, "path is unsafe"
                ),
            ):
                docker_runtime._canonical_path(path)

    def test_staging_rejects_links_and_inventory_flood(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("data", encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(
                docker_runtime.DockerRuntimeError, "staged artifact path"
            ):
                docker_runtime._safe_staged_files(root, allowed_directories=set())

    def test_unittest_summary_requires_real_non_skipped_success(self) -> None:
        adapter = capability_adapters()[5]
        plan, _paths, _evaluator, _toolchain, cleanup = _plan_paths(adapter)
        marker = b"GOVERNANCE_UNITTEST_SUMMARY="
        payloads = (
            {},
            {
                "tests_run": 0,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "unexpected_successes": 0,
            },
            {
                "tests_run": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 1,
                "unexpected_successes": 0,
            },
        )
        with cleanup:
            for index, payload in enumerate(payloads):
                output = Path(cleanup.name) / f"summary-{index}"
                output.mkdir()
                artifacts, errors = docker_runtime._capture_summary(
                    output,
                    plan,
                    marker,
                    marker + json.dumps(payload).encode("utf-8") + b"\n",
                )
                self.assertEqual(artifacts, [])
                self.assertTrue(errors)

    def test_unittest_adapter_blocks_before_candidate_interpreter(self) -> None:
        adapter = capability_adapters()[5]
        plan, _paths, _evaluator, _toolchain, cleanup = _plan_paths(adapter)
        with (
            cleanup,
            self.assertRaisesRegex(
                docker_runtime.DockerRuntimeError,
                "cannot authenticate success",
            ),
        ):
            docker_runtime._require_authoritative_adapter(plan)


def _plan_paths(adapter):
    receipt = strict_receipt()
    scope = scope_manifest(receipt, adapter)
    toolchain_manifest = (
        toolchain_binding(receipt) if adapter.mount_profile != "wheel-only.v1" else None
    )
    input_artifacts = (
        (_input_wheel(),) if adapter.mount_profile == "wheel-only.v1" else ()
    )
    with mock.patch(
        "governance_eval.execution_plan_v2.build_scope_manifest",
        return_value=deepcopy(scope),
    ):
        plan = compile_execution_plan_v2(
            receipt,
            capability=adapter.capability,
            adapter_id=adapter.adapter_id,
            scope_manifest=scope,
            target_root=Path("C:/target"),
            evaluator_root=Path("C:/evaluator"),
            toolchain_manifest=toolchain_manifest,
            input_artifacts=input_artifacts,
        )
    cleanup = tempfile.TemporaryDirectory()
    root = Path(cleanup.name).resolve()
    children = {
        name: root / name
        for name in (
            "workspace",
            "base-tests",
            "scope",
            "input",
            "staging",
            "output",
            "toolchain",
        )
    }
    for path in children.values():
        path.mkdir()
    paths = RuntimePaths(
        root=root,
        workspace=children["workspace"],
        base_tests=children["base-tests"],
        scope=children["scope"],
        input=children["input"],
        staging=children["staging"],
        output=children["output"],
    )
    toolchain = (
        None if adapter.mount_profile == "wheel-only.v1" else children["toolchain"]
    )
    return plan, paths, Path.cwd(), toolchain, cleanup


def _input_wheel():
    return {
        "kind": "python-wheel",
        "name": "python-wheel",
        "filename": "governance_eval-0.1.0-py3-none-any.whl",
        "sha256": "1" * 64,
        "size_bytes": 1234,
        "producer_plan_id": "2" * 64,
        "producer_artifact_id": "3" * 64,
    }


if __name__ == "__main__":
    unittest.main()
