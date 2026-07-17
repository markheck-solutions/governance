from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_named

ROOT = repo_root(Path(__file__).resolve())
BOOTSTRAP_PATH = ROOT / "governance_eval/toolchain_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("toolchain_bootstrap", BOOTSTRAP_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("toolchain bootstrap module unavailable")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class ToolchainBootstrapTests(unittest.TestCase):
    def test_repository_lock_is_exact_and_cross_platform(self) -> None:
        digest = BOOTSTRAP.validate_lock(ROOT / "requirements-governance.lock")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_lock_rejects_missing_hash(self) -> None:
        self._assert_lock_rejected(
            "ruff==0.15.21 \\\n"
            "  --hash=sha256:bab0905d2f29e0d9fbc3c373ed23db0095edaa3f71f1f4f519ec15134d9e85c8\n",
            "hash count",
        )

    def test_lock_rejects_extra_package_or_install_option(self) -> None:
        self._assert_lock_rejected(
            self._valid_lock() + "mypy==2.2.0 --hash=sha256:" + "0" * 64 + "\n",
            "exactly one requirement",
        )
        self._assert_lock_rejected(
            self._valid_lock().replace(
                "ruff==0.15.21",
                "--extra-index-url https://example.invalid ruff==0.15.21",
            ),
            "must pin",
        )

    def test_pip_environment_removes_credentials_and_package_overrides(self) -> None:
        source = {
            "PATH": "hostile-path",
            "GH_TOKEN": "secret-one",
            "GITHUB_TOKEN": "secret-two",
            "PIP_INDEX_URL": "https://example.invalid/simple",
            "PIP_TRUSTED_HOST": "example.invalid",
            "PYTHONPATH": "hostile-python-path",
            "SYSTEMROOT": r"C:\Windows",
        }
        runtime_bin = Path("/trusted/runtime/bin")
        environment = BOOTSTRAP.sanitized_pip_environment(runtime_bin, source)
        self.assertEqual(environment["PATH"], str(runtime_bin))
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)
        for key in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "PIP_INDEX_URL",
            "PIP_TRUSTED_HOST",
            "PYTHONPATH",
        ):
            self.assertNotIn(key, environment)
        self.assertNotIn("secret-one", environment.values())
        self.assertNotIn("secret-two", environment.values())

    def test_install_command_is_isolated_hash_locked_and_wheel_only(self) -> None:
        python_path = Path("/trusted/runtime/bin/python")
        lock_path = Path("/trusted/governance/requirements-governance.lock")
        command = BOOTSTRAP.pip_install_command(python_path, lock_path)
        self.assertEqual(command[0], str(python_path))
        self.assertEqual(command[1:4], ("-I", "-m", "pip"))
        for required in (
            "--require-virtualenv",
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--no-input",
        ):
            self.assertIn(required, command)
        self.assertIn("https://pypi.org/simple", command)
        self.assertEqual(command[-2:], ("-r", str(lock_path)))

    def test_provision_writes_exact_version_bound_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            module_origin = paths["runtime"] / "site-packages" / "ruff" / "__init__.py"

            def create_runtime(_builder: object, runtime_root: Path) -> None:
                python_path, runtime_bin = BOOTSTRAP._runtime_paths(Path(runtime_root))
                runtime_bin.mkdir(parents=True)
                python_path.touch()
                (runtime_bin / ("ruff.exe" if os.name == "nt" else "ruff")).touch()
                module_origin.parent.mkdir(parents=True)
                module_origin.touch()

            commands: list[tuple[str, ...]] = []
            environments: list[dict[str, str]] = []

            def run(
                command: tuple[str, ...], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                commands.append(tuple(command))
                environments.append(dict(kwargs["environment"]))
                evidence = kwargs["command_evidence"]
                if not isinstance(evidence, list):
                    raise TypeError("command evidence must be a list")
                evidence.append(
                    {
                        "command": list(command),
                        "started_at": "2026-07-16T00:00:00Z",
                        "completed_at": "2026-07-16T00:00:01Z",
                        "timeout_seconds": kwargs["timeout_seconds"],
                        "timed_out": False,
                        "exit_code": 0,
                    }
                )
                git_stdout = self._bound_git_stdout(command, paths["governance"])
                if git_stdout is not None:
                    stdout = git_stdout
                elif "-c" in command:
                    stdout = json.dumps(
                        {
                            "origin": str(module_origin),
                            "version": BOOTSTRAP.RUFF_VERSION,
                        }
                    )
                elif command[-2:] == ("ruff", "--version"):
                    stdout = f"ruff {BOOTSTRAP.RUFF_VERSION}\n"
                else:
                    stdout = ""
                return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

            with (
                mock.patch.object(
                    BOOTSTRAP, "_current_python_version", return_value=(3, 12, 13)
                ),
                mock.patch.object(BOOTSTRAP.venv.EnvBuilder, "create", create_runtime),
                mock.patch.object(BOOTSTRAP, "_run", side_effect=run),
                mock.patch.object(
                    BOOTSTRAP.platform, "python_version", return_value="3.12.13"
                ),
            ):
                receipt = BOOTSTRAP.provision(
                    governance_root=paths["governance"],
                    workspace_root=paths["workspace"],
                    runtime_root=paths["runtime"],
                    base_sha="b" * 40,
                    evaluator_sha="a" * 40,
                    receipt_path=paths["receipt"],
                )

            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["decision"], "TOOLCHAIN_READY")
            self.assertEqual(receipt["base_sha"], "b" * 40)
            self.assertEqual(receipt["head_sha"], "a" * 40)
            self.assertEqual(receipt["evaluator_sha"], "a" * 40)
            self.assertEqual(receipt["checkout_head_sha"], "a" * 40)
            self.assertEqual(receipt["merge_base_sha"], "c" * 40)
            self.assertEqual(receipt["python_version"], "3.12.13")
            self.assertEqual(
                receipt["packages"], [{"name": "ruff", "version": "0.15.21"}]
            )
            self.assertRegex(str(receipt["payload_sha256"]), r"^[0-9a-f]{64}$")
            claimed_digest = receipt["payload_sha256"]
            self.assertEqual(
                claimed_digest,
                BOOTSTRAP._payload_sha256(receipt),
            )
            self.assertEqual(
                json.loads(paths["receipt"].read_text(encoding="utf-8")), receipt
            )
            validate_named("governance_toolchain_receipt", receipt, ROOT)
            self.assertEqual(commands[5][1:4], ("-I", "-m", "ensurepip"))
            self.assertEqual(commands[6][1:4], ("-I", "-m", "pip"))
            self.assertEqual(commands[-1][-3:], ("-m", "ruff", "--version"))
            for environment in environments:
                self.assertNotIn("GH_TOKEN", environment)
                self.assertNotIn("GITHUB_TOKEN", environment)
                self.assertNotIn("PIP_INDEX_URL", environment)

            mutations = (
                ("identity", lambda item: item.__setitem__("evaluator_sha", "c" * 40)),
                (
                    "base command binding",
                    lambda item: (
                        item.__setitem__("base_sha", "c" * 40),
                        item.__setitem__("claimed_base_sha", "c" * 40),
                    ),
                ),
                ("Python", lambda item: item.__setitem__("python_version", "0.0.0")),
                ("package", lambda item: item.__setitem__("packages", [])),
                ("commands", lambda item: item.__setitem__("commands", [])),
                (
                    "failed command",
                    lambda item: item["commands"][0].__setitem__("exit_code", 1),
                ),
            )
            for name, mutate in mutations:
                with self.subTest(invalid_success=name):
                    invalid = json.loads(json.dumps(receipt))
                    mutate(invalid)
                    invalid["payload_sha256"] = BOOTSTRAP._payload_sha256(invalid)
                    with self.assertRaisesRegex(
                        BOOTSTRAP.BootstrapError,
                        "successful toolchain receipt",
                    ):
                        BOOTSTRAP.validate_receipt(paths["governance"], invalid)

    def test_provision_rejects_invalid_identity_location_and_runtime_state(
        self,
    ) -> None:
        cases = (
            (
                "wrong Python",
                {"python_version": (3, 12, 12)},
                "requires Python 3.12.13",
            ),
            ("invalid SHA", {"evaluator_sha": "a" * 39}, "exact 40-character"),
            (
                "runtime in workspace",
                {"runtime_in_workspace": True},
                "outside target workspace",
            ),
            (
                "runtime in governance checkout",
                {"runtime_in_governance": True},
                "governance checkout",
            ),
            ("existing runtime", {"existing_runtime": True}, "already exists"),
            (
                "receipt in workspace",
                {"receipt_in_workspace": True},
                "receipt must be outside",
            ),
            (
                "receipt in governance checkout",
                {"receipt_in_governance": True},
                "governance checkout",
            ),
        )
        for name, options, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                paths = self._provision_paths(Path(tmp))
                runtime = paths["runtime"]
                if options.get("runtime_in_workspace"):
                    runtime = paths["workspace"] / "runtime"
                if options.get("runtime_in_governance"):
                    runtime = paths["governance"] / "runtime"
                if options.get("existing_runtime"):
                    runtime.mkdir()
                receipt = paths["receipt"]
                if options.get("receipt_in_workspace"):
                    receipt = paths["workspace"] / "receipt.json"
                if options.get("receipt_in_governance"):
                    receipt = paths["governance"] / "receipt.json"
                with mock.patch.object(
                    BOOTSTRAP,
                    "_current_python_version",
                    return_value=options.get("python_version", (3, 12, 13)),
                ):
                    with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected):
                        BOOTSTRAP.provision(
                            governance_root=paths["governance"],
                            workspace_root=paths["workspace"],
                            runtime_root=runtime,
                            base_sha="b" * 40,
                            evaluator_sha=str(options.get("evaluator_sha", "a" * 40)),
                            receipt_path=receipt,
                        )

    def test_provision_rejects_untrusted_or_wrong_ruff(self) -> None:
        cases = (
            ("module escape", "0.15.21", True, "outside toolchain runtime"),
            ("version mismatch", "0.15.20", False, "version differs from lock"),
        )
        for name, version, escaped, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                paths = self._provision_paths(Path(tmp))
                module_origin = (
                    Path(tmp) / "escaped" / "ruff" / "__init__.py"
                    if escaped
                    else paths["runtime"] / "site-packages" / "ruff" / "__init__.py"
                )

                def create_runtime(_builder: object, runtime_root: Path) -> None:
                    python_path, runtime_bin = BOOTSTRAP._runtime_paths(
                        Path(runtime_root)
                    )
                    runtime_bin.mkdir(parents=True)
                    python_path.touch()
                    (runtime_bin / ("ruff.exe" if os.name == "nt" else "ruff")).touch()
                    module_origin.parent.mkdir(parents=True)
                    module_origin.touch()

                def run(
                    command: tuple[str, ...], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    git_stdout = self._bound_git_stdout(command, paths["governance"])
                    if git_stdout is not None:
                        stdout = git_stdout
                    elif "-c" in command:
                        stdout = json.dumps(
                            {"origin": str(module_origin), "version": version}
                        )
                    else:
                        stdout = ""
                    return subprocess.CompletedProcess(
                        command, 0, stdout=stdout, stderr=""
                    )

                with (
                    mock.patch.object(
                        BOOTSTRAP, "_current_python_version", return_value=(3, 12, 13)
                    ),
                    mock.patch.object(
                        BOOTSTRAP.venv.EnvBuilder, "create", create_runtime
                    ),
                    mock.patch.object(BOOTSTRAP, "_run", side_effect=run),
                ):
                    with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected):
                        BOOTSTRAP.provision(
                            governance_root=paths["governance"],
                            workspace_root=paths["workspace"],
                            runtime_root=paths["runtime"],
                            base_sha="b" * 40,
                            evaluator_sha="a" * 40,
                            receipt_path=paths["receipt"],
                        )

    def test_checkout_binding_rejects_sha_drift_dirty_tree_and_workspace_git(
        self,
    ) -> None:
        cases = (
            ("SHA drift", "b" * 40, "", False, "HEAD differs"),
            (
                "dirty tree",
                "a" * 40,
                "?? governance_eval/rogue.py",
                False,
                "uncommitted",
            ),
            ("workspace Git", "a" * 40, "", True, "inside target workspace"),
        )
        for name, head, status, workspace_git, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                paths = self._provision_paths(Path(tmp))
                git_path = Path(tmp) / "git"
                if workspace_git:
                    git_path = paths["workspace"] / "git"
                git_path.touch()
                observed_environments: list[dict[str, str]] = []

                def run(
                    command: tuple[str, ...], **kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    observed_environments.append(dict(kwargs["environment"]))
                    if command[-2:] == ("rev-parse", "--show-toplevel"):
                        stdout = str(paths["governance"])
                    elif command[-2:] == ("--verify", "HEAD^{commit}"):
                        stdout = head
                    elif command[-2:] == (
                        "--verify",
                        f"{'b' * 40}^{{commit}}",
                    ):
                        stdout = "b" * 40
                    elif "merge-base" in command:
                        stdout = "c" * 40
                    else:
                        stdout = status
                    return subprocess.CompletedProcess(
                        command, 0, stdout=stdout, stderr=""
                    )

                source = {
                    "PATH": str(Path(tmp)),
                    "GH_TOKEN": "secret-one",
                    "GITHUB_TOKEN": "secret-two",
                    "PIP_INDEX_URL": "https://example.invalid/simple",
                }
                with (
                    mock.patch.object(
                        BOOTSTRAP.shutil, "which", return_value=str(git_path)
                    ),
                    mock.patch.object(BOOTSTRAP, "_run", side_effect=run),
                    self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected),
                ):
                    BOOTSTRAP.validate_checkout(
                        paths["governance"],
                        paths["workspace"],
                        "b" * 40,
                        "a" * 40,
                        source,
                        [],
                    )
                for environment in observed_environments:
                    self.assertNotIn("GH_TOKEN", environment)
                    self.assertNotIn("GITHUB_TOKEN", environment)
                    self.assertNotIn("PIP_INDEX_URL", environment)

    def test_checkout_rejects_git_inside_governance_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            git_path = paths["governance"] / "git"
            git_path.touch()
            with (
                mock.patch.object(
                    BOOTSTRAP.shutil, "which", return_value=str(git_path)
                ),
                self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "governance checkout"),
            ):
                BOOTSTRAP.validate_checkout(
                    paths["governance"],
                    paths["workspace"],
                    "b" * 40,
                    "a" * 40,
                    {"PATH": str(Path(tmp))},
                    [],
                )

    def test_checkout_binding_rejects_missing_and_unrelated_base(self) -> None:
        cases = (
            ("missing base", True, False, "base commit missing"),
            ("unrelated base", False, True, "base has no common history"),
        )
        for name, missing, unrelated, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                paths = self._provision_paths(Path(tmp))
                git_path = Path(tmp) / "git"
                git_path.touch()

                def run(
                    command: tuple[str, ...], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    if command[-2:] == ("rev-parse", "--show-toplevel"):
                        stdout = str(paths["governance"])
                    elif command[-2:] == ("--verify", "HEAD^{commit}"):
                        stdout = "a" * 40
                    elif command[-2:] == (
                        "--verify",
                        f"{'b' * 40}^{{commit}}",
                    ):
                        if missing:
                            raise BOOTSTRAP.BootstrapError("base commit missing")
                        stdout = "b" * 40
                    elif "merge-base" in command:
                        if unrelated:
                            raise BOOTSTRAP.BootstrapError("base has no common history")
                        stdout = "c" * 40
                    else:
                        stdout = ""
                    return subprocess.CompletedProcess(
                        command, 0, stdout=stdout, stderr=""
                    )

                with (
                    mock.patch.object(
                        BOOTSTRAP.shutil, "which", return_value=str(git_path)
                    ),
                    mock.patch.object(BOOTSTRAP, "_run", side_effect=run),
                    self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected),
                ):
                    BOOTSTRAP.validate_checkout(
                        paths["governance"],
                        paths["workspace"],
                        "b" * 40,
                        "a" * 40,
                        {"PATH": str(Path(tmp))},
                        [],
                    )

    def test_provision_fails_closed_on_install_timeout_and_missing_ruff(self) -> None:
        cases = (
            ("install timeout", True, True, "timed out"),
            ("missing Ruff executable", False, False, "executable missing"),
        )
        for name, timeout_install, create_ruff, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                paths = self._provision_paths(Path(tmp))
                module_origin = (
                    paths["runtime"] / "site-packages" / "ruff" / "__init__.py"
                )

                def create_runtime(_builder: object, runtime_root: Path) -> None:
                    python_path, runtime_bin = BOOTSTRAP._runtime_paths(
                        Path(runtime_root)
                    )
                    runtime_bin.mkdir(parents=True)
                    python_path.touch()
                    if create_ruff:
                        (
                            runtime_bin / ("ruff.exe" if os.name == "nt" else "ruff")
                        ).touch()
                    module_origin.parent.mkdir(parents=True)
                    module_origin.touch()

                def run(
                    command: tuple[str, ...], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    git_stdout = self._bound_git_stdout(command, paths["governance"])
                    if git_stdout is not None:
                        stdout = git_stdout
                    elif command[1:4] == ("-I", "-m", "pip") and timeout_install:
                        raise BOOTSTRAP.BootstrapError(
                            "toolchain command timed out after 180s"
                        )
                    elif "-c" in command:
                        stdout = json.dumps(
                            {"origin": str(module_origin), "version": "0.15.21"}
                        )
                    else:
                        stdout = ""
                    return subprocess.CompletedProcess(
                        command, 0, stdout=stdout, stderr=""
                    )

                with (
                    mock.patch.object(
                        BOOTSTRAP, "_current_python_version", return_value=(3, 12, 13)
                    ),
                    mock.patch.object(
                        BOOTSTRAP.venv.EnvBuilder, "create", create_runtime
                    ),
                    mock.patch.object(BOOTSTRAP, "_run", side_effect=run),
                    self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected),
                ):
                    BOOTSTRAP.provision(
                        governance_root=paths["governance"],
                        workspace_root=paths["workspace"],
                        runtime_root=paths["runtime"],
                        base_sha="b" * 40,
                        evaluator_sha="a" * 40,
                        receipt_path=paths["receipt"],
                    )

    def test_bounded_runner_records_timeout_and_failed_exit(self) -> None:
        cases = (
            (
                "timeout",
                subprocess.TimeoutExpired(["tool"], 12),
                True,
                None,
                "timed out",
            ),
            (
                "failed exit",
                subprocess.CalledProcessError(7, ["tool"], stderr="failed"),
                False,
                7,
                "command failed",
            ),
        )
        for name, failure, timed_out, exit_code, expected in cases:
            with self.subTest(name=name):
                evidence: list[dict[str, object]] = []
                with (
                    mock.patch.object(BOOTSTRAP.subprocess, "run", side_effect=failure),
                    self.assertRaisesRegex(BOOTSTRAP.BootstrapError, expected),
                ):
                    BOOTSTRAP._run(
                        ("tool", "arg"),
                        environment={},
                        timeout_seconds=12,
                        command_evidence=evidence,
                    )
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0]["command"], ["tool", "arg"])
                self.assertEqual(evidence[0]["timeout_seconds"], 12)
                self.assertEqual(evidence[0]["timed_out"], timed_out)
                self.assertEqual(evidence[0]["exit_code"], exit_code)
                self.assertRegex(
                    str(evidence[0]["started_at"]),
                    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$",
                )

    def test_github_outputs_use_receipt_paths_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            receipt_path = root / "receipt.json"
            receipt_path.write_text("{}\n", encoding="utf-8")
            output_path = root / "github-output.txt"
            python_path = root / (
                "Scripts/python.exe" if os.name == "nt" else "bin/python"
            )
            receipt = {
                "python_path": str(python_path),
                "lock_sha256": "a" * 64,
                "payload_sha256": "b" * 64,
            }
            BOOTSTRAP.write_github_outputs(output_path, receipt_path, receipt)
            outputs = dict(
                line.split("=", 1)
                for line in output_path.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(outputs["python-path"], str(python_path))
            self.assertEqual(outputs["bin-path"], str(python_path.parent))
            self.assertEqual(
                outputs["receipt-file-sha256"],
                BOOTSTRAP.hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            )

    def test_receipt_schema_rejects_missing_payload_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            invalid = {
                "schema_version": "1.0",
                "status": "FAIL",
                "decision": "BLOCK_TECHNICAL",
                "base_sha": "b" * 40,
                "claimed_base_sha": "b" * 40,
                "head_sha": "a" * 40,
                "evaluator_sha": "a" * 40,
                "claimed_evaluator_sha": "a" * 40,
                "checkout_head_sha": None,
                "merge_base_sha": None,
                "lock_sha256": None,
                "python_version": "3.12.13",
                "platform_system": "test",
                "platform_machine": "test",
                "runtime_root": str(paths["runtime"]),
                "python_path": None,
                "ruff_module_origin": None,
                "ruff_executable": None,
                "packages": [],
                "commands": [],
                "error": "reproduced failure",
            }
            with self.assertRaises(SchemaValidationError):
                validate_named("governance_toolchain_receipt", invalid, ROOT)

    def test_main_persists_schema_valid_block_receipt_on_subprocess_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            github_output = Path(tmp) / "github-output.txt"

            def fail_provision(**kwargs: object) -> dict[str, object]:
                evidence = kwargs["command_evidence"]
                if not isinstance(evidence, list):
                    raise TypeError("command evidence must be a list")
                evidence.append(
                    {
                        "command": ["tool", "install"],
                        "started_at": "2026-07-16T00:00:00Z",
                        "completed_at": "2026-07-16T00:00:12Z",
                        "timeout_seconds": 12,
                        "timed_out": True,
                        "exit_code": None,
                    }
                )
                raise BOOTSTRAP.BootstrapError("reproduced install timeout")

            argv = [
                "--governance-root",
                str(paths["governance"]),
                "--workspace-root",
                str(paths["workspace"]),
                "--runtime-root",
                str(paths["runtime"]),
                "--base-sha",
                "b" * 40,
                "--evaluator-sha",
                "a" * 40,
                "--receipt",
                str(paths["receipt"]),
                "--failure-receipt",
                str(paths["receipt"]),
                "--github-output",
                str(github_output),
            ]
            with mock.patch.object(BOOTSTRAP, "provision", side_effect=fail_provision):
                self.assertEqual(BOOTSTRAP.main(argv), 1)

            receipt = json.loads(paths["receipt"].read_text(encoding="utf-8"))
            validate_named("governance_toolchain_receipt", receipt, ROOT)
            BOOTSTRAP.validate_receipt(paths["governance"], receipt)
            self.assertEqual(receipt["status"], "FAIL")
            self.assertEqual(receipt["decision"], "BLOCK_TECHNICAL")
            self.assertEqual(receipt["base_sha"], "b" * 40)
            self.assertEqual(receipt["head_sha"], "a" * 40)
            self.assertEqual(receipt["evaluator_sha"], "a" * 40)
            self.assertEqual(receipt["commands"][0]["timed_out"], True)
            outputs = dict(
                line.split("=", 1)
                for line in github_output.read_text(encoding="utf-8").splitlines()
            )
            self.assertIn("receipt-file-sha256", outputs)
            self.assertNotIn("python-path", outputs)

    def test_main_uses_external_failure_receipt_for_rejected_primary_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            rejected_receipt = paths["workspace"] / "receipt.json"
            failure_receipt = Path(tmp) / "failure-receipt.json"
            argv = [
                "--governance-root",
                str(paths["governance"]),
                "--workspace-root",
                str(paths["workspace"]),
                "--runtime-root",
                str(paths["runtime"]),
                "--base-sha",
                "b" * 40,
                "--evaluator-sha",
                "a" * 40,
                "--receipt",
                str(rejected_receipt),
                "--failure-receipt",
                str(failure_receipt),
            ]
            with mock.patch.object(
                BOOTSTRAP, "_current_python_version", return_value=(3, 12, 13)
            ):
                self.assertEqual(BOOTSTRAP.main(argv), 1)

            self.assertFalse(rejected_receipt.exists())
            receipt = json.loads(failure_receipt.read_text(encoding="utf-8"))
            BOOTSTRAP.validate_receipt(paths["governance"], receipt)
            self.assertEqual(receipt["decision"], "BLOCK_TECHNICAL")
            self.assertIn("receipt must be outside", receipt["error"])

    def test_main_rejects_output_boundaries_before_provision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            workspace_unsafe = paths["workspace"] / "unsafe.json"
            governance_unsafe = paths["governance"] / "unsafe.json"
            cases = (
                ("workspace failure receipt", workspace_unsafe, None),
                ("governance failure receipt", governance_unsafe, None),
                ("workspace GitHub output", paths["receipt"], workspace_unsafe),
                (
                    "governance GitHub output",
                    paths["receipt"],
                    governance_unsafe,
                ),
            )
            for name, failure_receipt, github_output in cases:
                with self.subTest(name=name):
                    argv = [
                        "--governance-root",
                        str(paths["governance"]),
                        "--workspace-root",
                        str(paths["workspace"]),
                        "--runtime-root",
                        str(paths["runtime"]),
                        "--base-sha",
                        "b" * 40,
                        "--evaluator-sha",
                        "a" * 40,
                        "--receipt",
                        str(paths["receipt"]),
                        "--failure-receipt",
                        str(failure_receipt),
                    ]
                    if github_output is not None:
                        argv.extend(("--github-output", str(github_output)))
                    with mock.patch.object(BOOTSTRAP, "provision") as provision:
                        self.assertEqual(BOOTSTRAP.main(argv), 1)
                    provision.assert_not_called()
                    self.assertFalse(workspace_unsafe.exists())
                    self.assertFalse(governance_unsafe.exists())

    def _assert_lock_rejected(self, text: str, message: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "requirements-governance.lock"
            lock.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, message):
                BOOTSTRAP.validate_lock(lock)

    @staticmethod
    def _bound_git_stdout(command: tuple[str, ...], governance: Path) -> str | None:
        if command[-2:] == ("rev-parse", "--show-toplevel"):
            return str(governance)
        if command[-2:] == ("--verify", "HEAD^{commit}"):
            return "a" * 40
        if command[-2:] == ("--verify", f"{'b' * 40}^{{commit}}"):
            return "b" * 40
        if "merge-base" in command:
            return "c" * 40
        if "status" in command:
            return ""
        return None

    @staticmethod
    def _valid_lock() -> str:
        return (ROOT / "requirements-governance.lock").read_text(encoding="utf-8")

    @staticmethod
    def _provision_paths(root: Path) -> dict[str, Path]:
        governance = root / "governance"
        workspace = root / "workspace"
        governance.mkdir()
        workspace.mkdir()
        (governance / "requirements-governance.lock").write_bytes(
            (ROOT / "requirements-governance.lock").read_bytes()
        )
        (governance / "schemas/v1").mkdir(parents=True)
        (
            governance / "schemas/v1/governance_toolchain_receipt.schema.json"
        ).write_bytes(
            (ROOT / "schemas/v1/governance_toolchain_receipt.schema.json").read_bytes()
        )
        (governance / "governance_eval").mkdir()
        (governance / "governance_eval/schema_validator.py").write_bytes(
            (ROOT / "governance_eval/schema_validator.py").read_bytes()
        )
        return {
            "governance": governance,
            "workspace": workspace,
            "runtime": root / "runtime",
            "receipt": root / "receipt.json",
        }


if __name__ == "__main__":
    unittest.main()
