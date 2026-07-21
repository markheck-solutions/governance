from __future__ import annotations

import importlib.util
import json
import os
import shutil
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


class _ToolchainBootstrapTestCase(unittest.TestCase):
    @staticmethod
    def _expected_context(**overrides: object) -> dict[str, object]:
        context: dict[str, object] = {
            "repository": "markheck-solutions/governance",
            "repository_id": "1280677092",
            "head_repository_id": "1280677092",
            "event_name": "pull_request",
            "pull_request_number": 52,
            "base_sha": "b" * 40,
            "head_sha": "a" * 40,
            "workflow_ref": (
                "markheck-solutions/governance/.github/workflows/"
                "toolchain-publication.yml@refs/pull/52/merge"
            ),
            "workflow_sha": "d" * 40,
            "run_id": "123456789",
            "run_attempt": "1",
            "expected_artifact_name": "governance-toolchain-publication-123456789-1",
        }
        context.update(overrides)
        return context

    @staticmethod
    def _evaluation_context(**overrides: object) -> dict[str, object]:
        context: dict[str, object] = {
            "context_kind": "SUPPORTABILITY_EVALUATION",
            "repository": "markheck-solutions/governance",
            "repository_id": "1280677092",
            "head_repository_id": "1280677092",
            "event_name": "pull_request_target",
            "event_action": "synchronize",
            "pull_request_number": 71,
            "target_base_sha": "b" * 40,
            "target_head_sha": "c" * 40,
            "evaluator_sha": "a" * 40,
            "workflow_ref": (
                "markheck-solutions/governance/.github/workflows/"
                "supportability-enforcement.yml@refs/heads/main"
            ),
            "workflow_sha": "d" * 40,
            "run_id": "123456789",
            "run_attempt": "1",
            "expected_artifact_name": "candidate-supportability-gate-evidence",
        }
        context.update(overrides)
        return context

    @staticmethod
    def _shadow_context(**overrides: object) -> dict[str, object]:
        context: dict[str, object] = {
            "context_kind": "PHASE1_SHADOW",
            "repository": "markheck-solutions/governance",
            "repository_id": "1280677092",
            "head_repository_id": "1280677092",
            "event_name": "pull_request",
            "pull_request_number": 75,
            "base_sha": "b" * 40,
            "head_sha": "a" * 40,
            "workflow_ref": (
                "markheck-solutions/governance/.github/workflows/"
                "governance-shadow.yml@refs/pull/75/merge"
            ),
            "workflow_sha": "d" * 40,
            "run_id": "123456789",
            "run_attempt": "1",
            "expected_artifact_name": "governance-benchmark-json",
        }
        context.update(overrides)
        return context

    @classmethod
    def _context_argv(cls, **overrides: object) -> list[str]:
        context = cls._expected_context(**overrides)
        pull_request_number = context["pull_request_number"]
        return [
            "--repository",
            str(context["repository"]),
            "--repository-id",
            str(context["repository_id"]),
            "--head-repository-id",
            str(context["head_repository_id"]),
            "--event-name",
            str(context["event_name"]),
            "--pull-request-number",
            "" if pull_request_number is None else str(pull_request_number),
            "--workflow-ref",
            str(context["workflow_ref"]),
            "--workflow-sha",
            str(context["workflow_sha"]),
            "--run-id",
            str(context["run_id"]),
            "--run-attempt",
            str(context["run_attempt"]),
            "--expected-artifact-name",
            str(context["expected_artifact_name"]),
        ]

    def _assert_expected_context(self, receipt: dict[str, object]) -> None:
        for key, value in self._expected_context().items():
            self.assertEqual(receipt[key], value)

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
        (
            governance
            / "schemas/v1/governance_toolchain_evaluation_receipt.schema.json"
        ).write_bytes(
            (
                ROOT / "schemas/v1/governance_toolchain_evaluation_receipt.schema.json"
            ).read_bytes()
        )
        (
            governance / "schemas/v1/governance_toolchain_shadow_receipt.schema.json"
        ).write_bytes(
            (
                ROOT / "schemas/v1/governance_toolchain_shadow_receipt.schema.json"
            ).read_bytes()
        )
        (
            governance / "schemas/v1/governance_toolchain_artifact_binding.schema.json"
        ).write_bytes(
            (
                ROOT / "schemas/v1/governance_toolchain_artifact_binding.schema.json"
            ).read_bytes()
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

    def _valid_failure_receipt(self, paths: dict[str, Path]) -> dict[str, object]:
        receipt: dict[str, object] = {
            **self._expected_context(),
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
            "governance_root": str(paths["governance"]),
            "workspace_root": str(paths["workspace"]),
            "git_executable": None,
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
        return BOOTSTRAP._attach_payload_sha256(receipt)


class ToolchainBootstrapProvisionTests(_ToolchainBootstrapTestCase):
    def test_phase1_shadow_context_accepts_pr_push_dispatch_and_merge_group(
        self,
    ) -> None:
        contexts = (
            self._shadow_context(),
            self._shadow_context(
                event_name="push",
                pull_request_number=None,
                workflow_ref=(
                    "markheck-solutions/governance/.github/workflows/"
                    "governance-shadow.yml@refs/heads/main"
                ),
            ),
            self._shadow_context(
                event_name="workflow_dispatch",
                pull_request_number=None,
                base_sha="a" * 40,
                workflow_ref=(
                    "markheck-solutions/governance/.github/workflows/"
                    "governance-shadow.yml@refs/heads/main"
                ),
            ),
            self._shadow_context(
                event_name="merge_group",
                pull_request_number=None,
                workflow_ref=(
                    "markheck-solutions/governance/.github/workflows/"
                    "governance-shadow.yml@refs/heads/main"
                ),
            ),
        )

        for context in contexts:
            with self.subTest(event=context["event_name"]):
                validated, kind = BOOTSTRAP._validated_context(context)
                self.assertEqual(validated, context)
                self.assertEqual(kind, "PHASE1_SHADOW")

    def test_phase1_shadow_context_fails_closed(self) -> None:
        cases = {
            "kind": {"context_kind": "PUBLICATION"},
            "event": {"event_name": "pull_request_target"},
            "pr_missing": {"pull_request_number": None},
            "workflow": {"workflow_ref": "owner/repo/.github/workflows/evil.yml@main"},
            "artifact": {"expected_artifact_name": "other"},
            "push_pr": {
                "event_name": "push",
                "workflow_ref": "markheck-solutions/governance/.github/workflows/governance-shadow.yml@refs/heads/main",
            },
            "dispatch_sha": {
                "event_name": "workflow_dispatch",
                "pull_request_number": None,
                "workflow_ref": "markheck-solutions/governance/.github/workflows/governance-shadow.yml@refs/heads/main",
            },
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(BOOTSTRAP.BootstrapError):
                    BOOTSTRAP._validated_shadow_context(
                        self._shadow_context(**mutation)
                    )

    def test_phase1_shadow_failure_receipt_is_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            context = self._shadow_context()
            args = type(
                "Args",
                (),
                {
                    "base_sha": context["base_sha"],
                    "evaluator_sha": context["head_sha"],
                    "governance_root": paths["governance"],
                    "workspace_root": paths["workspace"],
                    "runtime_root": paths["runtime"],
                },
            )()
            receipt = BOOTSTRAP.failure_receipt(args, context, [], "reproduced failure")

            validate_named("governance_toolchain_shadow_receipt", receipt, ROOT)
            BOOTSTRAP.validate_receipt(paths["governance"], receipt, context)

    def test_supportability_evaluation_context_is_separate_and_bound(self) -> None:
        context = self._evaluation_context()

        validated, kind = BOOTSTRAP._validated_context(context)

        self.assertEqual(kind, "SUPPORTABILITY_EVALUATION")
        self.assertEqual(validated, context)
        self.assertNotIn("base_sha", validated)
        self.assertEqual(validated["target_base_sha"], "b" * 40)
        self.assertEqual(validated["target_head_sha"], "c" * 40)

        merge_group = self._evaluation_context(
            event_name="merge_group", event_action="checks_requested"
        )
        self.assertEqual(
            BOOTSTRAP._validated_evaluation_context(merge_group), merge_group
        )

    def test_supportability_evaluation_context_fails_closed(self) -> None:
        cases = {
            "kind": {"context_kind": "PUBLICATION"},
            "event": {"event_name": "pull_request"},
            "action": {"event_action": "closed"},
            "attempt": {"run_attempt": "2"},
            "target_base": {"target_base_sha": "not-a-sha"},
            "target_head": {"target_head_sha": "not-a-sha"},
            "evaluator": {"evaluator_sha": "not-a-sha"},
            "workflow": {"workflow_ref": "owner/repo/.github/workflows/evil.yml@main"},
            "artifact": {"expected_artifact_name": "bad/name"},
        }
        for name, mutation in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(BOOTSTRAP.BootstrapError):
                    BOOTSTRAP._validated_evaluation_context(
                        self._evaluation_context(**mutation)
                    )

    def test_supportability_evaluation_accepts_valid_custom_artifact_name(self) -> None:
        context = self._evaluation_context(expected_artifact_name="custom.evidence-71")

        self.assertEqual(BOOTSTRAP._validated_evaluation_context(context), context)

    def test_context_validation_preserves_copy_order_and_bool_pr(self) -> None:
        context = self._evaluation_context()
        validated = BOOTSTRAP._validated_evaluation_context(context)
        self.assertEqual(validated, context)
        self.assertIsNot(validated, context)
        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "context kind"):
            BOOTSTRAP._validated_evaluation_context(
                self._evaluation_context(context_kind="bad", repository="bad")
            )
        shadow = self._shadow_context(pull_request_number=True)
        self.assertEqual(BOOTSTRAP._validated_shadow_context(shadow), shadow)

    def test_supportability_evaluation_failure_receipt_is_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            context = self._evaluation_context()
            receipt: dict[str, object] = {
                **context,
                "schema_version": "1.0",
                "status": "FAIL",
                "decision": "BLOCK_TECHNICAL",
                "base_sha": "a" * 40,
                "claimed_base_sha": "a" * 40,
                "head_sha": "a" * 40,
                "claimed_evaluator_sha": "a" * 40,
                "checkout_head_sha": None,
                "merge_base_sha": None,
                "lock_sha256": None,
                "governance_root": str(paths["governance"]),
                "workspace_root": str(paths["workspace"]),
                "git_executable": None,
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
            BOOTSTRAP._attach_payload_sha256(receipt)

            validate_named("governance_toolchain_evaluation_receipt", receipt, ROOT)
            BOOTSTRAP.validate_receipt(paths["governance"], receipt, context)

    def test_repository_lock_is_exact_and_cross_platform(self) -> None:
        digest = BOOTSTRAP.validate_lock(ROOT / "requirements-governance.lock")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")

    def test_lock_rejects_missing_hash(self) -> None:
        self._assert_lock_rejected(
            self._valid_lock().replace(
                " \\\n"
                "    --hash=sha256:d4b8d9a2f0f12b816b50447f6eccb9f4bb01a6b82c86b50fb3b5354b458dc6d3\n",
                "\n",
                1,
            ),
            "hash count",
        )

    def test_lock_rejects_extra_package_or_install_option(self) -> None:
        self._assert_lock_rejected(
            self._valid_lock() + "black==26.1.0 --hash=sha256:" + "0" * 64 + "\n",
            "exact approved requirements",
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
                self.assertIsInstance(evidence, list)
                git_stdout = self._bound_git_stdout(command, paths["governance"])
                if git_stdout is not None:
                    stdout = git_stdout
                elif "-c" in command:
                    stdout = json.dumps(
                        {
                            "origin": str(module_origin),
                            "version": BOOTSTRAP.RUFF_VERSION,
                        },
                        sort_keys=True,
                    )
                elif command[-2:] == ("ruff", "--version"):
                    stdout = f"ruff {BOOTSTRAP.RUFF_VERSION}\n"
                elif command[-2:] == ("mypy", "--version"):
                    stdout = f"mypy {BOOTSTRAP.MYPY_VERSION} (compiled: yes)\n"
                else:
                    stdout = ""
                evidence.append(
                    {
                        "command": list(command),
                        "started_at": "2026-07-16T00:00:00Z",
                        "completed_at": "2026-07-16T00:00:01Z",
                        "timeout_seconds": kwargs["timeout_seconds"],
                        "timed_out": False,
                        "exit_code": 0,
                        "stdout_sha256": BOOTSTRAP._stream_sha256(stdout),
                        "stderr_sha256": BOOTSTRAP._stream_sha256(""),
                    }
                )
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
                    expected_context=self._expected_context(),
                )

            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["decision"], "TOOLCHAIN_READY")
            self.assertEqual(receipt["base_sha"], "b" * 40)
            self.assertEqual(receipt["head_sha"], "a" * 40)
            self.assertEqual(receipt["evaluator_sha"], "a" * 40)
            self.assertEqual(receipt["checkout_head_sha"], "a" * 40)
            self.assertEqual(receipt["merge_base_sha"], "c" * 40)
            self._assert_expected_context(receipt)
            self.assertEqual(receipt["python_version"], "3.12.13")
            self.assertEqual(receipt["packages"], BOOTSTRAP.toolchain_packages())
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
            self.assertEqual(commands[-2][-3:], ("-m", "ruff", "--version"))
            self.assertEqual(commands[-1][-3:], ("-m", "mypy", "--version"))
            self.assertEqual(
                receipt["commands"][0]["stdout_sha256"],
                BOOTSTRAP._stream_sha256(paths["governance"].as_posix()),
            )
            for environment in environments:
                self.assertNotIn("GH_TOKEN", environment)
                self.assertNotIn("GITHUB_TOKEN", environment)
                self.assertNotIn("PIP_INDEX_URL", environment)

            mutations = (
                ("identity", lambda item: item.__setitem__("evaluator_sha", "c" * 40)),
                ("Python", lambda item: item.__setitem__("python_version", "0.0.0")),
                ("package", lambda item: item.__setitem__("packages", [])),
                ("commands", lambda item: item.__setitem__("commands", [])),
                (
                    "Git executable",
                    lambda item: item["commands"][0]["command"].__setitem__(0, "evil"),
                ),
                (
                    "pip hardening",
                    lambda item: item["commands"][6]["command"].remove("--no-deps"),
                ),
                (
                    "command observation",
                    lambda item: item["commands"][0].__setitem__(
                        "stdout_sha256", "0" * 64
                    ),
                ),
                ("lock digest", lambda item: item.__setitem__("lock_sha256", "0" * 64)),
                (
                    "merge base",
                    lambda item: item.__setitem__("merge_base_sha", "e" * 40),
                ),
                (
                    "runtime path",
                    lambda item: item.__setitem__(
                        "python_path", str(Path(tmp) / "evil")
                    ),
                ),
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
                        BOOTSTRAP.validate_receipt(
                            paths["governance"], invalid, self._expected_context()
                        )

            context_mutations = (
                {"repository": "markheck-solutions/other"},
                {"repository_id": "99"},
                {"head_repository_id": "98"},
                {"pull_request_number": 53},
                {"base_sha": "e" * 40},
                {"head_sha": "f" * 40},
                {
                    "workflow_ref": "markheck-solutions/governance/.github/workflows/other.yml@main"
                },
                {"workflow_sha": "1" * 40},
                {
                    "run_id": "987654321",
                    "expected_artifact_name": "governance-toolchain-publication-987654321-1",
                },
                {
                    "run_attempt": "2",
                    "expected_artifact_name": "governance-toolchain-publication-123456789-2",
                },
            )
            for mutation in context_mutations:
                with self.subTest(authoritative_context=mutation):
                    with self.assertRaisesRegex(
                        BOOTSTRAP.BootstrapError, "context mismatch"
                    ):
                        BOOTSTRAP.validate_receipt(
                            paths["governance"],
                            receipt,
                            self._expected_context(**mutation),
                        )

            shutil.rmtree(paths["runtime"])
            BOOTSTRAP.validate_receipt(
                paths["governance"], receipt, self._expected_context()
            )
            with self.assertRaises(OSError):
                BOOTSTRAP.validate_live_receipt(
                    paths["governance"], receipt, self._expected_context()
                )

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
                            expected_context=self._expected_context(
                                head_sha=str(options.get("evaluator_sha", "a" * 40))
                            ),
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
                            expected_context=self._expected_context(),
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
                        expected_context=self._expected_context(),
                    )


class ToolchainBootstrapCommandTests(_ToolchainBootstrapTestCase):
    def test_dispatch_context_cannot_authorize_publication(self) -> None:
        context = self._expected_context(
            event_name="workflow_dispatch", pull_request_number=None
        )
        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "event name"):
            BOOTSTRAP._validated_publication_context(context)

    def test_portable_command_reconstruction_uses_receipt_path_flavor(self) -> None:
        cases = (
            (
                "Linux evidence",
                "Linux",
                "/usr/bin/git",
                "/home/runner/work/governance/governance",
                "/tmp/governance-toolchain/bin/python",
                "/home/runner/work/governance/governance/requirements-governance.lock",
            ),
            (
                "Windows evidence",
                "Windows",
                r"C:\Program Files\Git\cmd\git.exe",
                r"C:\repos\governance",
                r"C:\temp\governance-toolchain\Scripts\python.exe",
                r"C:\repos\governance\requirements-governance.lock",
            ),
        )
        for name, system, git, governance, python_path, lock_path in cases:
            with self.subTest(name=name):
                receipt = {
                    "platform_system": system,
                    "git_executable": git,
                    "governance_root": governance,
                    "base_sha": "b" * 40,
                    "evaluator_sha": "a" * 40,
                    "python_path": python_path,
                }
                commands = BOOTSTRAP._expected_success_commands(receipt)
                self.assertEqual(commands[0][0:3], (git, "-C", governance))
                self.assertEqual(commands[5][0], python_path)
                self.assertEqual(commands[6][-1], lock_path)

    def test_artifact_binding_rejects_stale_or_mismatched_github_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            receipt = self._valid_failure_receipt(paths)
            paths["receipt"].write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            artifact_name = str(self._expected_context()["expected_artifact_name"])
            artifact_url = (
                "https://github.com/markheck-solutions/governance/"
                "actions/runs/123456789/artifacts/456"
            )
            binding = BOOTSTRAP.create_artifact_binding(
                paths["governance"],
                paths["receipt"],
                receipt,
                self._expected_context(),
                artifact_id="456",
                artifact_name=artifact_name,
                artifact_url=artifact_url,
                artifact_digest="a" * 64,
            )
            validate_named("governance_toolchain_artifact_binding", binding, ROOT)
            authority: dict[str, object] = {
                "artifact_id": "456",
                "artifact_name": artifact_name,
                "artifact_digest": f"sha256:{'a' * 64}",
                "expired": False,
                "workflow_run_id": "123456789",
                "workflow_run_attempt": "1",
                "repository": "markheck-solutions/governance",
                "repository_id": "1280677092",
                "head_repository_id": "1280677092",
                "head_sha": "a" * 40,
                "event_name": "pull_request",
                "pull_request_number": 52,
            }
            BOOTSTRAP.validate_artifact_binding(
                paths["governance"],
                receipt,
                paths["receipt"].read_bytes(),
                binding,
                self._expected_context(),
                authority,
            )

            mutations = (
                ("artifact_id", "457"),
                ("artifact_name", "other-artifact"),
                ("artifact_digest", f"sha256:{'b' * 64}"),
                ("expired", True),
                ("workflow_run_id", "987654321"),
                ("workflow_run_attempt", "2"),
                ("repository", "markheck-solutions/other"),
                ("repository_id", "99"),
                ("head_repository_id", "98"),
                ("head_sha", "b" * 40),
                ("pull_request_number", 53),
            )
            for key, value in mutations:
                with self.subTest(authority_field=key):
                    changed = dict(authority)
                    changed[key] = value
                    with self.assertRaises(BOOTSTRAP.BootstrapError):
                        BOOTSTRAP.validate_artifact_binding(
                            paths["governance"],
                            receipt,
                            paths["receipt"].read_bytes(),
                            binding,
                            self._expected_context(),
                            changed,
                        )

            missing = dict(authority)
            missing.pop("artifact_id")
            with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "metadata fields"):
                BOOTSTRAP.validate_artifact_binding(
                    paths["governance"],
                    receipt,
                    paths["receipt"].read_bytes(),
                    binding,
                    self._expected_context(),
                    missing,
                )

            tampered_receipt = (
                paths["receipt"]
                .read_bytes()
                .replace(b"reproduced failure", b"different failure")
            )
            with self.assertRaisesRegex(
                BOOTSTRAP.BootstrapError, "bound receipt bytes"
            ):
                BOOTSTRAP.validate_artifact_binding(
                    paths["governance"],
                    receipt,
                    tampered_receipt,
                    binding,
                    self._expected_context(),
                    authority,
                )

            binding_mutations = (
                ("artifact_id", "457"),
                (
                    "artifact_url",
                    (
                        "https://github.com/markheck-solutions/governance/"
                        "actions/runs/987654321/artifacts/456"
                    ),
                ),
                ("receipt_file_sha256", "b" * 64),
                ("receipt_payload_sha256", "c" * 64),
            )
            for key, value in binding_mutations:
                with self.subTest(binding_field=key):
                    changed_binding = dict(binding)
                    changed_binding[key] = value
                    changed_binding["payload_sha256"] = BOOTSTRAP._payload_sha256(
                        changed_binding
                    )
                    with self.assertRaises(BOOTSTRAP.BootstrapError):
                        BOOTSTRAP.validate_artifact_binding(
                            paths["governance"],
                            receipt,
                            paths["receipt"].read_bytes(),
                            changed_binding,
                            self._expected_context(),
                            authority,
                        )

    def test_artifact_binding_rejects_invalid_upload_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            receipt = self._valid_failure_receipt(paths)
            paths["receipt"].write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            valid = {
                "artifact_id": "456",
                "artifact_name": "governance-toolchain-publication-123456789-1",
                "artifact_url": (
                    "https://github.com/markheck-solutions/governance/"
                    "actions/runs/123456789/artifacts/456"
                ),
                "artifact_digest": "a" * 64,
            }
            cases = (
                {"artifact_id": "0"},
                {"artifact_name": "other"},
                {"artifact_url": "https://example.invalid/artifact/456"},
                {"artifact_digest": "not-a-digest"},
            )
            for mutation in cases:
                with self.subTest(upload_assignment=mutation):
                    assigned = {**valid, **mutation}
                    with self.assertRaises(BOOTSTRAP.BootstrapError):
                        BOOTSTRAP.create_artifact_binding(
                            paths["governance"],
                            paths["receipt"],
                            receipt,
                            self._expected_context(),
                            **assigned,
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
                **self._expected_context(),
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
                "governance_root": str(paths["governance"]),
                "workspace_root": str(paths["workspace"]),
                "git_executable": None,
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

    def test_receipt_schema_requires_empty_or_exact_toolchain_packages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._provision_paths(Path(tmp))
            args = type(
                "Args",
                (),
                {
                    "base_sha": "a" * 40,
                    "evaluator_sha": "a" * 40,
                    "governance_root": paths["governance"],
                    "workspace_root": paths["workspace"],
                    "runtime_root": paths["runtime"],
                },
            )()
            receipts = (
                ("governance_toolchain_receipt", self._valid_failure_receipt(paths)),
                (
                    "governance_toolchain_evaluation_receipt",
                    BOOTSTRAP.failure_receipt(
                        args, self._evaluation_context(), [], "reproduced failure"
                    ),
                ),
                (
                    "governance_toolchain_shadow_receipt",
                    BOOTSTRAP.failure_receipt(
                        args, self._shadow_context(), [], "reproduced failure"
                    ),
                ),
            )

            cases = (
                (
                    "mismatched version",
                    lambda item: item.__setitem__("version", "2.2.0"),
                ),
                (
                    "missing package",
                    lambda item: item.__setitem__("packages", item["packages"][:-1]),
                ),
                (
                    "duplicate package",
                    lambda item: item.__setitem__(
                        "packages", item["packages"][:-1] + [item["packages"][0]]
                    ),
                ),
            )
            for schema_name, receipt in receipts:
                with self.subTest(schema=schema_name, packages="empty"):
                    validate_named(schema_name, receipt, ROOT)

                receipt["packages"] = BOOTSTRAP.toolchain_packages()
                with self.subTest(schema=schema_name, packages="exact"):
                    validate_named(schema_name, receipt, ROOT)

                for name, mutate in cases:
                    with self.subTest(schema=schema_name, mutation=name):
                        invalid = json.loads(json.dumps(receipt))
                        mutate(invalid)
                        with self.assertRaises(SchemaValidationError):
                            validate_named(schema_name, invalid, ROOT)

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
                        "stdout_sha256": None,
                        "stderr_sha256": None,
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
                *self._context_argv(),
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
            BOOTSTRAP.validate_receipt(
                paths["governance"], receipt, self._expected_context()
            )
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
                *self._context_argv(),
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
            BOOTSTRAP.validate_receipt(
                paths["governance"], receipt, self._expected_context()
            )
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
                        *self._context_argv(),
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


if __name__ == "__main__":
    unittest.main()
