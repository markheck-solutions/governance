from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from governance_eval import architecture_policy
from governance_eval import supportability


REPO_ROOT = Path(__file__).resolve().parents[1]


class SelfUpdatePolicyTests(unittest.TestCase):
    def test_unique_noop_gate_replacements_are_rejected(self) -> None:
        base = _config()
        head = copy.deepcopy(base)
        for index, gate in enumerate(supportability.REQUIRED_COMMAND_GATES, start=1):
            head["required_gates"][gate] = [f'python -c "pass # {index}"']

        errors = supportability._supportability_config_weakening_errors(base, head)

        self.assertTrue(
            any("lacks required capability semantics" in error for error in errors)
        )

    def test_shell_masking_after_valid_commands_is_rejected(self) -> None:
        base = _config()
        for suffix in (
            "; true",
            " & true",
        ):
            with self.subTest(suffix=suffix):
                head = copy.deepcopy(base)
                head["required_gates"].update(_semantic_gate_commands(suffix))

                errors = supportability._supportability_config_weakening_errors(
                    base, head
                )

                self.assertTrue(errors)

    def test_help_and_collection_only_modes_are_rejected(self) -> None:
        base = _config()
        head = copy.deepcopy(base)
        commands = _semantic_gate_commands("")
        for gate in commands:
            commands[gate][0] += " --collect-only" if gate == "tests" else " --help"
        head["required_gates"].update(commands)

        errors = supportability._supportability_config_weakening_errors(base, head)

        self.assertTrue(any("non-execution mode" in error for error in errors))

    def test_structural_judge_surfaces_are_protected(self) -> None:
        for checker in (
            "governance_eval/supportability.py",
            "governance_eval/trusted_command.py",
            "governance_eval/architecture_policy.py",
            "governance_eval/future/nested_evaluator.py",
            "governance_eval/schema_data/v99/future.schema.json",
            "schemas/v99/future.schema.json",
            ".github/actions/future-toolchain/action.yml",
            ".github/workflows/future-reusable.yml",
            "pyproject.toml",
            "requirements-governance.lock",
        ):
            with self.subTest(checker=checker), tempfile.TemporaryDirectory() as tmp:
                errors = supportability._architecture_governance_change_errors(
                    Path(tmp),
                    [checker],
                    "a" * 40,
                )

                self.assertTrue(supportability._is_protected_judge_path(checker))
                self.assertTrue(errors)

    def test_special_and_ordinary_paths_are_not_generic_judge_surfaces(self) -> None:
        for path in (
            ".github/governance/supportability.yml",
            ".github/workflows/supportability-enforcement.yml",
            "README.md",
            "governance_eval_evil/future.py",
            "schemas-old/future.json",
            "tests/governance_eval/future.py",
        ):
            with self.subTest(path=path):
                self.assertFalse(supportability._is_protected_judge_path(path))

    def test_protected_judge_change_does_not_require_test_file_churn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow = repo / ".github/workflows/supportability-enforcement.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                (
                    REPO_ROOT / ".github/workflows/supportability-enforcement.yml"
                ).read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            errors = supportability._architecture_governance_change_errors(
                repo,
                ["governance_eval/future.py"],
                "a" * 40,
            )

        self.assertEqual(errors, [])

    def test_architecture_runner_transition_is_exact_workflow_change(self) -> None:
        base = (REPO_ROOT / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        head = base.replace(
            architecture_policy._ARCHITECTURE_WORKFLOW_BASE_COMMAND,
            architecture_policy._ARCHITECTURE_WORKFLOW_PINNED_COMMAND,
            1,
        )

        self.assertTrue(
            architecture_policy.architecture_workflow_transition_allowed(base, head)
        )
        self.assertEqual(
            hashlib.sha256(base.encode()).hexdigest(),
            architecture_policy._ARCHITECTURE_WORKFLOW_TRANSITION_SHA256[0],
        )
        self.assertEqual(
            hashlib.sha256(head.encode()).hexdigest(),
            architecture_policy._ARCHITECTURE_WORKFLOW_TRANSITION_SHA256[1],
        )

    def test_architecture_runner_transition_rejects_companion_workflow_change(
        self,
    ) -> None:
        base = (REPO_ROOT / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        head = base.replace(
            architecture_policy._ARCHITECTURE_WORKFLOW_BASE_COMMAND,
            architecture_policy._ARCHITECTURE_WORKFLOW_PINNED_COMMAND,
            1,
        ).replace("permissions:\n  actions: read", "permissions:\n  actions: write", 1)

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow = repo / ".github/workflows/supportability-gate.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(head, encoding="utf-8")
            with mock.patch(
                "governance_eval.supportability._git_show_text", return_value=base
            ):
                errors = supportability._architecture_governance_change_errors(
                    repo,
                    [".github/workflows/supportability-gate.yml"],
                    "a" * 40,
                )

        self.assertTrue(
            any(
                "architecture gate workflow command changed" in error
                for error in errors
            )
        )

    def test_config_migration_must_not_ship_shadowing_code(self) -> None:
        head = _config()
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch(
                "governance_eval.supportability._base_supportability_config"
            ) as load_base,
        ):
            trusted, errors = supportability._trusted_execution_config(
                Path(tmp) / ".github/governance/supportability.yml",
                Path(tmp),
                [".github/governance/supportability.yml", "ruff.py"],
                "a" * 40,
                head,
            )

        self.assertIs(trusted, head)
        self.assertTrue(any("must be isolated" in error for error in errors))
        load_base.assert_not_called()

    def test_delivery_chain_rejects_comment_only_fake_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow = repo / ".github/workflows/supportability-enforcement.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                "#  baseline-supportability:\n"
                "#    uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@"
                + "1"
                * 40
                + "\n#  candidate-supportability:\n"
                "#    uses: ./.github/workflows/supportability-gate.yml\n"
                "#  delivery-receipt:\n"
                "#    uses: markheck-solutions/governance/.github/workflows/delivery-receipt.yml@"
                + "1" * 40
                + "\n",
                encoding="utf-8",
            )

            errors = supportability._protected_delivery_chain_errors(repo)

        for job in (
            "baseline-supportability",
            "candidate-supportability",
            "delivery-receipt",
        ):
            self.assertTrue(any(f"missing {job}" in error for error in errors))

    def test_enforcement_pin_rotation_must_target_trusted_base_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow = repo / ".github/workflows/supportability-enforcement.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text(
                _protected_enforcement_workflow("2" * 40), encoding="utf-8"
            )
            with mock.patch(
                "governance_eval.supportability._git_show_text",
                return_value=_protected_enforcement_workflow("1" * 40),
            ):
                rejected = supportability._protected_enforcement_change_errors(
                    repo, "3" * 40, ".github/workflows/supportability-enforcement.yml"
                )
                accepted = supportability._protected_enforcement_change_errors(
                    repo, "2" * 40, ".github/workflows/supportability-enforcement.yml"
                )

        self.assertTrue(any("trusted base SHA" in error for error in rejected))
        self.assertEqual(accepted, [])

    def test_receipt_activation_matches_reviewed_digest(self) -> None:
        activated = _activated_enforcement_workflow("2" * 40)

        self.assertEqual(activated.count("2" * 40), 6)
        self.assertEqual(
            hashlib.sha256(
                _normalized_enforcement_workflow(activated).encode()
            ).hexdigest(),
            supportability._ENFORCEMENT_RECEIPT_TRANSITION_SHA256[1],
        )

    def test_receipt_activation_records_exact_transport_execution(self) -> None:
        expected_command = [
            "gh",
            "api",
            "--method",
            "POST",
            "repos/owner/repo/issues/31/comments",
            "-f",
            "body=@codex review\n\nGovernance review request for exact head "
            f"`{'a' * 40}`.",
        ]
        cases = (
            (
                subprocess.CompletedProcess(
                    expected_command,
                    0,
                    stdout=b'{"id":201,"created_at":"2026-07-17T13:32:58Z"}',
                    stderr=b"",
                ),
                "POSTED",
                "false",
                "0",
                "",
            ),
            (
                subprocess.CompletedProcess(
                    expected_command, 1, stdout=b"", stderr=b"unavailable"
                ),
                "TRANSPORT_UNAVAILABLE",
                "false",
                "1",
                "sha256:" + hashlib.sha256(b"unavailable").hexdigest(),
            ),
            (
                subprocess.CompletedProcess(
                    expected_command, 124, stdout=b"", stderr=b"child exit 124"
                ),
                "TRANSPORT_UNAVAILABLE",
                "false",
                "124",
                "sha256:" + hashlib.sha256(b"child exit 124").hexdigest(),
            ),
            (
                subprocess.TimeoutExpired(expected_command, 30, stderr=b"deadline"),
                "TRANSPORT_UNAVAILABLE",
                "true",
                "124",
                "sha256:"
                + hashlib.sha256(
                    b"deadline\nrequest timed out after 30 seconds"
                ).hexdigest(),
            ),
        )
        for transport, outcome, timed_out, exit_code, error_digest in cases:
            with self.subTest(outcome=outcome, timed_out=timed_out):
                outputs, run = _execute_request_fixture(transport)
                self.assertEqual(
                    json.loads(outputs["request-transport-command-json"]),
                    expected_command,
                )
                self.assertEqual(outputs["request-transport-timeout-seconds"], "30")
                self.assertEqual(outputs["request-transport-timed-out"], timed_out)
                self.assertEqual(outputs["request-transport-exit-code"], exit_code)
                self.assertEqual(outputs["request-outcome"], outcome)
                self.assertEqual(
                    outputs["request-transport-error-sha256"], error_digest
                )
                self.assertEqual(
                    outputs["request-response-validation-error-sha256"], ""
                )
                self.assertRegex(
                    outputs["request-transport-started-at"],
                    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                )
                self.assertGreaterEqual(
                    outputs["request-transport-completed-at"],
                    outputs["request-transport-started-at"],
                )
                run.assert_called_once_with(
                    expected_command,
                    check=False,
                    capture_output=True,
                    timeout=30,
                )

    def test_receipt_activation_records_invalid_success_response(self) -> None:
        cases = (
            (b"\xff", "INVALID_UTF8"),
            (b"{", "INVALID_JSON"),
            (b"[]", "RESPONSE_NOT_OBJECT"),
            (
                b'{"created_at":"2026-07-17T13:32:58Z"}',
                "INVALID_COMMENT_ID",
            ),
            (
                b'{"id":201,"created_at":"not-a-time"}',
                "INVALID_COMMENT_CREATED_AT",
            ),
        )
        for stdout, failure_code in cases:
            with self.subTest(failure_code=failure_code):
                malformed = subprocess.CompletedProcess(
                    [], 0, stdout=stdout, stderr=b""
                )
                outputs, _ = _execute_request_fixture(malformed)
                expected_digest = (
                    "sha256:"
                    + hashlib.sha256(
                        failure_code.encode("ascii") + b"\0" + stdout
                    ).hexdigest()
                )

                self.assertEqual(outputs["request-outcome"], "RESPONSE_INVALID")
                self.assertEqual(outputs["request-transport-exit-code"], "0")
                self.assertEqual(outputs["request-transport-error-sha256"], "")
                self.assertEqual(
                    outputs["request-response-validation-error-sha256"],
                    expected_digest,
                )
                self.assertEqual(outputs["request-comment-id"], "")
                self.assertEqual(outputs["request-comment-created-at"], "")

    def test_receipt_activation_records_process_launch_failures(self) -> None:
        cases = (
            (
                FileNotFoundError(errno.ENOENT, "missing", "first-gh"),
                "FILE_NOT_FOUND",
                str(errno.ENOENT),
            ),
            (
                PermissionError(errno.EACCES, "denied", "gh"),
                "PERMISSION_DENIED",
                str(errno.EACCES),
            ),
            (
                OSError(errno.ENOEXEC, "bad executable", "gh"),
                "EXEC_FORMAT_ERROR",
                str(errno.ENOEXEC),
            ),
            (OSError("localized message"), "OTHER_OS_ERROR", "NONE"),
        )
        digests = set()
        for failure, category, error_number in cases:
            with self.subTest(category=category):
                outputs, run = _execute_request_fixture(failure)
                canonical_error = (
                    f"PROCESS_LAUNCH_OS_ERROR_V1\0{category}\0errno={error_number}"
                ).encode("ascii")
                expected_digest = (
                    "sha256:" + hashlib.sha256(canonical_error).hexdigest()
                )

                self.assertEqual(outputs["request-outcome"], "TRANSPORT_UNAVAILABLE")
                self.assertEqual(outputs["request-transport-exit-code"], "")
                self.assertEqual(outputs["request-transport-timed-out"], "false")
                self.assertEqual(
                    outputs["request-transport-error-sha256"], expected_digest
                )
                self.assertEqual(
                    outputs["request-response-validation-error-sha256"], ""
                )
                self.assertEqual(outputs["request-comment-id"], "")
                self.assertEqual(outputs["request-comment-created-at"], "")
                run.assert_called_once()
                digests.add(expected_digest)

        same_failure, _ = _execute_request_fixture(
            FileNotFoundError(errno.ENOENT, "different message", "other-gh")
        )
        canonical_file_not_found = (
            f"PROCESS_LAUNCH_OS_ERROR_V1\0FILE_NOT_FOUND\0errno={errno.ENOENT}"
        ).encode("ascii")
        self.assertEqual(
            same_failure["request-transport-error-sha256"],
            "sha256:" + hashlib.sha256(canonical_file_not_found).hexdigest(),
        )
        self.assertEqual(len(digests), len(cases))

    def test_receipt_activation_normalizes_signal_termination(self) -> None:
        stderr = b"terminated"
        signaled = subprocess.CompletedProcess([], -15, stdout=b"", stderr=stderr)

        outputs, _ = _execute_request_fixture(signaled)

        marker = (
            b"\nrequest terminated by signal 15; raw returncode -15; "
            b"normalized exit code 143"
        )
        self.assertEqual(outputs["request-outcome"], "TRANSPORT_UNAVAILABLE")
        self.assertEqual(outputs["request-transport-exit-code"], "143")
        self.assertEqual(outputs["request-transport-timed-out"], "false")
        self.assertEqual(
            outputs["request-transport-error-sha256"],
            "sha256:" + hashlib.sha256(stderr + marker).hexdigest(),
        )
        self.assertEqual(outputs["request-comment-id"], "")
        self.assertEqual(outputs["request-comment-created-at"], "")

        impossible = subprocess.CompletedProcess([], -128, stdout=b"", stderr=b"")
        with self.assertRaises(SystemExit):
            _execute_request_fixture(impossible)

    def test_exact_legacy_to_receipt_activation_is_accepted(self) -> None:
        trusted_sha = "2" * 40

        errors = _enforcement_change_errors(
            _current_enforcement_workflow(),
            _activated_enforcement_workflow(trusted_sha),
            trusted_sha,
        )

        self.assertEqual(errors, [])

    def test_receipt_activation_rejects_any_unreviewed_byte_drift(self) -> None:
        activated = _activated_enforcement_workflow("2" * 40)
        mutations = {
            "timeout": activated.replace("timeout=30", "timeout=31", 1),
            "run-attempt guard": activated.replace(
                'if os.environ["RUN_ATTEMPT"] != "1":', "if False:", 1
            ),
            "output mapping": activated.replace(
                "outputs['request-outcome']",
                "outputs['request-comment-id']",
                1,
            ),
            "permission": activated.replace(
                "  pull-requests: read\n\njobs:",
                "  pull-requests: read\n  checks: write\n\njobs:",
                1,
            ),
            "trigger": activated.replace(
                "      - ready_for_review",
                "      - ready_for_review\n      - converted_to_draft",
                1,
            ),
            "second post": activated.replace(
                "              completed = subprocess.run(\n",
                "              subprocess.run(\n"
                "                  command, check=False, capture_output=True, timeout=30\n"
                "              )\n"
                "              completed = subprocess.run(\n",
                1,
            ),
            "extra step": activated.replace(
                "    steps:\n      - name: Request exact-head Codex review",
                "    steps:\n      - run: echo extra\n"
                "      - name: Request exact-head Codex review",
                1,
            ),
        }

        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated, activated)
                errors = _enforcement_change_errors(
                    _current_enforcement_workflow(), mutated, "2" * 40
                )
                self.assertEqual(
                    errors,
                    [
                        "protected enforcement workflow change is not an exact "
                        "SHA pin rotation"
                    ],
                )

    def test_receipt_activation_rejects_unreviewed_base(self) -> None:
        errors = _enforcement_change_errors(
            _current_enforcement_workflow() + "# unreviewed base\n",
            _activated_enforcement_workflow("2" * 40),
            "2" * 40,
        )

        self.assertEqual(
            errors,
            ["protected enforcement workflow change is not an exact SHA pin rotation"],
        )

    def test_receipt_activation_pins_must_target_trusted_base_sha(self) -> None:
        errors = _enforcement_change_errors(
            _current_enforcement_workflow(),
            _activated_enforcement_workflow("2" * 40),
            "3" * 40,
        )

        self.assertIn(
            "protected enforcement workflow pins must equal trusted base SHA", errors
        )

    def test_receipt_activation_rejects_symlinked_protected_caller(self) -> None:
        with mock.patch.object(Path, "is_symlink", return_value=True):
            errors = _enforcement_change_errors(
                _current_enforcement_workflow(),
                _activated_enforcement_workflow("2" * 40),
                "2" * 40,
            )

        self.assertEqual(
            errors,
            ["protected enforcement workflow base or head is missing or non-regular"],
        )

    def test_post_activation_change_is_limited_to_pin_rotation(self) -> None:
        errors = _enforcement_change_errors(
            _activated_enforcement_workflow("2" * 40),
            _activated_enforcement_workflow("3" * 40),
            "3" * 40,
        )

        self.assertEqual(errors, [])

    def test_delivery_chain_rejects_disabled_or_wrong_reusable_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            workflow = repo / ".github/workflows/supportability-enforcement.yml"
            workflow.parent.mkdir(parents=True)
            disabled = _protected_enforcement_workflow("1" * 40).replace(
                _pull_request_condition(), "${{ false }}", 1
            )
            workflow.write_text(disabled, encoding="utf-8")
            disabled_errors = supportability._protected_delivery_chain_errors(repo)
            workflow.write_text(
                _protected_enforcement_workflow("1" * 40).replace(
                    "supportability-gate.yml", "noop.yml", 1
                ),
                encoding="utf-8",
            )
            wrong_workflow_errors = supportability._protected_delivery_chain_errors(
                repo
            )

        self.assertTrue(any("condition" in error for error in disabled_errors))
        self.assertTrue(
            any(
                "exact supportability-gate.yml" in error
                for error in wrong_workflow_errors
            )
        )


def _config() -> dict[str, Any]:
    gates: dict[str, Any] = {
        gate: ["python -c pass"] for gate in supportability.REQUIRED_COMMAND_GATES
    }
    gates.update({"package_audit": [], "sql_supportability": "auto"})
    return {
        "standard": {"name": "standard", "source": "standard.md", "hash": "a" * 64},
        "required_gates": gates,
        "coverage": {
            "changed_files": "all",
            "high_risk_files": "all",
            "forbid_gate_scope_narrowing": True,
            "forbid_threshold_weakening": True,
        },
        "ai_review": {
            "provider": "codex_connector",
            "adapter": "codex_connector_pr_signal_v2",
            "review_window_seconds": 300,
            "unavailable_after_cutoff": "non_blocking",
            "unresolved_p0_p1_p2_blocks": True,
        },
        "receipt": {"artifact_name": "receipt", "retention_days": 90},
    }


def _protected_enforcement_workflow(sha: str) -> str:
    return (
        "jobs:\n"
        "  baseline-supportability:\n"
        "    if: " + _pull_request_condition() + "\n"
        "    uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@"
        + sha
        + "\n"
        "    with:\n"
        "      governance-ref: " + sha + "\n"
        "  candidate-supportability:\n"
        "    if: " + _pull_request_condition() + "\n"
        "    uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@"
        + sha
        + "\n"
        "    with:\n"
        "      governance-ref: " + sha + "\n"
        "  delivery-receipt:\n"
        "    needs:\n"
        "      - baseline-supportability\n"
        "      - candidate-supportability\n"
        "    if: " + _delivery_condition() + "\n"
        "    uses: markheck-solutions/governance/.github/workflows/delivery-receipt.yml@"
        + sha
        + "\n"
        "    with:\n"
        "      governance-ref: " + sha + "\n"
    )


def _current_enforcement_workflow() -> str:
    return (
        REPO_ROOT / "fixtures/supportability-enforcement-legacy-request.yml"
    ).read_text(encoding="utf-8")


def _activated_enforcement_workflow(sha: str) -> str:
    text = (
        REPO_ROOT / "fixtures/supportability-enforcement-receipt-activated.yml"
    ).read_text(encoding="utf-8")
    return text.replace("2" * 40, sha)


def _execute_request_fixture(
    transport: subprocess.CompletedProcess[bytes] | BaseException,
) -> tuple[dict[str, str], mock.Mock]:
    fixture = _activated_enforcement_workflow("2" * 40)
    script = textwrap.dedent(
        fixture.split("          python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[
            0
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "outputs.txt"
        environment = {
            "GITHUB_OUTPUT": str(output_path),
            "HEAD_SHA": "a" * 40,
            "REPOSITORY": "owner/repo",
            "PR_NUMBER": "31",
            "RUN_ATTEMPT": "1",
        }
        run = mock.Mock(
            side_effect=transport if isinstance(transport, BaseException) else None,
            return_value=(None if isinstance(transport, BaseException) else transport),
        )
        with (
            mock.patch.dict(os.environ, environment, clear=False),
            mock.patch("subprocess.run", run),
        ):
            exec(compile(script, "<request-fixture>", "exec"), {})
        outputs = dict(
            line.split("=", 1)
            for line in output_path.read_text(encoding="utf-8").splitlines()
        )
    return outputs, run


def _normalized_enforcement_workflow(text: str) -> str:
    text = re.sub(r"(?<=@)[0-9a-f]{40}", "<PIN>", text)
    return re.sub(
        r"(?m)(^\s+governance-ref:\s+)([0-9a-f]{40})(\s*$)",
        r"\1<PIN>\3",
        text,
    )


def _enforcement_change_errors(
    base_text: str, head_text: str, trusted_sha: str
) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        workflow = repo / ".github/workflows/supportability-enforcement.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text(head_text, encoding="utf-8")
        with mock.patch(
            "governance_eval.supportability._git_show_text", return_value=base_text
        ):
            return supportability._protected_enforcement_change_errors(
                repo,
                trusted_sha,
                ".github/workflows/supportability-enforcement.yml",
            )


def _semantic_gate_commands(suffix: str) -> dict[str, list[str]]:
    return {
        "lint": ["python -m ruff check ." + suffix],
        "format_check": ["python -m ruff format --check ." + suffix],
        "typecheck": ["python -m mypy ." + suffix],
        "complexity": ["python -m ruff check --select C901 ." + suffix],
        "architecture": ["python -m governance_eval architecture-gate" + suffix],
        "tests": ["python -m unittest discover -s tests -p test_*.py" + suffix],
        "compile_or_build": ["npm run build" + suffix],
    }


def _pull_request_condition() -> str:
    return "${{ github.event.pull_request.base.ref == 'main' }}"


def _delivery_condition() -> str:
    return "${{ always() && github.event.pull_request.base.ref == 'main' }}"


if __name__ == "__main__":
    unittest.main()
