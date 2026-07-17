from __future__ import annotations

import copy
import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

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

    def test_supportability_judge_is_a_protected_checker(self) -> None:
        for checker in (
            "governance_eval/supportability.py",
            "governance_eval/architecture_policy.py",
        ):
            with self.subTest(checker=checker), tempfile.TemporaryDirectory() as tmp:
                errors = supportability._architecture_governance_change_errors(
                    Path(tmp),
                    [checker],
                    "a" * 40,
                    Path(tmp) / ".github/governance/supportability.yml",
                )

                self.assertTrue(
                    any("protected checker change" in error for error in errors)
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
    return (REPO_ROOT / ".github/workflows/supportability-enforcement.yml").read_text(
        encoding="utf-8"
    )


def _activated_enforcement_workflow(sha: str) -> str:
    text = (
        REPO_ROOT / "fixtures/supportability-enforcement-receipt-activated.yml"
    ).read_text(encoding="utf-8")
    return text.replace("2" * 40, sha)


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
        "tests": ["python -m pytest" + suffix],
        "compile_or_build": ["python -m build" + suffix],
    }


def _pull_request_condition() -> str:
    return "${{ github.event.pull_request.base.ref == 'main' }}"


def _delivery_condition() -> str:
    return "${{ always() && github.event.pull_request.base.ref == 'main' }}"


if __name__ == "__main__":
    unittest.main()
