from __future__ import annotations

import unittest
from pathlib import Path

from governance_eval.paths import repo_root


PROTECTED_GOVERNANCE_REF = "d58e97019560183c38a0d6509e7aae0da40da356"


def _legacy_startup_receipt_strings() -> tuple[str, ...]:
    boot = "boot"
    strap = "strap"
    return (
        boot + strap + "-receipt",
        "baseline protected workflow missing " + "on main",
        "Baseline " + boot.capitalize() + strap + " Receipt Required",
        "Confirm " + boot + strap + " is still required",
        boot.capitalize() + strap + " reason",
        "remove " + boot + strap + " mode",
    )


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_required_governance_text_uses_no_banned_condition_word(self) -> None:
        banned = "un" + "less"
        checked_suffixes = {".md", ".py", ".json", ".yml", ".yaml"}
        checked_roots = ("docs", "schemas", "tests", "governance_eval", ".github")
        violations: list[str] = []
        for root_name in checked_roots:
            root = self.root / root_name
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix not in checked_suffixes:
                    continue
                if root_name == "docs" and path.name in {"GOAL.md", "02_GOAL.md", "03_GOAL.md"}:
                    continue
                text = path.read_text(encoding="utf-8")
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if banned in line.lower():
                        violations.append(f"{path.relative_to(self.root).as_posix()}:{line_number}:{line.strip()}")
        self.assertEqual(violations, [])

    def test_governance_workflows_are_read_only_nonblocking_and_retained(self) -> None:
        workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in (self.root / ".github/workflows").glob("*.yml")
        }
        self.assertIn("governance-shadow.yml", workflows)
        self.assertIn("governance-evaluate.yml", workflows)
        self.assertIn("supportability-gate.yml", workflows)
        self.assertIn("delivery-receipt.yml", workflows)
        self.assertIn("supportability-enforcement.yml", workflows)
        for text in workflows.values():
            self.assertNotIn("pull_request_target", text)
            self.assertIn("contents: read", text)
            self.assertNotIn("secrets: inherit", text)
        for name in ("governance-shadow.yml", "governance-evaluate.yml", "supportability-gate.yml", "delivery-receipt.yml"):
            self.assertIn("retention-days: 90", workflows[name])
        self.assertIn("workflow_call:", workflows["governance-evaluate.yml"])
        self.assertIn("governance-ref:", workflows["governance-evaluate.yml"])
        self.assertIn("revision-mode:", workflows["governance-evaluate.yml"])
        self.assertIn("target-pr-number:", workflows["governance-evaluate.yml"])
        self.assertIn("GOVERNANCE_CHECKOUT_REF", workflows["governance-evaluate.yml"])
        self.assertIn("validate-target-request", workflows["governance-evaluate.yml"])
        self.assertNotIn("allowed = {", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-digest", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-id", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-id", workflows["governance-shadow.yml"])
        self.assertIn("github.event.pull_request.head.sha || github.sha", workflows["governance-shadow.yml"])
        self.assertIn("review-quorum-json:", workflows["governance-shadow.yml"])
        self.assertIn("validate-review-quorum", workflows["governance-shadow.yml"])
        self.assertIn("steps.validate_quorum.conclusion == 'success'", workflows["governance-shadow.yml"])
        self.assertIn("if: success() && steps.validate_quorum.conclusion == 'success'", workflows["governance-shadow.yml"])
        self.assertIn("governance-review-quorum-json", workflows["governance-shadow.yml"])
        self.assertIn("Review quorum digest", workflows["governance-shadow.yml"])
        self.assertIn("workflow_call:", workflows["supportability-gate.yml"])
        self.assertIn("Supportability Gate", workflows["supportability-gate.yml"])
        self.assertIn("supportability-config", workflows["supportability-gate.yml"])
        self.assertIn("Validate supportability config", workflows["supportability-gate.yml"])
        self.assertIn("continue-on-error: true", workflows["supportability-gate.yml"])
        self.assertIn("supportability-gate", workflows["supportability-gate.yml"])
        self.assertIn("Run approved architecture fitness gate", workflows["supportability-gate.yml"])
        self.assertIn("python -m governance_eval architecture-gate", workflows["supportability-gate.yml"])
        self.assertIn("architecture-gate-result.json", workflows["supportability-gate.yml"])
        self.assertIn("architecture-gate-result.md", workflows["supportability-gate.yml"])
        self.assertIn("copilot-review-gate", workflows["supportability-gate.yml"])
        self.assertRegex(
            workflows["supportability-gate.yml"],
            r"(?s)- name: Run configured supportability gates.*?env:\s+GH_TOKEN: \"\".*?python -m governance_eval supportability-gate",
        )
        self.assertIn('replace("\\r", " ").replace("\\n", " ")', workflows["supportability-gate.yml"])
        self.assertIn("pull-requests: read", workflows["supportability-gate.yml"])
        self.assertIn("artifact-digest", workflows["supportability-gate.yml"])
        self.assertIn("artifact-digest: ${{ steps.upload.outputs.artifact-digest }}", workflows["supportability-gate.yml"])
        self.assertNotIn("steps.upload.outputs.digest", workflows["supportability-gate.yml"])
        self.assertIn("Fail closed on RED supportability evidence", workflows["supportability-gate.yml"])
        self.assertIn("pull_request:", workflows["supportability-enforcement.yml"])
        self.assertIn("pull_request_review:", workflows["supportability-enforcement.yml"])
        self.assertIn("baseline-supportability:", workflows["supportability-enforcement.yml"])
        self.assertIn("candidate-supportability:", workflows["supportability-enforcement.yml"])
        self.assertIn("Baseline Protected Supportability Gate", workflows["supportability-enforcement.yml"])
        for blocked_text in _legacy_startup_receipt_strings():
            for name in ("supportability-enforcement.yml", "delivery-receipt.yml"):
                self.assertNotIn(blocked_text, workflows[name])
            self.assertNotIn(blocked_text, Path(__file__).read_text(encoding="utf-8"))
        self.assertIn(
            f"uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@{PROTECTED_GOVERNANCE_REF}",
            workflows["supportability-enforcement.yml"],
        )
        self.assertNotIn(
            "uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@main",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            f"uses: markheck-solutions/governance/.github/workflows/delivery-receipt.yml@{PROTECTED_GOVERNANCE_REF}",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn("uses: ./.github/workflows/supportability-gate.yml", workflows["supportability-enforcement.yml"])
        self.assertNotIn("uses: ./.github/workflows/delivery-receipt.yml", workflows["supportability-enforcement.yml"])
        self.assertIn("artifact-name: baseline-supportability-gate-evidence", workflows["supportability-enforcement.yml"])
        self.assertIn("supportability-artifact-name: baseline-supportability-gate-evidence", workflows["supportability-enforcement.yml"])
        self.assertIn("needs['baseline-supportability'].outputs['artifact-id']", workflows["supportability-enforcement.yml"])
        self.assertIn("needs['baseline-supportability'].outputs['artifact-digest']", workflows["supportability-enforcement.yml"])
        self.assertIn("needs['candidate-supportability'].outputs['artifact-id']", workflows["supportability-enforcement.yml"])
        self.assertIn("needs['candidate-supportability'].outputs['artifact-digest']", workflows["supportability-enforcement.yml"])
        self.assertIn("missing-baseline-supportability-artifact-id", workflows["supportability-enforcement.yml"])
        self.assertIn("missing-baseline-supportability-artifact-digest", workflows["supportability-enforcement.yml"])
        self.assertIn("missing-candidate-supportability-artifact-id", workflows["supportability-enforcement.yml"])
        self.assertIn("missing-candidate-supportability-artifact-digest", workflows["supportability-enforcement.yml"])
        baseline_block, candidate_block = workflows["supportability-enforcement.yml"].split("  candidate-supportability:", 1)
        candidate_block, delivery_block = candidate_block.split("  delivery-receipt:", 1)
        self.assertNotIn("uses: ./.github/workflows/supportability-gate.yml", baseline_block)
        self.assertIn("target-base-sha: ${{ github.event.pull_request.base.sha }}", baseline_block)
        self.assertIn("target-head-sha: ${{ github.event.pull_request.head.sha }}", baseline_block)
        self.assertNotIn("governance-ref: ${{ github.event.pull_request.head.sha }}", baseline_block)
        self.assertIn("governance-ref: ${{ github.event.pull_request.base.sha }}", baseline_block)
        self.assertIn("uses: ./.github/workflows/supportability-gate.yml", candidate_block)
        self.assertIn("target-head-sha: ${{ github.event.pull_request.head.sha }}", candidate_block)
        self.assertIn("governance-ref: ${{ github.event.pull_request.head.sha }}", candidate_block)
        self.assertIn("supportability-artifact-id", delivery_block)
        self.assertIn("supportability-artifact-digest", delivery_block)
        self.assertIn("candidate-supportability-artifact-id", delivery_block)
        self.assertIn("candidate-supportability-artifact-digest", delivery_block)
        self.assertIn("governance-ref: ${{ github.event.pull_request.base.sha }}", delivery_block)
        self.assertIn("if: ${{ always() && github.event.pull_request.base.ref == 'main' }}", workflows["supportability-enforcement.yml"])
        self.assertIn("architecture_violation_count", workflows["supportability-gate.yml"])
        self.assertIn("architecture_known_debt_applied_count", workflows["supportability-gate.yml"])
        self.assertIn("architecture_expired_known_debt_count", workflows["supportability-gate.yml"])
        self.assertIn("workflow_call:", workflows["delivery-receipt.yml"])
        self.assertIn("Delivery Receipt", workflows["delivery-receipt.yml"])
        self.assertIn("gh api \"repos/${TARGET_REPOSITORY}/actions/artifacts/${SUPPORTABILITY_ARTIFACT_ID}/zip\"", workflows["delivery-receipt.yml"])
        self.assertIn('replace("\\r", " ").replace("\\n", " ")', workflows["delivery-receipt.yml"])
        self.assertIn("Record supportability artifact metadata", workflows["delivery-receipt.yml"])
        self.assertIn("id: supportability_artifact", workflows["delivery-receipt.yml"])
        self.assertIn("SUPPORTABILITY_ARTIFACT_ID", workflows["delivery-receipt.yml"])
        self.assertIn("SUPPORTABILITY_ARTIFACT_DIGEST", workflows["delivery-receipt.yml"])
        self.assertIn("CANDIDATE_SUPPORTABILITY_ARTIFACT_ID", workflows["delivery-receipt.yml"])
        self.assertIn("CANDIDATE_SUPPORTABILITY_ARTIFACT_NAME", workflows["delivery-receipt.yml"])
        self.assertIn("Download candidate supportability evidence", workflows["delivery-receipt.yml"])
        self.assertIn("/actions/artifacts/${SUPPORTABILITY_ARTIFACT_ID}/zip", workflows["delivery-receipt.yml"])
        self.assertIn("/actions/artifacts/${CANDIDATE_SUPPORTABILITY_ARTIFACT_ID}/zip", workflows["delivery-receipt.yml"])
        self.assertIn("repos/{os.environ['TARGET_REPOSITORY']}/actions/artifacts/{artifact_id}", workflows["delivery-receipt.yml"])
        self.assertIn("evidence_present(root)", workflows["delivery-receipt.yml"])
        self.assertIn('str(run.get("id") or "") == os.environ["GITHUB_RUN_ID"]', workflows["delivery-receipt.yml"])
        self.assertIn("archive_digest(archive_path) == expected_digest", workflows["delivery-receipt.yml"])
        self.assertIn("proof_flags=()", workflows["delivery-receipt.yml"])
        self.assertIn("proof_flags+=(--protected-baseline-judge-ran --baseline-receipt-produced)", workflows["delivery-receipt.yml"])
        self.assertIn("proof_flags+=(--candidate-judge-ran --candidate-receipt-produced)", workflows["delivery-receipt.yml"])
        self.assertIn('"${proof_flags[@]}"', workflows["delivery-receipt.yml"])
        self.assertIn("candidate-supportability-gate-evidence", workflows["supportability-enforcement.yml"])
        self.assertIn('digest="sha256:${digest}"', workflows["delivery-receipt.yml"])
        self.assertIn("if: always()", workflows["delivery-receipt.yml"])
        self.assertNotIn("actions/runs/{run_id}/artifacts", workflows["delivery-receipt.yml"])
        self.assertIn("delivery-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("--architecture-result", workflows["delivery-receipt.yml"])
        self.assertIn("architecture-gate-result.json", workflows["delivery-receipt.yml"])
        self.assertIn("verify-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("artifact-digest", workflows["delivery-receipt.yml"])
        self.assertIn("artifact-digest: ${{ steps.upload.outputs.artifact-digest }}", workflows["delivery-receipt.yml"])
        self.assertNotIn("steps.upload.outputs.digest", workflows["delivery-receipt.yml"])
        self.assertIn("Fail closed on RED delivery receipt", workflows["delivery-receipt.yml"])
        docs = (self.root / "docs/supportability-github-enforcement.md").read_text(encoding="utf-8")
        self.assertNotIn("trusted base config", docs)


if __name__ == "__main__":
    unittest.main()
