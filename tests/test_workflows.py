from __future__ import annotations

import unittest
from pathlib import Path

from governance_eval.paths import repo_root


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_governance_workflows_are_read_only_nonblocking_and_retained(self) -> None:
        workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in (self.root / ".github/workflows").glob("*.yml")
        }
        self.assertIn("governance-shadow.yml", workflows)
        self.assertIn("governance-evaluate.yml", workflows)
        self.assertIn("supportability-gate.yml", workflows)
        self.assertIn("delivery-receipt.yml", workflows)
        for text in workflows.values():
            self.assertNotIn("pull_request_target", text)
            self.assertIn("contents: read", text)
            self.assertIn("retention-days: 90", text)
            self.assertNotIn("secrets: inherit", text)
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
        self.assertIn("supportability-gate", workflows["supportability-gate.yml"])
        self.assertIn("copilot-review-gate", workflows["supportability-gate.yml"])
        self.assertIn("pull-requests: read", workflows["supportability-gate.yml"])
        self.assertIn("artifact-digest", workflows["supportability-gate.yml"])
        self.assertIn("artifact-digest: ${{ steps.upload.outputs.digest }}", workflows["supportability-gate.yml"])
        self.assertNotIn("steps.upload.outputs.artifact-digest", workflows["supportability-gate.yml"])
        self.assertIn("Fail closed on RED supportability evidence", workflows["supportability-gate.yml"])
        self.assertIn("workflow_call:", workflows["delivery-receipt.yml"])
        self.assertIn("Delivery Receipt", workflows["delivery-receipt.yml"])
        self.assertIn("gh run download", workflows["delivery-receipt.yml"])
        self.assertIn("delivery-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("verify-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("artifact-digest", workflows["delivery-receipt.yml"])
        self.assertIn("artifact-digest: ${{ steps.upload.outputs.digest }}", workflows["delivery-receipt.yml"])
        self.assertNotIn("steps.upload.outputs.artifact-digest", workflows["delivery-receipt.yml"])
        self.assertIn("Fail closed on RED delivery receipt", workflows["delivery-receipt.yml"])


if __name__ == "__main__":
    unittest.main()
