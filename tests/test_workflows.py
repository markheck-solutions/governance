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
        for text in workflows.values():
            self.assertNotIn("pull_request_target", text)
            self.assertIn("contents: read", text)
            self.assertIn("retention-days: 90", text)
            self.assertNotIn("secrets: inherit", text)
        self.assertIn("workflow_call:", workflows["governance-evaluate.yml"])
        self.assertIn("governance-ref:", workflows["governance-evaluate.yml"])
        self.assertIn("GOVERNANCE_CHECKOUT_REF", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-digest", workflows["governance-evaluate.yml"])


if __name__ == "__main__":
    unittest.main()
