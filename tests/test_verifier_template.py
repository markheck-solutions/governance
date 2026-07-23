from __future__ import annotations

import unittest
from pathlib import Path

from governance_eval.verifier_template import (
    VerifierTemplateError,
    render_verifier_workflow,
    validate_verifier_workflow,
)


class VerifierTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.template = (
            root
            / "templates"
            / "verifier"
            / ".github"
            / "workflows"
            / "verify-candidate.yml"
        )
        self.sha = "b" * 40

    def test_renders_external_exact_sha_app_workflow(self) -> None:
        workflow = render_verifier_workflow(self.template, self.sha).decode()

        validate_verifier_workflow(workflow, self.sha)
        self.assertEqual(workflow.count(self.sha), 2)
        self.assertIn("permission-checks: write", workflow)
        self.assertIn("permission-actions: read", workflow)
        self.assertIn('cron: "*/5 * * * *"', workflow)
        self.assertIn("governance_eval.verifier_controller", workflow)
        self.assertIn("app-id: ${{ vars.GOVERNANCE_VERIFIER_APP_ID }}", workflow)
        self.assertNotIn("--no-build-isolation", workflow)
        self.assertNotIn("__GOVERNANCE_SHA__", workflow)
        self.assertNotIn("pull_request_target", workflow)

    def test_rejects_floating_evaluator_or_permission_expansion(self) -> None:
        with self.assertRaisesRegex(VerifierTemplateError, "exact lowercase"):
            render_verifier_workflow(self.template, "main")

        workflow = render_verifier_workflow(self.template, self.sha).decode()
        for changed in (
            workflow.replace("permission-contents: read", "permission-contents: write"),
            workflow.replace("contents: read", "contents: write", 1),
            workflow.replace("workflow_dispatch:", "pull_request_target:", 1),
        ):
            with self.subTest(changed=changed[:80]):
                with self.assertRaises(VerifierTemplateError):
                    validate_verifier_workflow(changed, self.sha)


if __name__ == "__main__":
    unittest.main()
