from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from governance_eval.adopter_template import (
    AdopterTemplateError,
    render_candidate_workflow,
    validate_candidate_workflow,
    write_candidate_workflow,
)


class AdopterTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.template = (
            self.root
            / "templates"
            / "standard"
            / ".github"
            / "workflows"
            / "governance-candidate.yml"
        )
        self.governance_sha = "a" * 40

    def test_renders_exact_sha_read_only_candidate_workflow(self) -> None:
        rendered = render_candidate_workflow(
            self.template, self.governance_sha
        ).decode()

        validate_candidate_workflow(rendered, self.governance_sha)
        self.assertNotIn("__GOVERNANCE_SHA__", rendered)
        self.assertEqual(rendered.count(self.governance_sha), 2)
        self.assertIn('"network": "none"', self._runtime_source())
        self.assertIn("f\"--network={runtime['network']}\"", self._runtime_source())
        self.assertIn("--read-only", self._runtime_source())
        self.assertIn("--security-opt=no-new-privileges:true", self._runtime_source())
        self.assertNotIn("docker.sock", rendered)

    def test_rejects_mutable_or_malformed_governance_refs(self) -> None:
        for value in ("main", "v1", "A" * 40, "a" * 39, "a" * 41):
            with self.subTest(value=value):
                with self.assertRaisesRegex(AdopterTemplateError, "exact lowercase"):
                    render_candidate_workflow(self.template, value)

    def test_rejects_permission_and_trigger_expansion(self) -> None:
        rendered = render_candidate_workflow(
            self.template, self.governance_sha
        ).decode()
        cases = (
            rendered.replace("contents: read", "contents: write"),
            rendered.replace("pull_request:", "pull_request_target:", 1),
            rendered.replace('GITHUB_TOKEN: ""', "GITHUB_TOKEN: ${{ secrets.TOKEN }}"),
        )
        for workflow in cases:
            with self.subTest(workflow=workflow[:80]):
                with self.assertRaises(AdopterTemplateError):
                    validate_candidate_workflow(workflow, self.governance_sha)

    def test_writes_only_a_validated_rendering(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "nested" / "candidate.yml"
            write_candidate_workflow(self.template, destination, self.governance_sha)

            self.assertEqual(
                destination.read_bytes(),
                render_candidate_workflow(self.template, self.governance_sha),
            )

    def _runtime_source(self) -> str:
        return "\n".join(
            (self.root / "governance_eval" / name).read_text(encoding="utf-8")
            for name in ("docker_runtime.py", "execution_plan_v2.py")
        )


if __name__ == "__main__":
    unittest.main()
