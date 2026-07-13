from __future__ import annotations

import unittest
from pathlib import Path

from governance_eval.ai_review_failures import is_ai_review_service_failure
from governance_eval.copilot_review_evidence import evaluate_review_evidence
from governance_eval.paths import repo_root
from governance_eval.supportability import STATUS_RED, evaluate_copilot_review_gate


HEAD_SHA = "c" * 40


def review_payload(body: str) -> dict:
    return {
        "headRefOid": HEAD_SHA,
        "reviews": [
            {
                "state": "COMMENTED",
                "submittedAt": "2026-07-13T23:01:37Z",
                "commitOid": HEAD_SHA,
                "author": "copilot-pull-request-reviewer[bot]",
                "body": body,
            }
        ],
        "comments": [],
        "reviewThreads": [],
    }


class NativeReviewFailureEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_service_failure_classifier_is_precise(self) -> None:
        failures = (
            "Copilot was unable to review this pull request because quota is exhausted.",
            "Codex couldn't complete this request. Try again later.",
            "Could-not review this pull request.",
            "You have reached your Codex usage limits for code reviews.",
            "Usage exhausted for code reviews.",
            "Quota limit exceeded.",
            "Review failed with an error.",
            "Review unavailable.",
            "Service unavailable.",
            "To use Codex here, create an environment for this repo.",
            "Codex environment setup is required.",
            "> Copilot was unable to review this pull request.",
            "- > Copilot was unable to review this pull request.",
            "1. > Copilot was unable to review this pull request.",
            "> - Copilot was unable to review this pull request.",
            "```text\nCopilot was unable to review this pull request.\n```",
            "- ```text\n  Copilot was unable to review this pull request.\n- ```",
        )
        clean = (
            "Verified service-unavailable handling and quota tests pass.",
            "No review failure found.",
            "Review error handling passed.",
            '{"fixture": "Copilot was unable to review this pull request."}',
            "The quota failure test is covered; no issues found.",
        )

        for body in failures:
            with self.subTest(body=body):
                self.assertTrue(is_ai_review_service_failure(body))
        for body in clean:
            with self.subTest(body=body):
                self.assertFalse(is_ai_review_service_failure(body))

    def test_quota_exhaustion_cannot_be_native_clean_evidence(self) -> None:
        result = evaluate_review_evidence(
            review_payload(
                "Copilot was unable to review this pull request because the user "
                "who requested the review has reached their quota limit."
            ),
            HEAD_SHA,
        )

        self.assertFalse(result["review_status"]["latest_head_reviewed"])
        self.assertNotEqual(result["review_status"]["verdict"], "native_clean")
        self.assertTrue(
            any("service failure" in error.lower() for error in result["errors"]),
            result["errors"],
        )

    def test_live_quota_body_makes_supportability_review_gate_red(self) -> None:
        result = evaluate_copilot_review_gate(
            self.root / ".github/governance/supportability.yml",
            HEAD_SHA,
            payload=review_payload(
                "Copilot was unable to review this pull request because the user "
                "who requested the review has reached their quota limit."
            ),
        )

        self.assertEqual(result["owner_status"], STATUS_RED)
        self.assertFalse(result["review_status"]["latest_head_reviewed"])
        self.assertTrue(
            any("service failure" in error.lower() for error in result["errors"]),
            result["errors"],
        )

    def test_nested_markdown_failure_evasion_makes_full_gate_red(self) -> None:
        bodies = (
            "- > Copilot was unable to review this pull request.",
            "1. > Copilot was unable to review this pull request.",
            "> - Service unavailable.",
            "- ```text\n  Copilot was unable to review this pull request.\n- ```",
        )
        for body in bodies:
            with self.subTest(body=body):
                result = evaluate_copilot_review_gate(
                    self.root / ".github/governance/supportability.yml",
                    HEAD_SHA,
                    payload=review_payload(body),
                )
                self.assertEqual(result["owner_status"], STATUS_RED)
                self.assertFalse(result["review_status"]["latest_head_reviewed"])
                self.assertTrue(
                    any(
                        "service failure" in error.lower() for error in result["errors"]
                    ),
                    result["errors"],
                )

    def test_later_clean_review_cannot_erase_service_failure(self) -> None:
        payload = review_payload(
            "Unable to review this pull request: service unavailable."
        )
        payload["reviews"].append(
            {
                "state": "COMMENTED",
                "submittedAt": "2026-07-13T23:02:37Z",
                "commitOid": HEAD_SHA,
                "author": "copilot-pull-request-reviewer",
                "body": "No issues found.",
            }
        )

        result = evaluate_review_evidence(payload, HEAD_SHA)

        self.assertTrue(result["review_status"]["latest_head_reviewed"])
        self.assertTrue(
            any("service failure" in error.lower() for error in result["errors"]),
            result["errors"],
        )

    def test_unapproved_author_failure_text_is_not_trusted_evidence(self) -> None:
        payload = review_payload("No issues found.")
        payload["reviews"][0]["author"] = "copilot-pull-request-reviewer-attacker"
        payload["reviews"][0]["body"] = "Unable to review: quota limit reached."

        result = evaluate_review_evidence(payload, HEAD_SHA)

        self.assertFalse(result["review_status"]["latest_head_reviewed"])
        self.assertFalse(
            any("service failure" in error.lower() for error in result["errors"]),
            result["errors"],
        )

    def test_stale_failure_does_not_poison_current_clean_review(self) -> None:
        payload = review_payload("Unable to review this pull request.")
        payload["reviews"][0]["commitOid"] = "d" * 40
        payload["reviews"].append(
            {
                "state": "COMMENTED",
                "submittedAt": "2026-07-13T23:02:37Z",
                "commitOid": HEAD_SHA,
                "author": "copilot-pull-request-reviewer[bot]",
                "body": "No P0, P1, or P2 findings.",
            }
        )

        result = evaluate_review_evidence(payload, HEAD_SHA)

        self.assertEqual(result["errors"], [])
        self.assertTrue(result["review_status"]["latest_head_reviewed"])
        self.assertEqual(result["review_status"]["verdict"], "native_clean")

    def test_exact_structured_commenter_service_failure_blocks_clean_review(
        self,
    ) -> None:
        payload = review_payload("No issues found.")
        payload["comments"] = [
            {
                "author": {"login": "copilot-swe-agent[bot]"},
                "body": "> Service unavailable.",
                "createdAt": "2026-07-13T23:02:37Z",
                "isMinimized": False,
            }
        ]

        result = evaluate_review_evidence(payload, HEAD_SHA)

        self.assertTrue(result["review_status"]["latest_head_reviewed"])
        self.assertTrue(
            any("service failure" in error.lower() for error in result["errors"]),
            result["errors"],
        )


if __name__ == "__main__":
    unittest.main()
