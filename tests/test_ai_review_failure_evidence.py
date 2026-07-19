from __future__ import annotations

import unittest

from governance_eval.ai_review_failures import is_ai_review_service_failure


class AiReviewFailureClassifierTests(unittest.TestCase):
    def test_service_failure_classifier_is_precise(self) -> None:
        cases = {
            True: (
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
            ),
            False: (
                "Verified service-unavailable handling and quota tests pass.",
                "No review failure found.",
                "Review error handling passed.",
                '{"fixture": "Copilot was unable to review this pull request."}',
                "The quota failure test is covered; no issues found.",
            ),
        }

        for expected, bodies in cases.items():
            for body in bodies:
                with self.subTest(expected=expected, body=body):
                    self.assertEqual(is_ai_review_service_failure(body), expected)


if __name__ == "__main__":
    unittest.main()
