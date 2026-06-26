from __future__ import annotations

import unittest

from governance_eval.delivery_readiness import evaluate_readiness


class DeliveryReadinessTests(unittest.TestCase):
    def test_ready_when_final_review_is_on_latest_head_and_no_blocking_threads(self) -> None:
        payload = {
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "headRefOid": "a" * 40,
            "latestHeadCommittedAt": "2026-06-25T10:00:00Z",
            "reviews": [
                {
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commitOid": "a" * 40,
                    "author": "chatgpt-codex-connector",
                }
            ],
            "unresolvedThreads": [{"body": "nit: wording"}],
            "workflowContexts": [{"name": "tests", "conclusion": "SUCCESS"}],
        }

        result = evaluate_readiness(payload)

        self.assertTrue(result["ready"])
        self.assertEqual(result["unresolved_p0_count"], 0)
        self.assertEqual(result["final_review_commit"], "a" * 40)

    def test_blocks_stale_review_unresolved_p1_and_failed_workflow(self) -> None:
        payload = {
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "headRefOid": "b" * 40,
            "latestHeadCommittedAt": "2026-06-25T10:00:00Z",
            "reviews": [
                {
                    "submittedAt": "2026-06-25T09:59:00Z",
                    "commitOid": "b" * 40,
                    "author": "chatgpt-codex-connector",
                }
            ],
            "unresolvedThreads": [{"body": "severity: P1 candidate workflow can be bypassed"}],
            "workflowContexts": [{"name": "tests", "conclusion": "FAILURE"}],
        }

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertEqual(result["unresolved_p1_count"], 1)
        self.assertEqual(len(result["failed_workflow_contexts"]), 1)
        self.assertIsNone(result["final_review_timestamp"])

    def test_change_request_review_is_not_final_clean_review(self) -> None:
        payload = {
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "headRefOid": "c" * 40,
            "latestHeadCommittedAt": "2026-06-25T10:00:00Z",
            "reviews": [
                {
                    "state": "CHANGES_REQUESTED",
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commitOid": "c" * 40,
                    "author": "chatgpt-codex-connector",
                    "body": "Please fix this.",
                }
            ],
            "unresolvedThreads": [],
            "workflowContexts": [{"name": "tests", "conclusion": "SUCCESS"}],
        }

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertIsNone(result["final_review_timestamp"])

    def test_owner_review_comment_is_not_final_independent_review(self) -> None:
        payload = {
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "headRefOid": "d" * 40,
            "latestHeadCommittedAt": "2026-06-25T10:00:00Z",
            "reviews": [
                {
                    "state": "COMMENTED",
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commitOid": "d" * 40,
                    "author": "markheck-solutions",
                    "body": "",
                }
            ],
            "unresolvedThreads": [],
            "workflowContexts": [{"name": "tests", "conclusion": "SUCCESS"}],
        }

        result = evaluate_readiness(payload)

        self.assertFalse(result["ready"])
        self.assertIsNone(result["final_review_timestamp"])


if __name__ == "__main__":
    unittest.main()
