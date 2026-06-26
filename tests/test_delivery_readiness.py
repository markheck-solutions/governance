from __future__ import annotations

import json
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from governance_eval import delivery_readiness
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

    def test_live_thread_loader_paginates_review_threads(self) -> None:
        pages = [
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "isResolved": True,
                                        "path": "a.py",
                                        "line": 1,
                                        "comments": {"nodes": [{"body": "severity: P1 fixed"}]},
                                    }
                                ],
                                "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                            }
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "isResolved": False,
                                        "path": "b.py",
                                        "line": 2,
                                        "comments": {"nodes": [{"body": "severity: P2 still open"}]},
                                    }
                                ],
                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                            }
                        }
                    }
                }
            },
        ]
        calls: list[list[str]] = []

        def fake_run(args: list[str], **_: object) -> CompletedProcess[str]:
            calls.append(args)
            page = pages.pop(0)
            return CompletedProcess(args, 0, stdout=json.dumps(page), stderr="")

        with patch.object(delivery_readiness.subprocess, "run", side_effect=fake_run):
            threads = delivery_readiness._load_review_threads("owner", "repo", 12)

        self.assertEqual(threads, [{"path": "b.py", "line": 2, "body": "severity: P2 still open"}])
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("cursor=cursor-1" in arg for arg in calls[1]))


if __name__ == "__main__":
    unittest.main()
