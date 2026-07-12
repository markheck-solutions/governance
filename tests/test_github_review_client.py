from __future__ import annotations

import unittest
from unittest import mock

import governance_eval.github_review_client as client
from governance_eval.github_review_client import GitHubReviewTransportError


class GitHubReviewPaginationTests(unittest.TestCase):
    def test_load_copilot_payload_aggregates_review_and_comment_pages(self) -> None:
        head = "f" * 40
        metadata = {
            "url": "https://github.com/example/repo/pull/7",
            "state": "OPEN",
            "baseRefOid": "e" * 40,
            "headRefOid": head,
        }

        def graphql(
            _owner: str, _name: str, _number: int, query: str, cursor: str
        ) -> dict:
            if "reviews(first" in query:
                review = {
                    "state": "COMMENTED",
                    "submittedAt": "2026-06-25T10:05:00Z",
                    "commit": {"oid": head},
                    "author": {"login": "copilot-pull-request-reviewer[bot]"},
                    "body": "No findings.",
                }
                return _connection("reviews", [review], has_next=not cursor)
            if "reviewThreads(first" in query:
                return _connection("reviewThreads", [], has_next=False)
            comment = {
                "author": {"login": "copilot-swe-agent"},
                "body": "structured evidence",
                "createdAt": "2026-06-30T14:35:45Z",
                "isMinimized": False,
            }
            return _connection("comments", [comment], has_next=not cursor)

        with (
            mock.patch.object(client, "_gh_json", return_value=metadata),
            mock.patch.object(client, "_gh_graphql", side_effect=graphql),
        ):
            payload = client.load_copilot_payload("example/repo", 7)

        self.assertEqual(len(payload["reviews"]), 2)
        self.assertEqual(len(payload["comments"]), 2)
        self.assertEqual(
            payload["reviews"][0]["author"], "copilot-pull-request-reviewer[bot]"
        )
        self.assertEqual(payload["reviews"][0]["commitOid"], head)

    def test_review_thread_loader_paginates_threads_and_nested_comments(self) -> None:
        first_thread_page = _connection(
            "reviewThreads",
            [
                {
                    "id": "thread-1",
                    "isResolved": False,
                    "path": "src/app.py",
                    "comments": {
                        "nodes": [_thread_comment("first")],
                        "pageInfo": {
                            "hasNextPage": True,
                            "endCursor": "comment-page-2",
                        },
                    },
                }
            ],
            has_next=True,
        )
        second_thread_page = _connection("reviewThreads", [], has_next=False)
        second_comment_page = {
            "data": {
                "node": {
                    "comments": {
                        "nodes": [_thread_comment("second")],
                        "pageInfo": {"hasNextPage": False, "endCursor": ""},
                    }
                }
            }
        }

        with (
            mock.patch.object(
                client,
                "_gh_graphql",
                side_effect=[first_thread_page, second_thread_page],
            ),
            mock.patch.object(
                client,
                "_gh_graphql_thread_comments",
                return_value=second_comment_page,
            ),
        ):
            threads = client._load_review_threads("example", "repo", 7)

        self.assertEqual(threads[0]["body"], "first\nsecond")

    def test_partial_nested_thread_comment_response_fails_closed(self) -> None:
        first_page = _connection(
            "reviewThreads",
            [
                {
                    "id": "thread-1",
                    "isResolved": False,
                    "path": "src/app.py",
                    "comments": {
                        "nodes": [_thread_comment("first")],
                        "pageInfo": {"hasNextPage": True, "endCursor": "page-2"},
                    },
                }
            ],
            has_next=False,
        )
        nested = {
            "data": {
                "node": {
                    "comments": {
                        "nodes": [_thread_comment("second")],
                        "pageInfo": {"hasNextPage": False, "endCursor": ""},
                    }
                }
            },
            "errors": [{"message": "nested partial failure"}],
        }

        with (
            mock.patch.object(client, "_gh_graphql", return_value=first_page),
            mock.patch.object(
                client,
                "_gh_graphql_thread_comments",
                return_value=nested,
            ),
        ):
            with self.assertRaisesRegex(
                GitHubReviewTransportError,
                "partial or invalid",
            ):
                client._load_review_threads("example", "repo", 7)

    def test_repeated_or_empty_cursor_fails_closed(self) -> None:
        payload = _connection("reviewThreads", [], has_next=True, end_cursor="")

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "did not advance"):
                client._load_review_threads("example", "repo", 7)

    def test_missing_page_info_fails_closed(self) -> None:
        payload = _connection("reviews", [], has_next=False)
        del payload["data"]["repository"]["pullRequest"]["reviews"]["pageInfo"]

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "pageInfo"):
                client._load_reviews("example", "repo", 7)

    def test_partial_graphql_response_with_data_and_errors_fails_closed(self) -> None:
        payload = _connection("reviews", [], has_next=False)
        payload["errors"] = [{"message": "partial failure"}]

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(
                GitHubReviewTransportError,
                "partial or invalid",
            ):
                client._load_reviews("example", "repo", 7)

    def test_malformed_comment_minimized_flag_fails_closed(self) -> None:
        comment = {
            "author": {"login": "copilot-swe-agent"},
            "body": "evidence",
            "createdAt": "2026-06-30T14:35:45Z",
            "isMinimized": "false",
        }
        payload = _connection("comments", [comment], has_next=False)

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "isMinimized"):
                client._load_comments("example", "repo", 7)

    def test_page_cap_overflow_fails_closed(self) -> None:
        payload = _connection("reviews", [], has_next=True)

        with (
            mock.patch.object(client, "GITHUB_GRAPHQL_MAX_PAGES", 1),
            mock.patch.object(client, "_gh_graphql", return_value=payload),
        ):
            with self.assertRaisesRegex(GitHubReviewTransportError, "page limit"):
                client._load_reviews("example", "repo", 7)

    def test_node_cap_overflow_fails_closed(self) -> None:
        payload = _connection("reviews", [{}], has_next=False)

        with (
            mock.patch.object(client, "GITHUB_GRAPHQL_MAX_NODES", 0),
            mock.patch.object(client, "_gh_graphql", return_value=payload),
        ):
            with self.assertRaisesRegex(GitHubReviewTransportError, "node limit"):
                client._load_reviews("example", "repo", 7)

    def test_shared_request_budget_blocks_many_nested_thread_connections(self) -> None:
        threads = [
            {
                "id": f"thread-{index}",
                "isResolved": False,
                "path": f"src/file-{index}.py",
                "comments": {
                    "nodes": [_thread_comment("first")],
                    "pageInfo": {"hasNextPage": True, "endCursor": "nested-page-2"},
                },
            }
            for index in range(2)
        ]
        top_page = _connection("reviewThreads", threads, has_next=False)
        nested_page = {
            "data": {
                "node": {
                    "comments": {
                        "nodes": [_thread_comment("second")],
                        "pageInfo": {"hasNextPage": False, "endCursor": ""},
                    }
                }
            }
        }

        with (
            mock.patch.object(client, "GITHUB_EVIDENCE_MAX_REQUESTS", 2, create=True),
            mock.patch.object(client, "_gh_graphql", return_value=top_page),
            mock.patch.object(
                client, "_gh_graphql_thread_comments", return_value=nested_page
            ),
        ):
            with self.assertRaisesRegex(GitHubReviewTransportError, "request budget"):
                client._load_review_threads("example", "repo", 7)

    def test_malformed_thread_resolution_type_fails_closed(self) -> None:
        thread = {
            "id": "thread-1",
            "isResolved": "false",
            "path": "src/app.py",
            "comments": {
                "nodes": [_thread_comment("finding")],
                "pageInfo": {"hasNextPage": False, "endCursor": ""},
            },
        }
        payload = _connection("reviewThreads", [thread], has_next=False)

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "isResolved"):
                client._load_review_threads("example", "repo", 7)

    def test_missing_thread_comment_author_fails_closed(self) -> None:
        thread = {
            "id": "thread-1",
            "isResolved": False,
            "path": "src/app.py",
            "comments": {
                "nodes": [{"body": "finding", "author": None}],
                "pageInfo": {"hasNextPage": False, "endCursor": ""},
            },
        }
        payload = _connection("reviewThreads", [thread], has_next=False)

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "author login"):
                client._load_review_threads("example", "repo", 7)

    def test_unresolved_thread_with_no_comments_fails_closed(self) -> None:
        thread = {
            "id": "thread-1",
            "isResolved": False,
            "path": "src/app.py",
            "comments": {
                "nodes": [],
                "pageInfo": {"hasNextPage": False, "endCursor": ""},
            },
        }
        payload = _connection("reviewThreads", [thread], has_next=False)

        with mock.patch.object(client, "_gh_graphql", return_value=payload):
            with self.assertRaisesRegex(GitHubReviewTransportError, "at least one comment"):
                client._load_review_threads("example", "repo", 7)

    def test_shared_byte_and_elapsed_budgets_fail_closed(self) -> None:
        with mock.patch.object(client, "GITHUB_EVIDENCE_MAX_NODES", 0):
            with self.assertRaisesRegex(GitHubReviewTransportError, "aggregate node"):
                client.EvidenceBudget().consume_nodes(1)

        with mock.patch.object(client, "GITHUB_EVIDENCE_MAX_BYTES", 1):
            with self.assertRaisesRegex(GitHubReviewTransportError, "byte budget"):
                client.EvidenceBudget().consume_response({"data": "too large"})

        budget = client.EvidenceBudget(started_at=0.0)
        with (
            mock.patch.object(client, "GITHUB_EVIDENCE_MAX_SECONDS", 0.5),
            mock.patch.object(client.time, "monotonic", return_value=1.0),
        ):
            with self.assertRaisesRegex(GitHubReviewTransportError, "elapsed-time"):
                budget.consume_nodes(0)

    def test_transport_subprocess_failure_is_not_converted_to_empty_evidence(
        self,
    ) -> None:
        with mock.patch.object(
            client, "_gh_json", side_effect=RuntimeError("API unavailable")
        ):
            with self.assertRaisesRegex(RuntimeError, "API unavailable"):
                client.load_copilot_payload("example/repo", 7)


def _connection(
    field: str,
    nodes: list[dict],
    *,
    has_next: bool,
    end_cursor: str | None = None,
) -> dict:
    cursor = end_cursor if end_cursor is not None else ("page-2" if has_next else "")
    return {
        "data": {
            "repository": {
                "pullRequest": {
                    field: {
                        "nodes": nodes,
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                    }
                }
            }
        }
    }


def _thread_comment(body: str) -> dict:
    return {
        "body": body,
        "author": {"login": "copilot-pull-request-reviewer"},
    }
