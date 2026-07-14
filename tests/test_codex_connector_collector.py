from __future__ import annotations

import unittest
from hashlib import sha256

from governance_eval.codex_connector_collector import (
    ApiResponse,
    CodexConnectorCollectionError,
    collect_codex_connector_snapshot,
    serialize_codex_connector_snapshot,
)
from governance_eval.codex_connector_evidence import (
    TrustedCodexConnectorContext,
    evaluate_codex_connector_evidence,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named


REPOSITORY = "markheck-solutions/governance"
HEAD_SHA = "b" * 40
BASE_SHA = "a" * 40
EVALUATOR_SHA = "e" * 40


def user(login: str = "markheck-solutions", user_id: int = 1) -> dict:
    return {
        "login": login,
        "id": user_id,
        "node_id": f"U_{user_id}",
        "type": "User",
    }


class FakeGitHub:
    def __init__(self, responses: dict[str, ApiResponse]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str) -> ApiResponse:
        self.calls.append(url)
        return self.responses[url]


class CodexConnectorCollectorTests(unittest.TestCase):
    def test_collector_sets_safe_cutoff_before_evidence_reads(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        pull_url = f"{base}/pulls/35"
        stable_pr = {
            "number": 35,
            "node_id": "PR_node",
            "created_at": "2026-07-13T22:07:10Z",
            "state": "open",
            "draft": False,
            "base": {"sha": BASE_SHA},
            "head": {"sha": HEAD_SHA},
        }
        evidence_started = False

        def request(url: str) -> ApiResponse:
            nonlocal evidence_started
            if url == base:
                return ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {})
            if url == pull_url:
                return ApiResponse(
                    stable_pr,
                    {"Date": "Mon, 13 Jul 2026 22:12:10 GMT"},
                )
            evidence_started = True
            return ApiResponse([], {})

        snapshot = collect_codex_connector_snapshot(
            REPOSITORY,
            35,
            EVALUATOR_SHA,
            request_json=request,
        )

        self.assertTrue(evidence_started)
        self.assertEqual(snapshot["captured_at"], "2026-07-13T22:12:09Z")

    def test_collector_requires_server_cutoff_before_evidence_reads(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        pull_url = f"{base}/pulls/35"
        stable_pr = {
            "number": 35,
            "node_id": "PR_node",
            "created_at": "2026-07-13T22:07:10Z",
            "state": "open",
            "draft": False,
            "base": {"sha": BASE_SHA},
            "head": {"sha": HEAD_SHA},
        }
        calls: list[str] = []

        def request(url: str) -> ApiResponse:
            calls.append(url)
            if url == base:
                return ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {})
            if url == pull_url:
                return ApiResponse(stable_pr, {})
            raise AssertionError("evidence endpoint must not be read without cutoff")

        with self.assertRaisesRegex(
            CodexConnectorCollectionError,
            "Date header is missing",
        ):
            collect_codex_connector_snapshot(
                REPOSITORY,
                35,
                EVALUATOR_SHA,
                request_json=request,
            )

        self.assertEqual(calls, [base, pull_url])

    def test_fresh_cutoff_recollection_ignores_post_deadline_finding(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        pull_url = f"{base}/pulls/35"
        stable_pr = {
            "number": 35,
            "node_id": "PR_node",
            "created_at": "2026-07-13T22:07:10Z",
            "state": "open",
            "draft": False,
            "base": {"sha": BASE_SHA},
            "head": {"sha": HEAD_SHA},
        }
        reaction = {
            "id": 407803693,
            "node_id": "REA_clean",
            "created_at": "2026-07-13T22:11:20Z",
            "content": "+1",
            "user": {
                "login": "chatgpt-codex-connector[bot]",
                "id": 199175422,
                "node_id": "BOT_kgDOC98s_g",
                "type": "User",
            },
        }
        finding = {
            "id": 900,
            "created_at": "2026-07-13T22:12:11Z",
            "body": "P1: blocking connector finding",
            "user": {
                "login": "chatgpt-codex-connector[bot]",
                "id": 199175422,
                "node_id": "BOT_kgDOC98s_g",
                "type": "Bot",
            },
            "performed_via_github_app": {
                "id": 1144995,
                "node_id": "A_kwHOAOQ6Gs4AEXij",
                "slug": "chatgpt-codex-connector",
            },
        }

        def collect(date_header: str, comments: list[dict]) -> dict:
            responses = {
                base: ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {}),
                pull_url: ApiResponse(stable_pr, {"Date": date_header}),
            }
            endpoints = {
                f"{base}/issues/35/comments": comments,
                f"{base}/issues/35/reactions": [reaction],
                f"{base}/pulls/35/reviews": [],
                f"{base}/pulls/35/comments": [],
                f"{base}/issues/35/events": [],
            }
            for endpoint, items in endpoints.items():
                responses[f"{endpoint}?per_page=100&page=1"] = ApiResponse(items, {})
            return collect_codex_connector_snapshot(
                REPOSITORY,
                35,
                EVALUATOR_SHA,
                request_json=FakeGitHub(responses),
            )

        def evaluate(snapshot: dict) -> dict:
            raw = serialize_codex_connector_snapshot(snapshot)
            return evaluate_codex_connector_evidence(
                raw,
                TrustedCodexConnectorContext(
                    snapshot_file_sha256="sha256:" + sha256(raw).hexdigest(),
                    repository_id=1280677092,
                    repository_full_name=REPOSITORY,
                    pull_request_number=35,
                    pull_request_node_id="PR_node",
                    pull_request_created_at="2026-07-13T22:07:10Z",
                    base_sha=BASE_SHA,
                    head_sha=HEAD_SHA,
                    governance_evaluator_sha=EVALUATOR_SHA,
                    review_window_started_at="2026-07-13T22:07:10Z",
                    review_deadline_at="2026-07-13T22:12:10Z",
                    resolved_clean_commit_sha=None,
                ),
            )

        first = evaluate(collect("Mon, 13 Jul 2026 22:12:11 GMT", []))
        refreshed = evaluate(collect("Mon, 13 Jul 2026 22:12:21 GMT", [finding]))

        self.assertEqual(first["capability_status"], "PASS")
        self.assertEqual(first["evidence_cutoff_at"], "2026-07-13T22:12:10Z")
        self.assertEqual(refreshed["capability_status"], "PASS")
        self.assertEqual(refreshed["review_state"], "AI_REVIEW_UNAVAILABLE")
        self.assertEqual(refreshed["reasons"], ["ONLY_LATE_RESPONSE"])

    def test_collector_follows_every_page_and_emits_terminal_receipts(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        page_1 = f"{base}/issues/35/reactions?per_page=100&page=1"
        page_2 = f"{base}/issues/35/reactions?per_page=100&page=2"
        responses = {
            base: ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {}),
            f"{base}/pulls/35": ApiResponse(
                {
                    "number": 35,
                    "node_id": "PR_node",
                    "created_at": "2026-07-13T22:07:10Z",
                    "state": "open",
                    "draft": False,
                    "base": {"sha": BASE_SHA},
                    "head": {"sha": HEAD_SHA},
                },
                {"Date": "Mon, 13 Jul 2026 22:12:11 GMT"},
            ),
        }
        endpoints = {
            "issue_comments": f"{base}/issues/35/comments",
            "issue_reactions": f"{base}/issues/35/reactions",
            "pull_request_reviews": f"{base}/pulls/35/reviews",
            "review_comments": f"{base}/pulls/35/comments",
            "pull_request_events": f"{base}/issues/35/events",
        }
        for name, endpoint in endpoints.items():
            first = f"{endpoint}?per_page=100&page=1"
            responses[first] = ApiResponse([], {})
        reactions_1 = [
            {
                "id": index,
                "node_id": f"REA_{index}",
                "created_at": "2026-07-13T22:08:00Z",
                "content": "heart",
                "user": user(user_id=1000 + index),
            }
            for index in range(1, 101)
        ]
        reactions_2 = [
            {
                "id": 101,
                "node_id": "REA_101",
                "created_at": "2026-07-13T22:11:20Z",
                "content": "+1",
                "user": {
                    "login": "chatgpt-codex-connector[bot]",
                    "id": 199175422,
                    "node_id": "BOT_kgDOC98s_g",
                    "type": "User",
                },
            }
        ]
        responses[page_1] = ApiResponse(
            reactions_1,
            {
                "Link": (
                    f"<{base}/issues/35/reactions?page=2&per_page=100>; "
                    f'rel="next", <{page_2}>; rel="last"'
                )
            },
        )
        responses[page_2] = ApiResponse(reactions_2, {})
        fake = FakeGitHub(responses)

        snapshot = collect_codex_connector_snapshot(
            REPOSITORY,
            35,
            EVALUATOR_SHA,
            request_json=fake,
        )

        validate_named("codex_connector_snapshot_v2", snapshot)
        self.assertEqual(len(snapshot["issue_reactions"]), 101)
        receipt = snapshot["collection_receipts"]["issue_reactions"]
        self.assertEqual(receipt["item_count"], 101)
        self.assertEqual(
            receipt["items_sha256"], sha256_json(reactions_1 + reactions_2)
        )
        self.assertEqual([page["page"] for page in receipt["pages"]], [1, 2])
        self.assertFalse(receipt["pages"][0]["terminal"])
        self.assertTrue(receipt["pages"][1]["terminal"])
        self.assertIn(page_2, fake.calls)
        raw = serialize_codex_connector_snapshot(snapshot)
        evidence = evaluate_codex_connector_evidence(
            raw,
            TrustedCodexConnectorContext(
                snapshot_file_sha256="sha256:" + sha256(raw).hexdigest(),
                repository_id=1280677092,
                repository_full_name=REPOSITORY,
                pull_request_number=35,
                pull_request_node_id="PR_node",
                pull_request_created_at="2026-07-13T22:07:10Z",
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                governance_evaluator_sha=EVALUATOR_SHA,
                review_window_started_at="2026-07-13T22:07:10Z",
                review_deadline_at="2026-07-13T22:12:10Z",
                resolved_clean_commit_sha=None,
            ),
        )
        self.assertEqual(evidence["capability_status"], "PASS")

    def test_collector_rejects_untrusted_pagination_next_url(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        responses = {
            base: ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {}),
            f"{base}/pulls/35": ApiResponse(
                {
                    "number": 35,
                    "node_id": "PR_node",
                    "created_at": "2026-07-13T22:07:10Z",
                    "state": "open",
                    "draft": False,
                    "base": {"sha": BASE_SHA},
                    "head": {"sha": HEAD_SHA},
                },
                {"Date": "Mon, 13 Jul 2026 22:12:11 GMT"},
            ),
        }
        endpoints = (
            f"{base}/issues/35/comments",
            f"{base}/issues/35/reactions",
            f"{base}/pulls/35/reviews",
            f"{base}/pulls/35/comments",
            f"{base}/issues/35/events",
        )
        for endpoint in endpoints:
            responses[f"{endpoint}?per_page=100&page=1"] = ApiResponse([], {})
        responses[f"{endpoints[0]}?per_page=100&page=1"] = ApiResponse(
            [],
            {"Link": '<https://evil.example/page=2>; rel="next"'},
        )

        with self.assertRaises(CodexConnectorCollectionError):
            collect_codex_connector_snapshot(
                REPOSITORY,
                35,
                EVALUATOR_SHA,
                request_json=FakeGitHub(responses),
            )

    def test_collector_rejects_pull_request_change_during_collection(self) -> None:
        api = "https://api.github.com"
        base = f"{api}/repos/{REPOSITORY}"
        pull_url = f"{base}/pulls/35"
        stable_pr = {
            "number": 35,
            "node_id": "PR_node",
            "created_at": "2026-07-13T22:07:10Z",
            "state": "open",
            "draft": False,
            "base": {"sha": BASE_SHA},
            "head": {"sha": HEAD_SHA},
        }
        calls = 0

        def changing_request(url: str) -> ApiResponse:
            nonlocal calls
            if url == base:
                return ApiResponse({"id": 1280677092, "full_name": REPOSITORY}, {})
            if url == pull_url:
                calls += 1
                payload = dict(stable_pr)
                payload["base"] = dict(stable_pr["base"])
                payload["head"] = dict(stable_pr["head"])
                if calls > 1:
                    payload["head"]["sha"] = "c" * 40
                return ApiResponse(
                    payload,
                    {"Date": "Mon, 13 Jul 2026 22:12:11 GMT"},
                )
            return ApiResponse([], {})

        with self.assertRaisesRegex(
            CodexConnectorCollectionError,
            "changed during collection",
        ):
            collect_codex_connector_snapshot(
                REPOSITORY,
                35,
                EVALUATOR_SHA,
                request_json=changing_request,
            )


if __name__ == "__main__":
    unittest.main()
